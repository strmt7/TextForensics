"""Sealed, portable case files and replay.

A case file is a machine-verifiable audit artifact.  It contains the forensic
bundle, schema versions, registry/calibration references and a SHA-256 seal.
Raw source text is excluded by default and forbidden raw-text keys are
rejected recursively.

Replay verifies:

1. the seal and schema;
2. the SHA-256 of out-of-band text, when supplied;
3. detector re-execution, when detectors are supplied;
4. re-derivation of the Trust Map from sealed conditions and a registry,
   when a registry is supplied.

Replay cannot prove authorship.  It can only establish that the recorded
process is reproducible from the recorded inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._build_info import get_version
from .conditions import conditions_from_dict
from .detectors import (
    Detector,
    DetectorPrediction,
    execute_detector,
    text_sha256,
)
from .evidence import EvidenceRegistry
from .trust import assess_trust_map

CASE_SCHEMA = "textforensics.case-file/v2"
LEGACY_CASE_SCHEMA = "textforensics.case-file/v1"
BUNDLE_SCHEMA = "textforensics.forensic-bundle/v2"
LEGACY_BUNDLE_SCHEMA = "textforensics.forensic-bundle/v1"
TRUST_SCHEMA = "textforensics.trust-map/v2"
DETECTOR_SCHEMA = "textforensics.detector-result/v2"

_FORBIDDEN_RAW_KEYS = frozenset(
    {
        "text",
        "raw_text",
        "source_text",
        "document_text",
        "content",
        "snippet",
        "quote",
        "excerpt",
    }
)


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


_SEAL_EXCLUDED_KEYS = frozenset({"case_sha256", "created_at_utc"})


def _hash_without_seal(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the case body, excluding the seal and wall-clock fields.

    ``created_at_utc`` is excluded so that sealing the same bundle twice
    produces the same digest regardless of when the seal was created.  The
    timestamp is still recorded in the case file for auditability; it simply
    does not participate in the integrity check.
    """
    body = deepcopy(dict(payload))
    body.pop("case_sha256", None)
    for key in _SEAL_EXCLUDED_KEYS:
        body.pop(key, None)
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def _forbidden_paths(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_string = str(key)
            child_path = f"{path}.{key_string}"
            if key_string.strip().lower() in _FORBIDDEN_RAW_KEYS:
                found.append(child_path)
            found.extend(_forbidden_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_forbidden_paths(child, f"{path}[{index}]"))
    return found


def _strip_runtime_ms_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    bundle = deepcopy(bundle)
    for key in ("detector_results", "detector_failures"):
        collection = bundle.get(key)
        if isinstance(collection, list):
            for item in collection:
                if isinstance(item, dict):
                    item.pop("runtime_ms", None)
    robustness = bundle.get("robustness")
    if isinstance(robustness, dict):
        for row in robustness.get("detectors", []):
            if not isinstance(row, dict):
                continue
            for failure in row.get("failures", []):
                if isinstance(failure, dict):
                    failure.pop("runtime_ms", None)
    return bundle


def _validate_digest(value: Any, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a 64-character lowercase SHA-256 digest.")


def _validate_portable_bundle(bundle: Mapping[str, Any]) -> None:
    schema = bundle.get("schema")
    if schema not in {BUNDLE_SCHEMA, LEGACY_BUNDLE_SCHEMA}:
        raise ValueError(
            "Case files require a TextForensics forensic-bundle/v2 object "
            "(v1 is accepted for legacy verification)."
        )
    _validate_digest(bundle.get("content_sha256"), "content_sha256")

    input_metadata = bundle.get("input")
    if (
        not isinstance(input_metadata, Mapping)
        or input_metadata.get("raw_text_included") is not False
    ):
        raise ValueError("Forensic bundle must explicitly declare raw_text_included=false.")

    forbidden = _forbidden_paths(bundle)
    if forbidden:
        raise ValueError(
            "Portable case files reject fields that may contain raw source text: "
            + ", ".join(forbidden[:5])
        )


def _calibration_ids(bundle: Mapping[str, Any]) -> list[str]:
    found: set[str] = set()
    for result in bundle.get("detector_results", []):
        if not isinstance(result, Mapping):
            continue
        calibration_id = result.get("calibration_id")
        if isinstance(calibration_id, str) and calibration_id:
            found.add(calibration_id)
        calibration = result.get("calibration")
        if isinstance(calibration, Mapping):
            nested = calibration.get("calibration_id")
            if isinstance(nested, str) and nested:
                found.add(nested)
    return sorted(found)


def _schema_versions(bundle: Mapping[str, Any]) -> dict[str, Any]:
    trust_map = bundle.get("trust_map")
    detector_schema = None
    results = bundle.get("detector_results", [])
    if isinstance(results, list) and results and isinstance(results[0], Mapping):
        detector_schema = results[0].get("schema")
    return {
        "forensic_bundle": bundle.get("schema"),
        "trust_map": trust_map.get("schema") if isinstance(trust_map, Mapping) else None,
        "detector_result": detector_schema or DETECTOR_SCHEMA,
    }


def _manifest_for(bundle: Mapping[str, Any], tool: Mapping[str, Any]) -> dict[str, Any]:
    registry = bundle.get("evidence_registry")
    registry_id = None
    registry_sha256 = None
    if isinstance(registry, Mapping):
        value = registry.get("registry_id")
        if isinstance(value, str):
            registry_id = value
        registry_sha256 = hashlib.sha256(canonical_json_bytes(registry)).hexdigest()
    return {
        "content_sha256": bundle.get("content_sha256"),
        "registry_id": registry_id,
        "registry_sha256": registry_sha256,
        "calibration_ids": _calibration_ids(bundle),
        "schema_versions": _schema_versions(bundle),
        "git_sha": tool.get("git_sha"),
    }


def seal_case_file(
    forensic_bundle: Mapping[str, Any],
    deterministic: bool = False,
    fixed_timestamp: str | None = None,
) -> dict[str, Any]:
    bundle = deepcopy(dict(forensic_bundle))
    _validate_portable_bundle(bundle)

    if deterministic:
        timestamp = fixed_timestamp or "1970-01-01T00:00:00+00:00"
        bundle["generated_at_utc"] = timestamp
        trust_map = bundle.get("trust_map")
        if isinstance(trust_map, dict):
            trust_map["generated_at_utc"] = timestamp
        bundle = _strip_runtime_ms_from_bundle(bundle)
    else:
        timestamp = datetime.now(UTC).isoformat()

    provenance = bundle.get("provenance")
    git_sha = provenance.get("git_sha") if isinstance(provenance, Mapping) else None
    tool = {
        "name": "TextForensics",
        "version": get_version(),
        "git_sha": git_sha if isinstance(git_sha, str) and git_sha else None,
    }

    if bundle.get("schema") == LEGACY_BUNDLE_SCHEMA:
        case = {
            "schema": LEGACY_CASE_SCHEMA,
            "tool": {"name": "TextForensics", "version": get_version()},
            "forensic_bundle": bundle,
            "raw_text_included": False,
            "case_sha256": None,
        }
    else:
        case = {
            "schema": CASE_SCHEMA,
            "tool": tool,
            "created_at_utc": timestamp,
            "raw_text_included": False,
            "forensic_bundle": bundle,
            "manifest": _manifest_for(bundle, tool),
            "case_sha256": None,
        }
    case["case_sha256"] = _hash_without_seal(case)
    return case


def _verify_manifest(case: Mapping[str, Any], bundle: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    manifest = case.get("manifest")
    if not isinstance(manifest, Mapping):
        return ["missing_manifest"]
    expected = _manifest_for(bundle, case.get("tool", {}))
    for key in (
        "content_sha256",
        "registry_id",
        "registry_sha256",
        "calibration_ids",
        "schema_versions",
    ):
        if manifest.get(key) != expected.get(key):
            errors.append(f"manifest_mismatch:{key}")
    return errors


def verify_case_file(payload: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    schema = payload.get("schema")
    if schema not in {CASE_SCHEMA, LEGACY_CASE_SCHEMA}:
        errors.append("unsupported_schema")
    if payload.get("raw_text_included") is not False:
        errors.append("raw_text_policy_violation")

    supplied_hash = payload.get("case_sha256")
    if (
        not isinstance(supplied_hash, str)
        or len(supplied_hash) != 64
        or any(character not in "0123456789abcdef" for character in supplied_hash)
    ):
        errors.append("missing_or_invalid_case_sha256")
    elif supplied_hash != _hash_without_seal(payload):
        errors.append("case_hash_mismatch")

    bundle = payload.get("forensic_bundle")
    if not isinstance(bundle, Mapping):
        errors.append("missing_forensic_bundle")
    else:
        try:
            _validate_portable_bundle(bundle)
        except ValueError:
            errors.append("invalid_or_nonportable_forensic_bundle")
        if schema == CASE_SCHEMA:
            errors.extend(_verify_manifest(payload, bundle))
        if payload.get("tool", {}).get("name") != "TextForensics":
            errors.append("invalid_tool_identity")

    return {
        "valid": not errors,
        "errors": errors,
        "schema": schema,
        "case_sha256": supplied_hash,
        "note": (
            "Integrity verification checks this artifact's structure, seal and "
            "manifest; it does not prove an authorship conclusion."
        ),
    }


def write_case_file(
    path: str | Path,
    forensic_bundle: Mapping[str, Any],
    deterministic: bool = False,
    fixed_timestamp: str | None = None,
) -> dict[str, Any]:
    case = seal_case_file(
        forensic_bundle, deterministic=deterministic, fixed_timestamp=fixed_timestamp
    )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(case, ensure_ascii=False, indent=2, allow_nan=False) + "\n"

    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = handle.name
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
        temp_path = None
    finally:
        if temp_path is not None:
            with suppress(FileNotFoundError):
                os.unlink(temp_path)
    return case


def verify_case_file_path(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {
            "valid": False,
            "errors": ["case_file_must_be_json_object"],
            "schema": None,
            "case_sha256": None,
            "note": "The case file must be a JSON object.",
        }
    return verify_case_file(payload)


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def _prediction_from_dict(payload: Mapping[str, Any]) -> DetectorPrediction:
    fields = {
        "schema",
        "detector_id",
        "detector_version",
        "detector_family",
        "execution",
        "score",
        "score_semantics",
        "verdict",
        "threshold",
        "calibrated_ai_probability",
        "calibration_id",
        "reliability",
        "supported_languages",
        "min_words",
        "evidence",
        "warnings",
        "runtime_ms",
        "native_score_direction",
        "score_range",
        "supported_length",
        "supported_domains",
        "supported_editing_regimes",
        "supported_generators",
        "calibration",
        "runtime",
        "evidence_schema",
        "protocol_version",
        "normalized_from",
    }
    return DetectorPrediction(**{key: value for key, value in payload.items() if key in fields})


def _compare_scores(expected: Any, actual: Any, *, atol: float) -> bool:
    if expected is None or actual is None:
        return expected is None and actual is None
    if isinstance(expected, bool) or isinstance(actual, bool):
        return expected == actual
    if not isinstance(expected, (int, float)) or not isinstance(actual, (int, float)):
        return False
    return abs(float(expected) - float(actual)) <= atol


def _replay_detectors(
    sealed_results: Iterable[Mapping[str, Any]],
    detectors: Iterable[Detector],
    text: str,
    *,
    atol: float,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    checks: dict[str, Any] = {}
    expected = {
        str(item.get("detector_id")): item for item in sealed_results if isinstance(item, Mapping)
    }
    observed: dict[str, Any] = {}
    for detector in detectors:
        detector_id = str(getattr(detector, "detector_id", "unknown"))
        prediction, failure = execute_detector(detector, text)
        if prediction is None:
            errors.append(f"detector_failed:{detector_id}")
            observed[detector_id] = {
                "status": "failed",
                "failure": failure.to_dict() if failure else None,
            }
            continue
        row: dict[str, Any] = {
            "status": "observed",
            "detector_version": prediction.detector_version,
            "verdict": prediction.verdict,
            "score": prediction.score,
            "calibration_id": prediction.calibration_id,
        }
        baseline = expected.get(detector_id)
        if baseline is None:
            row["status"] = "not_in_case"
            errors.append(f"unexpected_detector:{detector_id}")
        else:
            if prediction.detector_version != baseline.get("detector_version"):
                errors.append(f"detector_version_mismatch:{detector_id}")
                row["version_match"] = False
            if prediction.verdict != baseline.get("verdict"):
                errors.append(f"verdict_mismatch:{detector_id}")
                row["verdict_match"] = False
            if not _compare_scores(baseline.get("score"), prediction.score, atol=atol):
                errors.append(f"score_mismatch:{detector_id}")
                row["score_match"] = False
            if prediction.calibration_id != baseline.get("calibration_id"):
                errors.append(f"calibration_id_mismatch:{detector_id}")
                row["calibration_match"] = False
        observed[detector_id] = row
    for detector_id in sorted(set(expected) - set(observed)):
        errors.append(f"detector_not_replayed:{detector_id}")
    checks["detectors"] = observed
    return errors, checks


def _replay_trust_map(
    sealed_bundle: Mapping[str, Any],
    registry: EvidenceRegistry | None,
) -> tuple[list[str], list[str], dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    checks: dict[str, Any] = {}
    conditions_payload = sealed_bundle.get("input_conditions")
    sealed_trust = sealed_bundle.get("trust_map")
    if not isinstance(conditions_payload, Mapping):
        errors.append("missing_input_conditions")
        return errors, warnings, checks
    if not isinstance(sealed_trust, Mapping):
        errors.append("missing_trust_map")
        return errors, warnings, checks

    sealed_registry = sealed_bundle.get("evidence_registry")
    sealed_registry_id = (
        sealed_registry.get("registry_id") if isinstance(sealed_registry, Mapping) else None
    )
    if sealed_registry_id and registry is None:
        warnings.append("registry_not_supplied:trust_map_not_rederived")
        checks["trust_map"] = {"status": "not_rederived", "reason": "registry_not_supplied"}
        return errors, warnings, checks
    if registry is not None and sealed_registry_id and registry.registry_id != sealed_registry_id:
        errors.append("registry_id_mismatch")
        checks["trust_map"] = {"status": "not_rederived", "reason": "registry_id_mismatch"}
        return errors, warnings, checks

    try:
        conditions = conditions_from_dict(conditions_payload)
    except (KeyError, TypeError, ValueError) as exc:
        errors.append("invalid_input_conditions")
        checks["trust_map"] = {"status": "not_rederived", "reason": str(exc)}
        return errors, warnings, checks

    results = sealed_bundle.get("detector_results", [])
    try:
        predictions = [_prediction_from_dict(item) for item in results if isinstance(item, Mapping)]
    except (TypeError, ValueError) as exc:
        errors.append("invalid_detector_results_for_replay")
        checks["trust_map"] = {"status": "not_rederived", "reason": str(exc)}
        return errors, warnings, checks

    robustness = sealed_bundle.get("robustness", {})
    robustness_rows = robustness.get("detectors", []) if isinstance(robustness, Mapping) else []
    failures = sealed_bundle.get("detector_failures", [])
    rederived = assess_trust_map(
        conditions,
        predictions,
        registry=registry,
        robustness=robustness_rows,
        failure_count=len(failures) if isinstance(failures, list) else 0,
        generated_at_utc=str(sealed_trust.get("generated_at_utc", "")),
    ).to_dict()
    sealed_states = {
        item.get("dimension"): item.get("state")
        for item in sealed_trust.get("dimensions", [])
        if isinstance(item, Mapping)
    }
    rederived_states = {item["dimension"]: item["state"] for item in rederived["dimensions"]}
    if sealed_states != rederived_states:
        errors.append("trust_map_state_mismatch")
        checks["trust_map"] = {
            "status": "mismatch",
            "sealed": sealed_states,
            "rederived": rederived_states,
        }
    elif sealed_trust.get("overall") != rederived["overall"]:
        errors.append("trust_map_overall_mismatch")
        checks["trust_map"] = {
            "status": "mismatch",
            "sealed_overall": sealed_trust.get("overall"),
            "rederived_overall": rederived["overall"],
        }
    else:
        checks["trust_map"] = {"status": "rederived", "overall": rederived["overall"]}
    return errors, warnings, checks


def replay_case_file(
    case: Mapping[str, Any],
    *,
    text: str | None = None,
    detectors: Iterable[Detector] | None = None,
    registry: EvidenceRegistry | None = None,
    atol: float = 1e-9,
) -> dict[str, Any]:
    """Replay a sealed case file.

    ``text`` is optional.  Without it, replay verifies structural integrity but
    cannot re-run detection.  ``registry`` is required to re-derive an
    evidence-conditioned Trust Map; without it, that check is reported as not
    performed rather than silently passing.
    """
    if isinstance(atol, bool) or not isinstance(atol, (int, float)) or atol < 0:
        raise ValueError("atol must be a non-negative number.")

    verification = verify_case_file(case)
    errors = list(verification["errors"])
    warnings: list[str] = []
    checks: dict[str, Any] = {
        "seal": {
            "status": "valid" if verification["valid"] else "invalid",
            "errors": verification["errors"],
        }
    }

    bundle = case.get("forensic_bundle")
    if not isinstance(bundle, Mapping):
        return {
            "valid": False,
            "errors": errors,
            "warnings": warnings,
            "checks": checks,
        }

    if text is not None:
        digest = text_sha256(text)
        if digest != bundle.get("content_sha256"):
            errors.append("text_hash_mismatch")
            checks["text"] = {"status": "mismatch"}
        else:
            checks["text"] = {"status": "matched", "sha256": digest}
    else:
        checks["text"] = {"status": "not_supplied"}

    if detectors is not None:
        if text is None:
            errors.append("text_required_for_detector_replay")
            checks["detectors"] = {"status": "not_performed", "reason": "text_not_supplied"}
        else:
            detector_errors, detector_checks = _replay_detectors(
                bundle.get("detector_results", []),
                detectors,
                text,
                atol=float(atol),
            )
            errors.extend(detector_errors)
            checks["detectors"] = detector_checks
    else:
        checks["detectors"] = {"status": "not_supplied"}

    trust_errors, trust_warnings, trust_checks = _replay_trust_map(bundle, registry)
    errors.extend(trust_errors)
    warnings.extend(trust_warnings)
    checks["trust_map"] = trust_checks

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "checks": checks,
        "note": (
            "Replay establishes reproducibility of the recorded process; it "
            "does not prove authorship."
        ),
    }


def replay_case_file_path(
    path: str | Path,
    *,
    text: str | None = None,
    detectors: Iterable[Detector] | None = None,
    registry: EvidenceRegistry | None = None,
    atol: float = 1e-9,
) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {
            "valid": False,
            "errors": ["case_file_must_be_json_object"],
            "warnings": [],
            "checks": {},
        }
    return replay_case_file(
        payload,
        text=text,
        detectors=detectors,
        registry=registry,
        atol=atol,
    )
