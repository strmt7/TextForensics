"""Forensic bundle consistency checking.

This module validates internal consistency of forensic bundles - checking that
field relationships make sense, timestamps are valid, and metadata aligns
with actual data.

This is a unique quality assurance feature: detecting inconsistent state
before it causes downstream issues.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass
class ConsistencyIssue:
    """A detected inconsistency in a forensic bundle."""

    field: str
    issue_type: str  # "mismatch", "invalid", "missing", "type_error"
    message: str
    severity: str  # "warning", "error", "critical"


@dataclass
class ConsistencyReport:
    """Full consistency analysis of a forensic bundle."""

    is_consistent: bool
    issues: list[ConsistencyIssue]
    checked_fields: list[str]


def _check_field_value(
    bundle: dict[str, Any],
    field_path: str,
    *,
    expected_type: type | None = None,
    min_value: float | None = None,
    max_value: float | None = None,
    required: bool = False,
) -> ConsistencyIssue | None:
    """Check a single field for validity.

    Returns None if the field is valid, or a ConsistencyIssue if not.
    """
    keys = field_path.split(".")
    value = bundle
    for key in keys:
        if not isinstance(value, dict):
            if required:
                return ConsistencyIssue(
                    field=field_path,
                    issue_type="missing",
                    message=f"Required field {field_path} is missing.",
                    severity="error",
                )
            return None
        if key not in value:
            if required:
                return ConsistencyIssue(
                    field=field_path,
                    issue_type="missing",
                    message=f"Required field {field_path} is missing.",
                    severity="error",
                )
            return None
        value = value[key]

    if expected_type is not None and not isinstance(value, expected_type):
        return ConsistencyIssue(
            field=field_path,
            issue_type="type_error",
            message=f"Field {field_path} has type {type(value).__name__}, expected {expected_type.__name__}.",
            severity="error",
        )

    if isinstance(value, (int, float)) and min_value is not None and value < min_value:
        return ConsistencyIssue(
            field=field_path,
            issue_type="invalid",
            message=f"Field {field_path} value {value} is below minimum {min_value}.",
            severity="warning",
        )

    if isinstance(value, (int, float)) and max_value is not None and value > max_value:
        return ConsistencyIssue(
            field=field_path,
            issue_type="invalid",
            message=f"Field {field_path} value {value} exceeds maximum {max_value}.",
            severity="warning",
        )

    return None


def _check_bundle_consistency(bundle: dict[str, Any]) -> list[ConsistencyIssue]:
    """Validate internal consistency of a forensic bundle."""
    issues: list[ConsistencyIssue] = []

    # Check schema
    schema = bundle.get("schema")
    if schema is None:
        issues.append(
            ConsistencyIssue(
                field="schema",
                issue_type="missing",
                message="Bundle is missing required 'schema' field.",
                severity="error",
            )
        )
    elif not isinstance(schema, str):
        issues.append(
            ConsistencyIssue(
                field="schema",
                issue_type="type_error",
                message=f"Schema has invalid type: {type(schema).__name__}",
                severity="error",
            )
        )

    # Check consensus structure
    consensus = bundle.get("consensus", {})
    if not isinstance(consensus, dict):
        issues.append(
            ConsistencyIssue(
                field="consensus",
                issue_type="type_error",
                message="Consensus must be a dictionary.",
                severity="error",
            )
        )
    else:
        verdict = consensus.get("verdict")
        if verdict is not None and verdict not in (
            "ai_like",
            "human_like",
            "abstain",
            "insufficient_evidence",
            "mixed",
        ):
            issues.append(
                ConsistencyIssue(
                    field="consensus.verdict",
                    issue_type="invalid",
                    message=f"Invalid verdict value: {verdict}",
                    severity="warning",
                )
            )

        # Check AI probability range if present
        ai_prob = consensus.get("ai_probability")
        if ai_prob is not None:
            issue = _check_field_value(
                bundle, "consensus.ai_probability", min_value=0.0, max_value=1.0
            )
            if issue:
                issues.append(issue)

    # Check detector results consistency
    detector_results = bundle.get("detector_results", [])
    if not isinstance(detector_results, list):
        issues.append(
            ConsistencyIssue(
                field="detector_results",
                issue_type="type_error",
                message="detector_results must be a list.",
                severity="error",
            )
        )
    else:
        detector_ids = set()
        for i, result in enumerate(detector_results):
            if not isinstance(result, dict):
                issues.append(
                    ConsistencyIssue(
                        field=f"detector_results[{i}]",
                        issue_type="type_error",
                        message=f"Detector result {i} is not a dictionary.",
                        severity="warning",
                    )
                )
                continue

            # Check for duplicate detector IDs
            det_id = result.get("detector_id")
            if det_id:
                if det_id in detector_ids:
                    issues.append(
                        ConsistencyIssue(
                            field=f"detector_results[{i}].detector_id",
                            issue_type="mismatch",
                            message=f"Duplicate detector_id: {det_id}",
                            severity="warning",
                        )
                    )
                detector_ids.add(det_id)

            # Check score range for uncalibrated
            score = result.get("score")
            reliability = result.get("reliability")
            if score is not None and reliability is not None and reliability < 0.1:
                # Uncalibrated scores with low reliability
                issues.append(
                    ConsistencyIssue(
                        field=f"detector_results[{i}].reliability",
                        issue_type="warning",
                        message=f"Detector {det_id} has low reliability ({reliability:.3f}) with score {score:.3f}. Treat with caution.",
                        severity="warning",
                    )
                )

    # Check trust map structure
    trust_map = bundle.get("trust_map", {})
    if isinstance(trust_map, dict):
        overall = trust_map.get("overall")
        # Overall is the aggregate verdict over the dimensions, NOT a
        # dimension state: trust.TrustMap requires it to be one of
        # {"strong", "mixed", "insufficient"} (trust.py). Validating it
        # against the dimension states flagged every real bundle.
        if overall is not None and overall not in (
            "strong",
            "mixed",
            "insufficient",
        ):
            issues.append(
                ConsistencyIssue(
                    field="trust_map.overall",
                    issue_type="invalid",
                    message=f"Invalid overall trust state: {overall}",
                    severity="warning",
                )
            )

        dims = trust_map.get("dimensions", [])
        if isinstance(dims, list):
            for i, dim in enumerate(dims):
                if not isinstance(dim, dict):
                    issues.append(
                        ConsistencyIssue(
                            field=f"trust_map.dimensions[{i}]",
                            issue_type="type_error",
                            message="Trust dimension must be a dictionary.",
                            severity="warning",
                        )
                    )
                    continue
                state = dim.get("state")
                if state is not None and state not in (
                    "supported",
                    "partial",
                    "unknown",
                    "out_of_scope",
                ):
                    issues.append(
                        ConsistencyIssue(
                            field=f"trust_map.dimensions[{i}].state",
                            issue_type="invalid",
                            message=f"Invalid dimension state: {state}",
                            severity="warning",
                        )
                    )

    # Check input statistics
    inp = bundle.get("input", {})
    if isinstance(inp, dict):
        word_count = inp.get("word_count")
        if word_count is not None and word_count < 0:
            issues.append(
                ConsistencyIssue(
                    field="input.word_count",
                    issue_type="invalid",
                    message=f"Word count cannot be negative: {word_count}",
                    severity="error",
                )
            )

        sentence_count = inp.get("sentence_count")
        inp.get("paragraph_count")
        if (
            word_count is not None
            and sentence_count is not None
            and word_count > 0
            and sentence_count == 0
        ):
            issues.append(
                ConsistencyIssue(
                    field="input.sentence_count",
                    issue_type="mismatch",
                    message=f"Word count is {word_count} but sentence count is 0.",
                    severity="warning",
                )
            )

    # Check content_sha256
    content_sha256 = bundle.get("content_sha256")
    if content_sha256 is not None:
        if not isinstance(content_sha256, str):
            issues.append(
                ConsistencyIssue(
                    field="content_sha256",
                    issue_type="type_error",
                    message="content_sha256 must be a string.",
                    severity="error",
                )
            )
        elif len(content_sha256) != 64:
            issues.append(
                ConsistencyIssue(
                    field="content_sha256",
                    issue_type="invalid",
                    message=f"content_sha256 should be 64 hex characters, got {len(content_sha256)}.",
                    severity="error",
                )
            )

    return issues


def check_bundle_consistency(bundle: dict[str, Any]) -> ConsistencyReport:
    """Check internal consistency of a forensic bundle.

    This validates field relationships, types, and value ranges to detect
    potentially corrupted or incorrectly constructed bundles before they
    are used or distributed.

    Returns a report with any detected issues and an overall consistency
    status.
    """
    issues = _check_bundle_consistency(bundle)

    critical_errors = sum(1 for i in issues if i.severity == "critical")
    errors = sum(1 for i in issues if i.severity == "error")

    is_consistent = critical_errors == 0 and errors == 0

    checked_fields = [
        "schema",
        "consensus.verdict",
        "consensus.ai_probability",
        "detector_results.*.detector_id",
        "detector_results.*.score",
        "detector_results.*.reliability",
        "trust_map.overall",
        "trust_map.dimensions.*.state",
        "input.word_count",
        "input.sentence_count",
        "input.paragraph_count",
        "content_sha256",
    ]

    return ConsistencyReport(
        is_consistent=is_consistent,
        issues=issues,
        checked_fields=checked_fields,
    )


def bundle_hash(bundle: dict[str, Any]) -> str:
    """Compute a content hash for a forensic bundle.

    This excludes fields that may vary between identical bundles
    (like timestamps).
    """
    canonical = {
        "schema": bundle.get("schema"),
        "consensus": bundle.get("consensus", {}),
        "trust_map": bundle.get("trust_map", {}),
        "detector_results": bundle.get("detector_results", []),
        "input": bundle.get("input", {}),
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()
