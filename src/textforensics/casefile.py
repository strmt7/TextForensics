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

Case-file versions
------------------
``v1`` is the legacy shape (no manifest, no creation timestamp).
``v2`` adds the manifest and ``created_at_utc``.  ``v3`` (the current
default) adds the U2 legal-process sections: ``input`` (acquisition
metadata), ``detector_observations`` (a normalised, re-verifiable view
of the bundle's observations), ``validation_refs`` (pointers into the
U1 validation registry), ``limitations`` (mandatory plain-language
disclosure plus counterfactuals), ``process`` (the D1–D10
due-process/appeal checklist), ``custody`` (an append-only hash chain),
``seal`` (three-tier seal record: hash always, Ed25519/DSSE signature,
RFC 3161 timestamp reference) and ``gaps`` (absent items declared with
a reason, never silently omitted).  All three versions verify; only v3
is sealed by default.

The seal record cannot hold the sealed *bundle's* own digest: the
bundle digest depends on the case file's bytes, so a case file that
contained its own bundle digest could never be self-consistent.  The
per-file manifest and the bundle digest therefore live in the sealed
bundle (``sealed_bundle`` module) and in a companion seal record, while
the case file's ``seal`` section holds the case-level signature, the
timestamp reference and the digest-publication record.
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

CASE_SCHEMA_V3 = "textforensics.case-file/v3"
CASE_SCHEMA = "textforensics.case-file/v2"
LEGACY_CASE_SCHEMA = "textforensics.case-file/v1"
CASE_SCHEMAS = frozenset({CASE_SCHEMA_V3, CASE_SCHEMA, LEGACY_CASE_SCHEMA})
BUNDLE_SCHEMA = "textforensics.forensic-bundle/v2"
LEGACY_BUNDLE_SCHEMA = "textforensics.forensic-bundle/v1"
TRUST_SCHEMA = "textforensics.trust-map/v2"
TRUST_SCHEMA_V3 = "textforensics.trust-map/v3"
DETECTOR_SCHEMA = "textforensics.detector-result/v2"

# The submitted text is hashed exactly as supplied, encoded as UTF-8,
# with no case folding, whitespace normalisation, or other transformation
# (see detectors.text_sha256).  Recording this verbatim is what makes
# hash-then-reveal replay possible: the verifier applies the same steps.
INPUT_NORMALISATION = (
    "The submitted text is hashed exactly as supplied, encoded as UTF-8, "
    "with no case folding, whitespace normalisation, or other transformation."
)

CHECKLIST_ITEMS = ("D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "D10")
CHECKLIST_STATUSES = ("satisfied", "not_satisfied", "not_applicable", "unknown")
CHECKLIST_TITLES = {
    "D1": "Evidence considered, enumerated",
    "D2": "Contrary / exculpatory evidence addressed",
    "D3": "Alternative explanations tested and recorded",
    "D4": "Human review step, named",
    "D5": "Separation of roles",
    "D6": "Limitations disclosed to the subject",
    "D7": "Subject's response recorded",
    "D8": "What would change the decision",
    "D9": "Retention, access & disposal",
    "D10": "Provenance of the process itself",
}
# Greg's decision (Phase 3, §13): the D1–D10 checklist ships with
# "template, not legal advice" framing; legal review is sought only on
# institutional adoption.  The checklist is education-grounded; it is
# not presented as employment-law-compliant.
CHECKLIST_TEMPLATE_NOTICE = (
    "Template, not legal advice. This checklist is an education-grounded "
    "template for due-process review of an AI-text detection finding. It "
    "is not a policy, not legal advice, and not a finding of admissibility "
    "or compliance. Adapt it to the institution's own code with legal "
    "review before consequential use."
)
CHECKLIST_DISPOSITIONS = ("relied_on", "considered", "discounted")

# D3 alternative explanations (research §6.4).  Each entry is recorded
# as tested / not_tested / not_applicable with an outcome.
ALTERNATIVE_EXPLANATIONS = (
    "tutoring_or_editing_assistance",
    "non_native_or_esl_writing",
    "disciplinary_conventions",
    "short_text_limits",
    "paraphrase_or_editing_regime",
    "template_or_boilerplate_text",
)

# D8 counterfactuals recorded when the sealer supplies none of their own.
DEFAULT_COUNTERFACTUALS = (
    "A longer sample of the subject's writing.",
    "Draft or revision history for the submitted text.",
    "A C2PA or other provenance manifest for the document.",
    "A second, independent detector family reaching the same conclusion.",
    "Evidence about the editing or paraphrase regime applied to the text.",
)

CUSTODY_GENESIS_PREV_HASH = "0" * 64

SCORE_NOT_PROBABILITY = (
    "The detector score is not a probability that the text was written by "
    "an AI system. Scores are detector-native values; only a documented "
    "calibration artifact can support a probability, and only for the exact "
    "output semantics it was fitted for."
)
AUTHORSHIP_WARNING = (
    "Text-only detection cannot prove authorship. A detector result is "
    "evidence about textual signals, not a finding about who wrote the text."
)

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


# ---------------------------------------------------------------------------
# Case-file v3 sections (U2)
# ---------------------------------------------------------------------------


def _checklist_item(
    status: str = "unknown",
    *,
    evidence: list[str] | None = None,
    actor: str | None = None,
    at_utc: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    if status not in CHECKLIST_STATUSES:
        raise ValueError(f"Invalid checklist status: {status!r}.")
    return {
        "status": status,
        "evidence": list(evidence or []),
        "actor": actor,
        "at_utc": at_utc,
        "note": note,
    }


def build_checklist(
    items: Mapping[str, Mapping[str, Any]] | None = None,
    *,
    policy_version: str | None = None,
    procedure_version: str | None = None,
    reviewer: Mapping[str, Any] | None = None,
    appeal: Mapping[str, Any] | None = None,
    retention: Mapping[str, Any] | None = None,
    contrary_evidence: list[Mapping[str, Any]] | None = None,
    evidence_dispositions: Mapping[str, Mapping[str, Any]] | None = None,
    alternative_explanations: Mapping[str, Mapping[str, Any]] | None = None,
    subject_response: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the D1–D10 due-process / appeal checklist (``process``).

    Every item defaults to ``unknown`` with a note that nothing was
    recorded at seal time — an unrecorded item is never silently
    presented as satisfied.  Callers supply per-item records (status,
    evidence pointers, actor, timestamp, note) for the items they can
    evidence.  The checklist is a template, not legal advice (see
    ``CHECKLIST_TEMPLATE_NOTICE``).
    """
    supplied = dict(items or {})
    unknown_keys = sorted(set(supplied) - set(CHECKLIST_ITEMS))
    if unknown_keys:
        raise ValueError(f"Unknown checklist items: {', '.join(unknown_keys)}.")
    built: dict[str, Any] = {}
    for item_id in CHECKLIST_ITEMS:
        record = supplied.get(item_id)
        if record is None:
            built[item_id] = _checklist_item(
                note="Not recorded at seal time; complete before consequential use."
            )
            continue
        if not isinstance(record, Mapping):
            raise ValueError(f"Checklist item {item_id} must be a mapping.")
        built[item_id] = _checklist_item(
            str(record.get("status", "unknown")),
            evidence=record.get("evidence"),
            actor=record.get("actor"),
            at_utc=record.get("at_utc"),
            note=record.get("note"),
        )
    dispositions: dict[str, Any] = {}
    for detector_id, disposition in dict(evidence_dispositions or {}).items():
        if not isinstance(disposition, Mapping):
            raise ValueError("Evidence dispositions must be mappings.")
        value = disposition.get("disposition")
        if value not in CHECKLIST_DISPOSITIONS:
            raise ValueError(
                f"Disposition for {detector_id!r} must be one of "
                f"{', '.join(CHECKLIST_DISPOSITIONS)}."
            )
        dispositions[str(detector_id)] = {
            "disposition": value,
            "reason": disposition.get("reason"),
        }
    explanations: dict[str, Any] = {}
    for name, entry in dict(alternative_explanations or {}).items():
        if name not in ALTERNATIVE_EXPLANATIONS:
            raise ValueError(f"Unknown alternative explanation: {name!r}.")
        if not isinstance(entry, Mapping):
            raise ValueError("Alternative explanations must be mappings.")
        tested = entry.get("tested")
        if tested not in {"tested", "not_tested", "not_applicable"}:
            raise ValueError(
                f"Alternative explanation {name!r} needs tested/not_tested/not_applicable."
            )
        explanations[name] = {"tested": tested, "outcome": entry.get("outcome")}
    return {
        "template_notice": CHECKLIST_TEMPLATE_NOTICE,
        "policy_version": policy_version,
        "procedure_version": procedure_version,
        "items": built,
        "reviewer": dict(reviewer) if reviewer is not None else None,
        "appeal": dict(appeal) if appeal is not None else None,
        "retention": dict(retention) if retention is not None else None,
        "contrary_evidence": [dict(entry) for entry in (contrary_evidence or [])],
        "evidence_dispositions": dispositions,
        "alternative_explanations": explanations,
        "subject_response": dict(subject_response) if subject_response is not None else None,
    }


def validate_checklist(process: Mapping[str, Any]) -> list[str]:
    """Structural validation of a ``process`` section. Returns errors."""
    errors: list[str] = []
    if not isinstance(process, Mapping):
        return ["process_not_a_mapping"]
    if process.get("template_notice") != CHECKLIST_TEMPLATE_NOTICE:
        errors.append("checklist_template_notice_missing_or_altered")
    items = process.get("items")
    if not isinstance(items, Mapping):
        return errors + ["checklist_items_missing"]
    for item_id in CHECKLIST_ITEMS:
        record = items.get(item_id)
        if not isinstance(record, Mapping):
            errors.append(f"checklist_{item_id.lower()}_missing")
            continue
        if record.get("status") not in CHECKLIST_STATUSES:
            errors.append(f"checklist_{item_id.lower()}_invalid_status")
        evidence = record.get("evidence")
        if evidence is not None and (
            not isinstance(evidence, list) or any(not isinstance(entry, str) for entry in evidence)
        ):
            errors.append(f"checklist_{item_id.lower()}_invalid_evidence")
    for detector_id, disposition in (process.get("evidence_dispositions") or {}).items():
        if (
            not isinstance(disposition, Mapping)
            or disposition.get("disposition") not in CHECKLIST_DISPOSITIONS
        ):
            errors.append(f"checklist_disposition_invalid:{detector_id}")
    for name, entry in (process.get("alternative_explanations") or {}).items():
        if name not in ALTERNATIVE_EXPLANATIONS:
            errors.append(f"checklist_alternative_explanation_unknown:{name}")
        elif not isinstance(entry, Mapping) or entry.get("tested") not in {
            "tested",
            "not_tested",
            "not_applicable",
        }:
            errors.append(f"checklist_alternative_explanation_invalid:{name}")
    return errors


def _custody_entry_hash(
    *, actor: str, action: str, at_utc: str, note: str | None, prev_hash: str
) -> str:
    payload = {
        "actor": actor,
        "action": action,
        "at_utc": at_utc,
        "note": note,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def chain_custody_entry(
    custody: list[dict[str, Any]],
    *,
    actor: str,
    action: str,
    at_utc: str,
    note: str | None = None,
) -> dict[str, Any]:
    """Append one entry to a custody hash chain (returns the new entry).

    Each entry hash covers the previous entry hash plus the event bytes,
    so tampering with any entry breaks every subsequent link.  The
    genesis entry chains from 32 zero bytes.
    """
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("Custody actor must be a non-empty string.")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("Custody action must be a non-empty string.")
    if not isinstance(at_utc, str) or not at_utc.strip():
        raise ValueError("Custody at_utc must be a non-empty string.")
    prev_hash = custody[-1]["entry_hash"] if custody else CUSTODY_GENESIS_PREV_HASH
    entry = {
        "actor": actor,
        "action": action,
        "at_utc": at_utc,
        "note": note,
        "prev_hash": prev_hash,
        "entry_hash": _custody_entry_hash(
            actor=actor, action=action, at_utc=at_utc, note=note, prev_hash=prev_hash
        ),
    }
    return entry


def verify_custody(custody: Any) -> list[str]:
    """Verify a custody hash chain. Returns errors (empty when valid)."""
    errors: list[str] = []
    if not isinstance(custody, list) or not custody:
        return ["custody_missing_or_empty"]
    prev_hash = CUSTODY_GENESIS_PREV_HASH
    for index, entry in enumerate(custody):
        if not isinstance(entry, Mapping):
            errors.append(f"custody_entry_not_a_mapping:{index}")
            return errors
        if entry.get("prev_hash") != prev_hash:
            errors.append(f"custody_chain_broken:{index}")
            return errors
        expected = _custody_entry_hash(
            actor=str(entry.get("actor")),
            action=str(entry.get("action")),
            at_utc=str(entry.get("at_utc")),
            note=entry.get("note"),
            prev_hash=prev_hash,
        )
        if entry.get("entry_hash") != expected:
            errors.append(f"custody_entry_hash_mismatch:{index}")
            return errors
        prev_hash = str(entry.get("entry_hash"))
    return errors


def build_case_input(
    bundle: Mapping[str, Any],
    *,
    source: Mapping[str, Any] | None = None,
    acquired_by: str | None = None,
    acquisition_method: str | None = None,
    authorisation_ref: str | None = None,
    acquired_at_utc: str | None = None,
    normalisation: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Build the v3 ``input`` (acquisition) section plus its gaps.

    Returns ``(input_section, gaps)``.  Word/character counts come from
    the bundle's ``input_conditions``; sentence/paragraph counts are not
    recorded by the forensic bundle and are always declared as gaps.
    """
    gaps: list[dict[str, str]] = []
    conditions = bundle.get("input_conditions")
    word_count = None
    char_count = None
    if isinstance(conditions, Mapping):
        word_count = conditions.get("word_count")
        char_count = conditions.get("char_count")
    if not isinstance(word_count, int):
        word_count = None
        gaps.append(
            {
                "field": "input.word_count",
                "reason": "The forensic bundle carries no input_conditions word count.",
            }
        )
    if not isinstance(char_count, int):
        char_count = None
        gaps.append(
            {
                "field": "input.char_count",
                "reason": "The forensic bundle carries no input_conditions character count.",
            }
        )
    gaps.append(
        {
            "field": "input.sentence_count",
            "reason": (
                "Sentence counts are not recorded by the forensic bundle "
                "(input_conditions carries word and character counts only)."
            ),
        }
    )
    gaps.append(
        {
            "field": "input.paragraph_count",
            "reason": (
                "Paragraph counts are not recorded by the forensic bundle "
                "(input_conditions carries word and character counts only)."
            ),
        }
    )
    source_section: dict[str, Any] = {}
    if source is not None:
        if not isinstance(source, Mapping):
            raise ValueError("input source must be a mapping.")
        for key in ("system", "receipt_id"):
            value = source.get(key)
            if isinstance(value, str) and value:
                source_section[key] = value
        filename_hash = source.get("filename_sha256")
        if filename_hash is not None:
            _validate_digest(filename_hash, "source.filename_sha256")
            source_section["filename_sha256"] = filename_hash
    if not source_section:
        gaps.append(
            {
                "field": "input.source",
                "reason": "No submission-system, receipt, or filename hash was supplied at seal time.",
            }
        )
    for field_name, value in (
        ("input.acquired_by", acquired_by),
        ("input.acquisition_method", acquisition_method),
        ("input.authorisation_ref", authorisation_ref),
        ("input.acquired_at_utc", acquired_at_utc),
    ):
        if not isinstance(value, str) or not value:
            gaps.append(
                {
                    "field": field_name,
                    "reason": f"No {field_name.split('.', 1)[1]} was supplied at seal time.",
                }
            )
    return (
        {
            "content_sha256": bundle.get("content_sha256"),
            "normalisation": normalisation or INPUT_NORMALISATION,
            "word_count": word_count,
            "char_count": char_count,
            "source": source_section,
            "acquired_at_utc": acquired_at_utc,
            "acquired_by": acquired_by,
            "acquisition_method": acquisition_method,
            "authorisation_ref": authorisation_ref,
        },
        gaps,
    )


def build_detector_observations(
    bundle: Mapping[str, Any],
    *,
    dispositions: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build the v3 ``detector_observations`` view of the bundle.

    A normalised, re-verifiable view of ``detector_results``,
    ``detector_failures`` and ``plugin_health``: every observation
    carries detector ID/version, checkpoint/provider version, config
    hash, runtime, calibration ID and native score semantics.  Failures
    are recorded with their reason, never silently dropped.
    """
    observations: list[dict[str, Any]] = []
    for result in bundle.get("detector_results", []):
        if not isinstance(result, Mapping):
            continue
        detector_id = result.get("detector_id")
        disposition = (dispositions or {}).get(str(detector_id)) or {}
        observations.append(
            {
                "kind": "observed",
                "detector_id": detector_id,
                "detector_version": result.get("detector_version"),
                "checkpoint_or_provider_version": result.get("checkpoint_version")
                or result.get("provider_version")
                or result.get("model_version"),
                "config_hash": result.get("config_hash"),
                "runtime": result.get("runtime"),
                "calibration_id": result.get("calibration_id"),
                "score": result.get("score"),
                "score_semantics": result.get("score_semantics"),
                "verdict": result.get("verdict"),
                "native_score_direction": result.get("native_score_direction"),
                "score_range": result.get("score_range"),
                "supported_languages": result.get("supported_languages"),
                "min_words": result.get("min_words"),
                "disposition": disposition.get("disposition"),
                "disposition_reason": disposition.get("reason"),
            }
        )
    for failure in bundle.get("detector_failures", []):
        if not isinstance(failure, Mapping):
            continue
        observations.append(
            {
                "kind": "failed",
                "detector_id": failure.get("detector_id"),
                "detector_version": None,
                "checkpoint_or_provider_version": None,
                "config_hash": None,
                "runtime": None,
                "calibration_id": None,
                "score": None,
                "score_semantics": None,
                "verdict": None,
                "native_score_direction": None,
                "score_range": None,
                "supported_languages": None,
                "min_words": None,
                "disposition": None,
                "disposition_reason": None,
                "reason": failure.get("reason") or failure.get("error") or "detector failed",
                "detail": dict(failure),
            }
        )
    for row in bundle.get("plugin_health", []):
        if not isinstance(row, Mapping):
            continue
        observations.append(
            {
                "kind": "plugin_health",
                "detector_id": row.get("detector_id") or row.get("plugin"),
                "detector_version": None,
                "checkpoint_or_provider_version": None,
                "config_hash": None,
                "runtime": None,
                "calibration_id": None,
                "score": None,
                "score_semantics": None,
                "verdict": None,
                "native_score_direction": None,
                "score_range": None,
                "supported_languages": None,
                "min_words": None,
                "disposition": None,
                "disposition_reason": None,
                "reason": None,
                "detail": dict(row),
            }
        )
    return observations


def build_validation_refs(
    bundle: Mapping[str, Any],
    registry: Any | None,
    *,
    now: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Build the v3 ``validation_refs`` pointers into the U1 registry.

    Returns ``(refs, gaps)``.  Per observed detector, the records whose
    declared regime covers the sealed input conditions (via the
    registry's public ``matching`` API) are listed with their stored
    and effective statuses plus the nearest-slice human FPR.  The
    registry digest is the registry id itself: the id *is* the SHA-256
    of the canonical registry payload (see
    ``validation.ValidationRegistry._compute_registry_id``), so the two
    fields are identical by construction and are recorded as such.
    A verifier holding the registry can check every pointer without
    trusting the sealer's word for it.
    """
    if registry is None:
        return [], [
            {
                "field": "validation_refs",
                "reason": "No validation registry was supplied at seal time; no evidence pointers were recorded.",
            }
        ]
    from .validation import INPUT_EDITING_REGIME_MAP, effective_status

    conditions_payload = bundle.get("input_conditions")
    try:
        conditions = conditions_from_dict(conditions_payload)
    except (KeyError, TypeError, ValueError):
        return [], [
            {
                "field": "validation_refs",
                "reason": "The forensic bundle's input_conditions are invalid, so no regime matching was possible.",
            }
        ]
    mapped_editing = INPUT_EDITING_REGIME_MAP.get(conditions.effective_editing_regime, "unknown")
    refs: list[dict[str, Any]] = []
    detector_ids = sorted(
        {
            str(result.get("detector_id"))
            for result in bundle.get("detector_results", [])
            if isinstance(result, Mapping) and result.get("detector_id")
        }
    )
    observations = {
        str(result.get("detector_id")): result
        for result in bundle.get("detector_results", [])
        if isinstance(result, Mapping) and result.get("detector_id")
    }
    for detector_id in detector_ids:
        records = registry.matching(
            language=conditions.effective_language
            if conditions.effective_language != "und"
            else None,
            word_count=conditions.word_count,
            domain=conditions.effective_domain
            if conditions.effective_domain != "unknown"
            else None,
            editing_regime=mapped_editing if mapped_editing != "unknown" else None,
            detector_id=detector_id,
        )
        detector_version = observations[detector_id].get("detector_version")
        record_refs: list[dict[str, Any]] = []
        for record in records:
            payload = record.to_dict()
            metrics = payload.get("metrics") or []
            fpr_native = None
            if metrics and isinstance(metrics[0], Mapping):
                raw_fpr = metrics[0].get("fpr_native")
                if isinstance(raw_fpr, Mapping):
                    fpr_native = {
                        "value": raw_fpr.get("value"),
                        "n": raw_fpr.get("n"),
                        "ci_lower": raw_fpr.get("ci_lower"),
                        "ci_upper": raw_fpr.get("ci_upper"),
                        "method": raw_fpr.get("method"),
                    }
            regime = payload.get("regime") or {}
            record_refs.append(
                {
                    "record_id": record.record_id,
                    "stored_status": record.status,
                    "effective_status": effective_status(
                        record, detector_version=str(detector_version), now=now
                    ),
                    "regime": regime,
                    "fpr_native": fpr_native,
                }
            )
        refs.append(
            {
                "detector_id": detector_id,
                "detector_version": detector_version,
                "registry_id": registry.registry_id,
                "registry_sha256": registry.registry_id,
                "covers_input_regime": bool(record_refs),
                "records": record_refs,
            }
        )
    return refs, []


def build_limitations(
    bundle: Mapping[str, Any],
    validation_refs: list[dict[str, Any]] | None = None,
    *,
    counterfactuals: list[str] | None = None,
) -> dict[str, Any]:
    """Build the v3 ``limitations`` section (D6 disclosure + D8).

    The human-FPR sentence names the nearest matching record when the
    validation refs carry one; otherwise it discloses honestly that no
    human false-positive evidence is available for this regime.
    """
    fpr_text = (
        "No human false-positive evidence is available for this input "
        "regime in the validation records supplied at seal time; the "
        "worst-slice human false-positive rate is unknown."
    )
    for ref in validation_refs or []:
        for record in ref.get("records", []):
            fpr = record.get("fpr_native") or {}
            if fpr.get("value") is None:
                continue
            value = fpr["value"]
            ci_lower = fpr.get("ci_lower")
            ci_upper = fpr.get("ci_upper")
            n_value = fpr.get("n")
            if ci_lower is not None and ci_upper is not None:
                fpr_text = (
                    f"Nearest-slice human false-positive rate: {value:.4f} "
                    f"(95% CI [{ci_lower:.4f}, {ci_upper:.4f}], n={n_value}) "
                    f"from validation record {record.get('record_id')}."
                )
            else:
                fpr_text = (
                    f"Nearest-slice human false-positive rate: {value:.4f} "
                    f"(n={n_value}) from validation record {record.get('record_id')}."
                )
            break
        if "Nearest-slice" in fpr_text:
            break
    bundle_limitations = bundle.get("limitations")
    return {
        "plain_language": {
            "score_not_probability": SCORE_NOT_PROBABILITY,
            "authorship_warning": AUTHORSHIP_WARNING,
            "human_fpr": fpr_text,
        },
        "counterfactuals": list(counterfactuals)
        if counterfactuals is not None
        else list(DEFAULT_COUNTERFACTUALS),
        "bundle_limitations": list(bundle_limitations)
        if isinstance(bundle_limitations, list)
        else [],
    }


def _checklist_consistency(case: Mapping[str, Any], bundle: Mapping[str, Any]) -> list[str]:
    """Re-derive checklist consistency from the sealed evidence.

    A ``satisfied`` item must be supported by the sealed evidence; an
    unsupported ``satisfied`` is an error, not a warning.  Items marked
    ``not_satisfied`` / ``not_applicable`` / ``unknown`` are declarations
    and are not re-derived.  The rules are deliberately narrow and
    deterministic (research §6.6, step 6).
    """
    errors: list[str] = []
    process = case.get("process")
    if not isinstance(process, Mapping):
        return ["checklist_missing"]
    errors.extend(f"checklist_invalid:{detail}" for detail in validate_checklist(process))
    items = process.get("items")
    if not isinstance(items, Mapping):
        return errors + ["checklist_items_missing"]
    observations = case.get("detector_observations") or []
    observed = [item for item in observations if isinstance(item, Mapping)]

    def _status(item_id: str) -> str | None:
        record = items.get(item_id)
        return record.get("status") if isinstance(record, Mapping) else None

    # D1: every observation needs a disposition (relied on / considered /
    # discounted + why) before the evidence can be called enumerated.
    if _status("D1") == "satisfied":
        missing = [
            str(item.get("detector_id"))
            for item in observed
            if item.get("kind") == "observed" and not item.get("disposition")
        ]
        if missing:
            errors.append(
                f"checklist_d1_unsupported:missing_disposition:{','.join(sorted(missing))}"
            )
    # D2: detector disagreement without a recorded contrary-evidence entry
    # cannot be called addressed.
    if _status("D2") == "satisfied":
        verdicts = {item.get("verdict") for item in observed if item.get("kind") == "observed"}
        if "ai_like" in verdicts and "human_like" in verdicts:
            contrary = process.get("contrary_evidence")
            if not isinstance(contrary, list) or not contrary:
                errors.append("checklist_d2_unsupported:detector_disagreement_unaddressed")
            else:
                for entry in contrary:
                    if not isinstance(entry, Mapping) or not entry.get("detector_id"):
                        errors.append("checklist_d2_unsupported:contrary_evidence_incomplete")
                        break
    # D3: every listed alternative explanation needs a tested verdict.
    if _status("D3") == "satisfied":
        explanations = process.get("alternative_explanations")
        if not isinstance(explanations, Mapping) or not explanations:
            errors.append("checklist_d3_unsupported:no_alternative_explanations_recorded")
    # D4: the reviewer must be named, with reasoning in their own words
    # and an explicit agree/disagree position.
    if _status("D4") == "satisfied":
        reviewer = process.get("reviewer")
        if not isinstance(reviewer, Mapping):
            errors.append("checklist_d4_unsupported:reviewer_missing")
        else:
            if not reviewer.get("identity") or not reviewer.get("role"):
                errors.append("checklist_d4_unsupported:reviewer_unidentified")
            if not reviewer.get("reasoning"):
                errors.append("checklist_d4_unsupported:reasoning_missing")
            if reviewer.get("agreed_with_tool") not in {True, False}:
                errors.append("checklist_d4_unsupported:position_missing")
    # D5: the appeal decider must be a different person from the decider.
    if _status("D5") == "satisfied":
        appeal = process.get("appeal")
        if not isinstance(appeal, Mapping):
            errors.append("checklist_d5_unsupported:appeal_missing")
        else:
            decider = appeal.get("decider")
            appeal_decider = appeal.get("appeal_decider")
            if not decider or not appeal_decider:
                errors.append("checklist_d5_unsupported:deciders_missing")
            elif decider == appeal_decider:
                errors.append("checklist_d5_unsupported:same_decider_for_appeal")
            if not appeal.get("route") or not appeal.get("deadline"):
                errors.append("checklist_d5_unsupported:route_or_deadline_missing")
    # D6: the plain-language disclosure must be present and complete.
    if _status("D6") == "satisfied":
        limitations = case.get("limitations")
        plain = limitations.get("plain_language") if isinstance(limitations, Mapping) else None
        if not isinstance(plain, Mapping) or not all(
            isinstance(plain.get(key), str) and plain[key].strip()
            for key in ("score_not_probability", "authorship_warning", "human_fpr")
        ):
            errors.append("checklist_d6_unsupported:limitations_disclosure_incomplete")
    # D7: the subject must have been given the opportunity to respond;
    # either the response is attached or its absence is recorded.
    if _status("D7") == "satisfied":
        response = process.get("subject_response")
        if not isinstance(response, Mapping):
            errors.append("checklist_d7_unsupported:subject_response_missing")
        elif not response.get("opportunity_given"):
            errors.append("checklist_d7_unsupported:opportunity_not_given")
        elif not response.get("response_attached") and not response.get("note"):
            errors.append("checklist_d7_unsupported:absence_not_recorded")
    # D8: counterfactuals must be recorded.
    if _status("D8") == "satisfied":
        limitations = case.get("limitations")
        counterfactuals = (
            limitations.get("counterfactuals") if isinstance(limitations, Mapping) else None
        )
        if not isinstance(counterfactuals, list) or not counterfactuals:
            errors.append("checklist_d8_unsupported:no_counterfactuals")
    # D9: retention, access and disposal terms must all be recorded.
    if _status("D9") == "satisfied":
        retention = process.get("retention")
        if not isinstance(retention, Mapping) or not all(
            isinstance(retention.get(key), str) and retention[key].strip()
            for key in ("period", "legal_basis", "access", "disposal", "expungement")
        ):
            errors.append("checklist_d9_unsupported:retention_terms_incomplete")
    # D10: policy and procedure versions must be recorded.
    if _status("D10") == "satisfied" and (
        not process.get("policy_version") or not process.get("procedure_version")
    ):
        errors.append("checklist_d10_unsupported:policy_or_procedure_version_missing")
    return errors


def _verify_v3_sections(case: Mapping[str, Any], bundle: Mapping[str, Any]) -> list[str]:
    """Verify the v3-only sections against the sealed bundle."""
    errors: list[str] = []
    input_section = case.get("input")
    if not isinstance(input_section, Mapping):
        errors.append("v3_input_missing")
    elif input_section.get("content_sha256") != bundle.get("content_sha256"):
        errors.append("v3_input_content_sha256_mismatch")
    observations = case.get("detector_observations")
    if not isinstance(observations, list):
        errors.append("v3_detector_observations_missing")
    else:
        expected = build_detector_observations(
            bundle,
            dispositions=(case.get("process") or {}).get("evidence_dispositions")
            if isinstance(case.get("process"), Mapping)
            else None,
        )
        if observations != expected:
            errors.append("v3_detector_observations_mismatch")
    refs = case.get("validation_refs")
    if not isinstance(refs, list):
        errors.append("v3_validation_refs_missing")
    else:
        for ref in refs:
            if not isinstance(ref, Mapping):
                errors.append("v3_validation_ref_invalid")
                continue
            registry_id = ref.get("registry_id")
            if (
                not isinstance(registry_id, str)
                or len(registry_id) != 64
                or any(c not in "0123456789abcdef" for c in registry_id)
            ):
                errors.append("v3_validation_ref_registry_id_invalid")
            if ref.get("registry_sha256") != registry_id:
                errors.append("v3_validation_ref_registry_sha256_mismatch")
    limitations = case.get("limitations")
    if not isinstance(limitations, Mapping):
        errors.append("v3_limitations_missing")
    else:
        plain = limitations.get("plain_language")
        if not isinstance(plain, Mapping) or not all(
            isinstance(plain.get(key), str) and plain[key].strip()
            for key in ("score_not_probability", "authorship_warning", "human_fpr")
        ):
            errors.append("v3_limitations_incomplete")
        if not isinstance(limitations.get("counterfactuals"), list):
            errors.append("v3_limitations_counterfactuals_missing")
    errors.extend(_checklist_consistency(case, bundle))
    custody = case.get("custody")
    errors.extend(f"custody_{detail}" for detail in verify_custody(custody))
    seal = case.get("seal")
    if not isinstance(seal, Mapping):
        errors.append("v3_seal_missing")
    else:
        if seal.get("algorithm") != "sha256":
            errors.append("v3_seal_algorithm_invalid")
        if (
            isinstance(custody, list)
            and custody
            and seal.get("custody_head") != custody[-1].get("entry_hash")
        ):
            errors.append("v3_seal_custody_head_mismatch")
        signature = seal.get("signature")
        if signature is not None:
            if not isinstance(signature, Mapping):
                errors.append("v3_seal_signature_invalid")
            else:
                if signature.get("algorithm") != "ed25519":
                    errors.append("v3_seal_signature_algorithm_invalid")
                fingerprint = signature.get("key_fingerprint")
                if (
                    not isinstance(fingerprint, str)
                    or len(fingerprint) != 64
                    or any(c not in "0123456789abcdef" for c in fingerprint)
                ):
                    errors.append("v3_seal_signature_fingerprint_invalid")
                if not isinstance(signature.get("dsse"), Mapping):
                    errors.append("v3_seal_signature_dsse_missing")
                if not isinstance(signature.get("signer"), Mapping):
                    errors.append("v3_seal_signature_signer_missing")
        timestamp = seal.get("timestamp")
        if timestamp is not None and not isinstance(timestamp, Mapping):
            errors.append("v3_seal_timestamp_invalid")
        digest_publication = seal.get("digest_publication")
        if digest_publication is not None and not isinstance(digest_publication, Mapping):
            errors.append("v3_seal_digest_publication_invalid")
    gaps = case.get("gaps")
    if not isinstance(gaps, list):
        errors.append("v3_gaps_missing")
    else:
        for gap in gaps:
            if (
                not isinstance(gap, Mapping)
                or not isinstance(gap.get("field"), str)
                or not gap["field"]
                or not isinstance(gap.get("reason"), str)
                or not gap["reason"]
            ):
                errors.append("v3_gaps_invalid")
                break
    return errors


def seal_case_file(
    forensic_bundle: Mapping[str, Any],
    deterministic: bool = False,
    fixed_timestamp: str | None = None,
    *,
    version: str = "v3",
    process: Mapping[str, Any] | None = None,
    custody: Iterable[Mapping[str, Any]] | None = None,
    validation_registry: Any | None = None,
    input_meta: Mapping[str, Any] | None = None,
    signing_seed: bytes | None = None,
    signer: Mapping[str, Any] | None = None,
    digest_publication: Mapping[str, Any] | None = None,
    limitations: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Seal a forensic bundle into a case file.

    ``version`` selects the case-file schema: ``"v3"`` (default, the U2
    legal-process format), ``"v2"`` (the previous shape) or ``"v1"``
    (legacy bundles only).  A v3 seal requires a v2 bundle; a legacy v1
    bundle always seals as v1.  ``process`` supplies the D1–D10
    checklist (defaults to all ``unknown``); ``custody`` supplies extra
    custody events to chain after the genesis entry; ``validation_registry``
    supplies the U1 registry for ``validation_refs``; ``input_meta``
    supplies acquisition metadata (``source``, ``acquired_by``,
    ``acquisition_method``, ``authorisation_ref``, ``acquired_at_utc``).
    ``signing_seed`` + ``signer`` attach the T2 Ed25519/DSSE signature
    over the case body; ``digest_publication`` records where the sealed
    bundle digest was published out-of-band.
    """
    if version not in {"v1", "v2", "v3"}:
        raise ValueError(f"Unsupported case-file version: {version!r}.")
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
        if version != "v1":
            raise ValueError("A legacy forensic-bundle/v1 can only seal as case-file/v1.")
        case = {
            "schema": LEGACY_CASE_SCHEMA,
            "tool": {"name": "TextForensics", "version": get_version()},
            "forensic_bundle": bundle,
            "raw_text_included": False,
            "case_sha256": None,
        }
        case["case_sha256"] = _hash_without_seal(case)
        return case
    if version == "v1":
        raise ValueError("case-file/v1 requires a legacy forensic-bundle/v1.")

    if version == "v2":
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

    # --- v3 ---
    if not isinstance(input_meta, Mapping) and input_meta is not None:
        raise ValueError("input_meta must be a mapping.")
    meta = dict(input_meta or {})
    process_section = build_checklist(
        (process or {}).get("items") if isinstance(process, Mapping) else None,
        policy_version=(process or {}).get("policy_version")
        if isinstance(process, Mapping)
        else None,
        procedure_version=(process or {}).get("procedure_version")
        if isinstance(process, Mapping)
        else None,
        reviewer=(process or {}).get("reviewer") if isinstance(process, Mapping) else None,
        appeal=(process or {}).get("appeal") if isinstance(process, Mapping) else None,
        retention=(process or {}).get("retention") if isinstance(process, Mapping) else None,
        contrary_evidence=(process or {}).get("contrary_evidence")
        if isinstance(process, Mapping)
        else None,
        evidence_dispositions=(process or {}).get("evidence_dispositions")
        if isinstance(process, Mapping)
        else None,
        alternative_explanations=(process or {}).get("alternative_explanations")
        if isinstance(process, Mapping)
        else None,
        subject_response=(process or {}).get("subject_response")
        if isinstance(process, Mapping)
        else None,
    )
    input_section, input_gaps = build_case_input(
        bundle,
        source=meta.get("source"),
        acquired_by=meta.get("acquired_by"),
        acquisition_method=meta.get("acquisition_method"),
        authorisation_ref=meta.get("authorisation_ref"),
        acquired_at_utc=meta.get("acquired_at_utc"),
        normalisation=meta.get("normalisation"),
    )
    observations = build_detector_observations(
        bundle, dispositions=process_section["evidence_dispositions"]
    )
    validation_refs, refs_gaps = build_validation_refs(bundle, validation_registry, now=timestamp)
    if limitations is not None:
        if not isinstance(limitations, Mapping):
            raise ValueError("limitations must be a mapping.")
        limitations_section = {
            "plain_language": dict(limitations.get("plain_language") or {}),
            "counterfactuals": list(limitations.get("counterfactuals") or []),
            "bundle_limitations": list(limitations.get("bundle_limitations") or []),
        }
    else:
        limitations_section = build_limitations(bundle, validation_refs)
    custody_chain: list[dict[str, Any]] = []
    genesis = chain_custody_entry(custody_chain, actor="sealer", action="sealed", at_utc=timestamp)
    custody_chain.append(genesis)
    for entry in custody or []:
        if not isinstance(entry, Mapping):
            raise ValueError("Custody entries must be mappings.")
        if "prev_hash" in entry or "entry_hash" in entry:
            raise ValueError(
                "Supplied custody entries must not carry hashes; the sealer chains them."
            )
        custody_chain.append(
            chain_custody_entry(
                custody_chain,
                actor=str(entry.get("actor")),
                action=str(entry.get("action")),
                at_utc=str(entry.get("at_utc") or timestamp),
                note=entry.get("note"),
            )
        )
    gaps = input_gaps + refs_gaps
    if signing_seed is None and signer is not None:
        raise ValueError("A signer without a signing_seed cannot sign the case file.")
    if signing_seed is not None and signer is None:
        raise ValueError("A signing_seed without signer identity/role cannot sign.")
    publication = None
    if digest_publication is not None:
        if not isinstance(digest_publication, Mapping):
            raise ValueError("digest_publication must be a mapping.")
        publication = {
            "channel": digest_publication.get("channel"),
            "reference": digest_publication.get("reference"),
            "published_at_utc": digest_publication.get("published_at_utc"),
        }
        if not all(
            isinstance(publication[key], str) and publication[key]
            for key in ("channel", "reference", "published_at_utc")
        ):
            raise ValueError("digest_publication needs channel, reference and published_at_utc.")
    case = {
        "schema": CASE_SCHEMA_V3,
        "tool": tool,
        "created_at_utc": timestamp,
        "raw_text_included": False,
        "forensic_bundle": bundle,
        "manifest": _manifest_for(bundle, tool),
        "input": input_section,
        "detector_observations": observations,
        "validation_refs": validation_refs,
        "limitations": limitations_section,
        "process": process_section,
        "custody": custody_chain,
        "seal": {
            "algorithm": "sha256",
            "custody_head": custody_chain[-1]["entry_hash"],
            "signature": None,
            "timestamp": None,
            "digest_publication": publication,
        },
        "gaps": gaps,
        "case_sha256": None,
    }
    if signing_seed is not None:
        from .sealing import fingerprint, public_key_from_seed, sign_case_body

        if not isinstance(signing_seed, (bytes, bytearray)) or len(signing_seed) != 32:
            raise ValueError("signing_seed must be 32 bytes.")
        if not isinstance(signer, Mapping) or not signer.get("identity") or not signer.get("role"):
            raise ValueError("signer needs identity and role.")
        envelope = sign_case_body(case, bytes(signing_seed))
        case["seal"]["signature"] = {
            "algorithm": "ed25519",
            "key_fingerprint": fingerprint(public_key_from_seed(bytes(signing_seed))),
            "signer": {"identity": signer["identity"], "role": signer["role"]},
            "dsse": envelope,
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


def verify_case_file(
    payload: Mapping[str, Any], *, public_key: bytes | None = None
) -> dict[str, Any]:
    """Verify a case file (v1, v2 or v3).

    ``public_key`` supplies the Ed25519 public key for cryptographic
    verification of a v3 T2 signature.  Without it, a present signature
    is reported as a warning (present but not cryptographically
    verified), never as a pass: a signature nobody checks authenticates
    nothing.
    """
    errors: list[str] = []
    warnings: list[str] = []
    schema = payload.get("schema")
    if schema not in CASE_SCHEMAS:
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
        if schema in {CASE_SCHEMA, CASE_SCHEMA_V3}:
            errors.extend(_verify_manifest(payload, bundle))
        if schema == CASE_SCHEMA_V3:
            errors.extend(_verify_v3_sections(payload, bundle))
            seal = payload.get("seal")
            signature = seal.get("signature") if isinstance(seal, Mapping) else None
            if signature is None:
                warnings.append(
                    "signature_absent_t1_hash_seal_only: integrity since sealing "
                    "only — origin not authenticated."
                )
            elif public_key is None:
                warnings.append(
                    "signature_present_public_key_not_supplied: the T2 signature "
                    "was not cryptographically verified."
                )
            else:
                from .sealing import verify_case_signature

                result = verify_case_signature(payload, public_key)
                if not result["valid"]:
                    errors.extend(f"signature_invalid:{detail}" for detail in result["errors"])
        if payload.get("tool", {}).get("name") != "TextForensics":
            errors.append("invalid_tool_identity")

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "schema": schema,
        "case_sha256": supplied_hash,
        "note": (
            "Integrity verification checks this artifact's structure, seal and "
            "manifest; it does not prove an authorship conclusion."
        ),
    }


def append_custody_entry(
    case: Mapping[str, Any],
    *,
    actor: str,
    action: str,
    at_utc: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Append a custody event to a sealed v3 case file and re-seal it.

    Returns a new case dict; the input is not mutated.  Appending
    changes ``case_sha256`` (the seal covers the whole case), so the
    custody hash chain — not the case hash — is the continuity record
    across versions: each version's seal covers that version, and the
    chain links the versions.  Only v3 case files carry custody.
    """
    if case.get("schema") != CASE_SCHEMA_V3:
        raise ValueError("Custody entries exist only on case-file/v3.")
    updated = deepcopy(dict(case))
    custody = list(updated.get("custody") or [])
    entry = chain_custody_entry(
        custody,
        actor=actor,
        action=action,
        at_utc=at_utc or datetime.now(UTC).isoformat(),
        note=note,
    )
    custody.append(entry)
    updated["custody"] = custody
    updated["seal"] = dict(updated.get("seal") or {})
    updated["seal"]["custody_head"] = entry["entry_hash"]
    updated["case_sha256"] = _hash_without_seal(updated)
    return updated


def write_case_file(
    path: str | Path,
    forensic_bundle: Mapping[str, Any],
    deterministic: bool = False,
    fixed_timestamp: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    case = seal_case_file(
        forensic_bundle,
        deterministic=deterministic,
        fixed_timestamp=fixed_timestamp,
        **kwargs,
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


def verify_case_file_path(path: str | Path, *, public_key: bytes | None = None) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {
            "valid": False,
            "errors": ["case_file_must_be_json_object"],
            "warnings": [],
            "schema": None,
            "case_sha256": None,
            "note": "The case file must be a JSON object.",
        }
    return verify_case_file(payload, public_key=public_key)


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


def _replay_trust_map_v3(
    sealed_bundle: Mapping[str, Any],
    sealed_trust: Mapping[str, Any],
    validation_registry: Any,
    conditions: Any,
    predictions: list[DetectorPrediction],
    robustness_rows: list[Any],
    failure_count: int,
) -> tuple[list[str], list[str], dict[str, Any]]:
    """Re-derive a Trust Map v3 from a U1 validation registry.

    The sealed map was derived for exactly one detector: the detector
    is identified from the record ids cited in the dimensions'
    ``evidence_refs``.  An ambiguous or unidentifiable derivation
    detector is reported as not re-derived, never guessed.
    """
    from .validation import derive_trust_map

    errors: list[str] = []
    warnings: list[str] = []
    checks: dict[str, Any] = {}
    record_ids: set[str] = set()
    for item in sealed_trust.get("dimensions", []):
        if isinstance(item, Mapping):
            for ref in item.get("evidence_refs", []) or []:
                if isinstance(ref, str):
                    record_ids.add(ref)
    detector_ids: set[str] = set()
    detector_versions: set[str] = set()
    for record_id in record_ids:
        record = validation_registry.record(record_id)
        if record is None:
            continue
        detector_ids.add(record.detector_id)
        detector_versions.add(record.detector_version)
    if len(detector_ids) != 1 or len(detector_versions) != 1:
        warnings.append(
            "validation_registry_not_supplied:trust_map_not_rederived"
            if not record_ids
            else "trust_map_v3_derivation_detector_ambiguous"
        )
        checks["trust_map"] = {
            "status": "not_rederived",
            "reason": "derivation_detector_ambiguous",
        }
        return errors, warnings, checks
    detector_id = next(iter(detector_ids))
    detector_version = next(iter(detector_versions))
    rederived = derive_trust_map(
        conditions,
        validation_registry,
        detector_id=detector_id,
        detector_version=detector_version,
        now=str(sealed_trust.get("generated_at_utc", "")),
        predictions=predictions,
        robustness=robustness_rows,
        failure_count=failure_count,
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


def _replay_trust_map(
    sealed_bundle: Mapping[str, Any],
    registry: EvidenceRegistry | None,
    *,
    validation_registry: Any | None = None,
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

    if sealed_trust.get("schema") == TRUST_SCHEMA_V3:
        # A v3 map is derived from U1 validation records, never from the
        # v1 EvidenceRegistry: it needs a ValidationRegistry to re-derive.
        if validation_registry is None:
            warnings.append("validation_registry_not_supplied:trust_map_not_rederived")
            checks["trust_map"] = {
                "status": "not_rederived",
                "reason": "validation_registry_not_supplied",
            }
            return errors, warnings, checks
        try:
            conditions = conditions_from_dict(conditions_payload)
        except (KeyError, TypeError, ValueError) as exc:
            errors.append("invalid_input_conditions")
            checks["trust_map"] = {"status": "not_rederived", "reason": str(exc)}
            return errors, warnings, checks
        results = sealed_bundle.get("detector_results", [])
        try:
            predictions = [
                _prediction_from_dict(item) for item in results if isinstance(item, Mapping)
            ]
        except (TypeError, ValueError) as exc:
            errors.append("invalid_detector_results_for_replay")
            checks["trust_map"] = {"status": "not_rederived", "reason": str(exc)}
            return errors, warnings, checks
        robustness = sealed_bundle.get("robustness", {})
        robustness_rows = robustness.get("detectors", []) if isinstance(robustness, Mapping) else []
        failures = sealed_bundle.get("detector_failures", [])
        return _replay_trust_map_v3(
            sealed_bundle,
            sealed_trust,
            validation_registry,
            conditions,
            predictions,
            robustness_rows,
            len(failures) if isinstance(failures, list) else 0,
        )

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
    validation_registry: Any | None = None,
    atol: float = 1e-9,
) -> dict[str, Any]:
    """Replay a sealed case file.

    ``text`` is optional.  Without it, replay verifies structural integrity but
    cannot re-run detection.  ``registry`` is required to re-derive an
    evidence-conditioned Trust Map; without it, that check is reported as not
    performed rather than silently passing.  ``validation_registry`` is the
    U1 registry used to re-derive a Trust Map v3; a v3 map without it is
    reported as not re-derived.
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

    trust_errors, trust_warnings, trust_checks = _replay_trust_map(
        bundle, registry, validation_registry=validation_registry
    )
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
    validation_registry: Any | None = None,
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
        validation_registry=validation_registry,
        atol=atol,
    )
