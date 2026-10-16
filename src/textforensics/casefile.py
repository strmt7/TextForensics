from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .version import get_version


CASE_SCHEMA = "textforensics.case-file/v1"


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash_without_seal(payload: Mapping[str, Any]) -> str:
    body = deepcopy(dict(payload))
    body.pop("case_sha256", None)
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def seal_case_file(forensic_bundle: Mapping[str, Any]) -> dict[str, Any]:
    bundle = deepcopy(dict(forensic_bundle))
    case = {
        "schema": CASE_SCHEMA,
        "tool": {
            "name": "TextForensics",
            "version": get_version(),
        },
        "forensic_bundle": bundle,
        "raw_text_included": False,
        "case_sha256": None,
    }
    case["case_sha256"] = _hash_without_seal(case)
    return case


def verify_case_file(payload: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if payload.get("schema") != CASE_SCHEMA:
        errors.append("unsupported_schema")
    if payload.get("raw_text_included") is not False:
        errors.append("raw_text_policy_violation")
    supplied_hash = payload.get("case_sha256")
    if not isinstance(supplied_hash, str) or len(supplied_hash) != 64:
        errors.append("missing_or_invalid_case_sha256")
    elif supplied_hash != _hash_without_seal(payload):
        errors.append("case_hash_mismatch")
    if not isinstance(payload.get("forensic_bundle"), dict):
        errors.append("missing_forensic_bundle")
    return {
        "valid": not errors,
        "errors": errors,
        "schema": payload.get("schema"),
        "case_sha256": supplied_hash,
        "note": (
            "Integrity verification checks this artifact's structure/hash; it "
            "does not prove an authorship conclusion."
        ),
    }


def write_case_file(path: str | Path, forensic_bundle: Mapping[str, Any]) -> dict[str, Any]:
    case = seal_case_file(forensic_bundle)
    target = Path(path)
    target.write_text(
        json.dumps(case, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
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
