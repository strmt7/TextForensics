from __future__ import annotations

import hashlib
import json
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .version import get_version


CASE_SCHEMA = "textforensics.case-file/v1"
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


def _hash_without_seal(payload: Mapping[str, Any]) -> str:
    body = deepcopy(dict(payload))
    body.pop("case_sha256", None)
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


def _validate_portable_bundle(bundle: Mapping[str, Any]) -> None:
    if bundle.get("schema") != "textforensics.forensic-bundle/v1":
        raise ValueError("Case files require a TextForensics forensic-bundle/v1 object.")

    digest = bundle.get("content_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        raise ValueError("Forensic bundle has an invalid content_sha256.")

    input_metadata = bundle.get("input")
    if (
        not isinstance(input_metadata, Mapping)
        or input_metadata.get("raw_text_included") is not False
    ):
        raise ValueError(
            "Forensic bundle must explicitly declare raw_text_included=false."
        )

    forbidden = _forbidden_paths(bundle)
    if forbidden:
        raise ValueError(
            "Portable case files reject fields that may contain raw source text: "
            + ", ".join(forbidden[:5])
        )


def seal_case_file(forensic_bundle: Mapping[str, Any]) -> dict[str, Any]:
    bundle = deepcopy(dict(forensic_bundle))
    _validate_portable_bundle(bundle)
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
    if (
        not isinstance(supplied_hash, str)
        or len(supplied_hash) != 64
        or any(char not in "0123456789abcdef" for char in supplied_hash)
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


def write_case_file(
    path: str | Path,
    forensic_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    case = seal_case_file(forensic_bundle)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rendered = (
        json.dumps(case, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    )

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
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
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
