from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

try:
    import jsonschema
except ImportError:
    jsonschema = None  # type: ignore[assignment]

_SCHEMA_NAMES = {
    "detector-result": "detector-result.schema.json",
    "forensic-bundle": "forensic-bundle.schema.json",
    "case-file": "case-file.schema.json",
    "trust-map": "trust-map.schema.json",
}


@lru_cache(maxsize=16)
def load_schema(name: str) -> dict[str, Any]:
    """Load a JSON schema by name from packaged schemas.

    Args:
        name: Schema name (e.g., "forensic-bundle", "detector-result", "case-file", "trust-map")

    Returns:
        The parsed JSON schema as a dictionary.

    Raises:
        ValueError: If the schema name is unknown.
    """
    try:
        filename = _SCHEMA_NAMES[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown schema {name!r}. Available: {', '.join(sorted(_SCHEMA_NAMES))}"
        ) from exc
    resource = files("textforensics").joinpath("schemas", filename)
    return json.loads(resource.read_text(encoding="utf-8"))


def _get_validator(schema: dict[str, Any]):
    """Create a jsonschema validator for the given schema."""
    if jsonschema is None:
        raise RuntimeError(
            "jsonschema is required for validation. "
            "Install with 'pip install jsonschema' or use the 'dev' extra."
        )
    return jsonschema.Draft202012Validator(schema)


def validate_forensic_bundle(bundle: dict[str, Any]) -> list[str]:
    """Validate a forensic bundle against its schema.

    Args:
        bundle: The forensic bundle dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    schema = load_schema("forensic-bundle")
    validator = _get_validator(schema)
    errors = sorted(validator.iter_errors(bundle), key=lambda e: e.path)
    return [f"{'.'.join(str(p) for p in err.path)}: {err.message}" for err in errors]


def validate_detector_result(result: dict[str, Any]) -> list[str]:
    """Validate a detector result against its schema.

    Args:
        result: The detector result dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    schema = load_schema("detector-result")
    validator = _get_validator(schema)
    errors = sorted(validator.iter_errors(result), key=lambda e: e.path)
    return [f"{'.'.join(str(p) for p in err.path)}: {err.message}" for err in errors]


def validate_case_file(case: dict[str, Any]) -> list[str]:
    """Validate a case file against its schema.

    Args:
        case: The case file dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    schema = load_schema("case-file")
    validator = _get_validator(schema)
    errors = sorted(validator.iter_errors(case), key=lambda e: e.path)
    return [f"{'.'.join(str(p) for p in err.path)}: {err.message}" for err in errors]


def validate_trust_map(trust_map: dict[str, Any]) -> list[str]:
    """Validate a trust map against its schema.

    Args:
        trust_map: The trust map dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    schema = load_schema("trust-map")
    validator = _get_validator(schema)
    errors = sorted(validator.iter_errors(trust_map), key=lambda e: e.path)
    return [f"{'.'.join(str(p) for p in err.path)}: {err.message}" for err in errors]


def list_schemas() -> list[str]:
    """List all available schema names.

    Returns:
        Sorted list of available schema names.
    """
    return sorted(_SCHEMA_NAMES.keys())


def get_schema_by_name(name: str) -> dict[str, Any]:
    """Get a schema by name (alias for load_schema).

    Args:
        name: Schema name.

    Returns:
        The parsed JSON schema.
    """
    return load_schema(name)


def validate(bundle: dict[str, Any], schema_name: str) -> list[str]:
    """Validate a payload against a named schema.

    Args:
        bundle: The dictionary to validate.
        schema_name: Name of the schema to validate against.

    Returns:
        List of validation error messages (empty if valid).
    """
    if schema_name == "forensic-bundle":
        return validate_forensic_bundle(bundle)
    elif schema_name == "detector-result":
        return validate_detector_result(bundle)
    elif schema_name == "case-file":
        return validate_case_file(bundle)
    elif schema_name == "trust-map":
        return validate_trust_map(bundle)
    else:
        raise ValueError(
            f"Unknown schema {schema_name!r}. Available: {', '.join(sorted(_SCHEMA_NAMES))}"
        )