"""One explicit, complete, version-aware schema registry (W2, CORE-10/C23).

Every JSON schema shipped under ``src/textforensics/schemas/`` is listed
here by name, and the generic :func:`validate` dispatches to the same
published contract as the per-schema helpers — discovery, loading and
validation can no longer disagree about which schemas exist.

Versioning contract
-------------------
Each schema file is the authority for the versions it supports: the
supported versions of a name are read from that file's top-level
``schema`` property (``enum`` or ``const``).  A payload whose ``schema``
value is not in that set is refused deliberately by :func:`validate`
(and by :func:`load_schema` when a version is requested explicitly),
never silently validated against a different version.  Schemas without
a top-level version (``enterprise-policy``) are unversioned.

Trust Map dimensions (C10/C23)
-------------------------------
:const:`DECLARED_TRUST_MAP_DIMENSIONS` is the single declared v3 Trust
Map dimension set.  It is an alias of ``trust.TRUST_DIMENSIONS``, not a
second list: every eligibility, completeness and bundle check imports
it from here.

Bundle / Trust Map version compatibility (C23)
----------------------------------------------
A forensic bundle accepts the Trust Map version it was designed for
and the next one — bundle and map versions are deliberately decoupled,
because the map version tracks the derivation engine (v1 legacy
capability view, v2 evidence-conditioned, v3 U1-derived with ``stale``)
while the bundle version tracks the container contract:

* ``forensic-bundle/v1`` accepts ``trust-map/v1`` or ``trust-map/v2``;
* ``forensic-bundle/v2`` accepts ``trust-map/v2`` or ``trust-map/v3``.

A v3 map is never accepted inside a v1 bundle, and a v1 map is never
accepted inside a v2 bundle.  See :const:`ACCEPTED_BUNDLE_TRUST_MAP_PAIRS`,
:func:`validate_bundle_trust_map_pair`, and ``docs/REVAMP_SPEC.md`` §13.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import lru_cache
from importlib.resources import files
from typing import Any

try:
    import jsonschema
except ImportError:
    jsonschema = None  # type: ignore[assignment]

from .trust import TRUST_DIMENSIONS, TRUST_STATES, TRUST_STATES_V3

# The single declared Trust Map dimension set (C10/C23).  Aliased from
# trust.TRUST_DIMENSIONS — do not define a second list anywhere.
DECLARED_TRUST_MAP_DIMENSIONS: frozenset[str] = frozenset(TRUST_DIMENSIONS)
DECLARED_TRUST_MAP_STATES_V2: frozenset[str] = frozenset(TRUST_STATES)
DECLARED_TRUST_MAP_STATES_V3: frozenset[str] = frozenset(TRUST_STATES_V3)

_SCHEMA_NAMES = {
    "case-file": "case-file.schema.json",
    "detector-result": "detector-result.schema.json",
    "enterprise-policy": "enterprise-policy.schema.json",
    "evidence-manifest": "evidence-manifest.schema.json",
    "evidence-record": "evidence-record.schema.json",
    "evidence-registry": "evidence-registry.schema.json",
    "forensic-bundle": "forensic-bundle.schema.json",
    "mixed-origin-report": "mixed-origin-report.schema.json",
    "probe-run": "probe-run.schema.json",
    "run-artifact": "run-artifact.schema.json",
    "sealed-bundle-manifest": "sealed-bundle-manifest.schema.json",
    "trust-map": "trust-map.schema.json",
    "validation-registry": "validation-registry.schema.json",
}

# C23 compatibility decision (see module docstring): which
# (forensic-bundle version, trust-map version) pairs are accepted.
# The bundle version tracks the container contract; the map version
# tracks the derivation engine.  A pair outside this table is rejected
# by the bundle schema, the sealer, and both verifiers alike.
ACCEPTED_BUNDLE_TRUST_MAP_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v1"),
        ("textforensics.forensic-bundle/v1", "textforensics.trust-map/v2"),
        ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v2"),
        ("textforensics.forensic-bundle/v2", "textforensics.trust-map/v3"),
    }
)


@lru_cache(maxsize=16)
def load_schema(name: str, *, version: str | None = None) -> dict[str, Any]:
    """Load a JSON schema by name from packaged schemas.

    Args:
        name: Schema name (e.g., "forensic-bundle", "detector-result", "case-file", "trust-map")
        version: Optional version string (e.g., ``"textforensics.trust-map/v3"``).
            When given, the version must be one of :func:`supported_versions`
            for that name; an unknown version is refused deliberately.

    Returns:
        The parsed JSON schema as a dictionary.

    Raises:
        ValueError: If the schema name or the requested version is unknown.
    """
    try:
        filename = _SCHEMA_NAMES[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown schema {name!r}. Available: {', '.join(sorted(_SCHEMA_NAMES))}"
        ) from exc
    if version is not None:
        supported = supported_versions(name)
        if version not in supported:
            raise ValueError(
                f"Unsupported schema version {version!r} for {name!r}. "
                f"Supported versions: {', '.join(sorted(supported)) or 'none (unversioned schema)'}"
            )
    resource = files("textforensics").joinpath("schemas", filename)
    return json.loads(resource.read_text(encoding="utf-8"))


def supported_versions(name: str) -> frozenset[str]:
    """Return the versions a named schema supports.

    The versions are read from the schema file itself — its top-level
    ``schema`` property (``enum`` or ``const``) is the authority.  A
    schema without a top-level version (``enterprise-policy``) returns
    an empty frozenset: it is unversioned, not versioned-unknown.

    Raises:
        ValueError: If the schema name is unknown.
    """
    schema = load_schema(name)
    version_property = schema.get("properties", {}).get("schema", {})
    if "enum" in version_property:
        return frozenset(version_property["enum"])
    if "const" in version_property:
        return frozenset({version_property["const"]})
    return frozenset()


def _get_validator(schema: dict[str, Any]):
    """Create a jsonschema validator for the given schema."""
    if jsonschema is None:
        raise RuntimeError(
            "jsonschema is required for validation. "
            "Install with 'pip install jsonschema' or use the 'dev' extra."
        )
    return jsonschema.Draft202012Validator(schema)


def _version_error(payload: Any, name: str) -> list[str]:
    """Refuse a payload whose ``schema`` value is an unsupported version.

    Returns a one-element error list when the payload is a mapping with
    a string ``schema`` value outside :func:`supported_versions`, and an
    empty list otherwise (missing/non-string versions are left to the
    JSON Schema validation itself).
    """
    if not isinstance(payload, dict):
        return []
    value = payload.get("schema")
    if not isinstance(value, str):
        return []
    supported = supported_versions(name)
    if supported and value not in supported:
        return [
            f"unsupported schema version {value!r} for {name!r}; "
            f"supported versions: {', '.join(sorted(supported))}"
        ]
    return []


def _validate_named(payload: dict[str, Any], name: str) -> list[str]:
    """Validate a payload against a named schema (generic dispatch path).

    An unsupported payload version is refused deliberately before the
    JSON Schema run; anything else is reported by the schema itself.
    """
    errors = _version_error(payload, name)
    schema = load_schema(name)
    validator = _get_validator(schema)
    schema_errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
    errors.extend(f"{'.'.join(str(p) for p in err.path)}: {err.message}" for err in schema_errors)
    return errors


def validate_forensic_bundle(bundle: dict[str, Any]) -> list[str]:
    """Validate a forensic bundle against its schema.

    Args:
        bundle: The forensic bundle dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    return _validate_named(bundle, "forensic-bundle")


def validate_detector_result(result: dict[str, Any]) -> list[str]:
    """Validate a detector result against its schema.

    Args:
        result: The detector result dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    return _validate_named(result, "detector-result")


def validate_case_file(case: dict[str, Any]) -> list[str]:
    """Validate a case file against its schema.

    Args:
        case: The case file dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    return _validate_named(case, "case-file")


def validate_trust_map(trust_map: dict[str, Any]) -> list[str]:
    """Validate a trust map against its schema.

    Args:
        trust_map: The trust map dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    return _validate_named(trust_map, "trust-map")


def validate_evidence_record(record: dict[str, Any]) -> list[str]:
    """Validate a U1 validation-evidence record against its schema.

    Args:
        record: The evidence record dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    return _validate_named(record, "evidence-record")


def validate_enterprise_policy(policy: dict[str, Any]) -> list[str]:
    """Validate an enterprise policy against its schema.

    Args:
        policy: The enterprise policy dictionary to validate.

    Returns:
        List of validation error messages (empty if valid).
    """
    return _validate_named(policy, "enterprise-policy")


def validate_evidence_registry(registry: dict[str, Any]) -> list[str]:
    """Validate a U7 evidence registry against its schema."""
    return _validate_named(registry, "evidence-registry")


def validate_validation_registry(registry: dict[str, Any]) -> list[str]:
    """Validate a U1 validation registry against its schema."""
    return _validate_named(registry, "validation-registry")


def validate_run_artifact(artifact: dict[str, Any]) -> list[str]:
    """Validate a U7 run artifact against its schema."""
    return _validate_named(artifact, "run-artifact")


def validate_sealed_bundle_manifest(manifest: dict[str, Any]) -> list[str]:
    """Validate a sealed-bundle manifest against its schema."""
    return _validate_named(manifest, "sealed-bundle-manifest")


def validate_evidence_manifest(manifest: dict[str, Any]) -> list[str]:
    """Validate a candidate evidence manifest against its schema."""
    return _validate_named(manifest, "evidence-manifest")


def validate_probe_run(run: dict[str, Any]) -> list[str]:
    """Validate a U3 probe run against its schema."""
    return _validate_named(run, "probe-run")


def validate_mixed_origin_report(report: dict[str, Any]) -> list[str]:
    """Validate a mixed-origin report against its schema."""
    return _validate_named(report, "mixed-origin-report")


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

    This is the single generic dispatch surface: every listed name
    dispatches to the same published contract as its per-schema
    helper, and a payload carrying an unsupported schema version is
    refused deliberately instead of being validated against another
    version's contract.

    Args:
        bundle: The dictionary to validate.
        schema_name: Name of the schema to validate against.

    Returns:
        List of validation error messages (empty if valid).

    Raises:
        ValueError: If the schema name is unknown.
    """
    if schema_name not in _SCHEMA_NAMES:
        raise ValueError(
            f"Unknown schema {schema_name!r}. Available: {', '.join(sorted(_SCHEMA_NAMES))}"
        )
    return _validate_named(bundle, schema_name)


# ---------------------------------------------------------------------------
# Trust Map completeness (C10) and bundle/map pairing (C23)
# ---------------------------------------------------------------------------

_TRUST_MAP_SCHEMAS = {
    "textforensics.trust-map/v1": "v1",
    "textforensics.trust-map/v2": "v2",
    "textforensics.trust-map/v3": "v3",
}


def _trust_map_version(trust_map: Mapping[str, Any]) -> str | None:
    return _TRUST_MAP_SCHEMAS.get(trust_map.get("schema"))


def validate_trust_map_dimensions(trust_map: Mapping[str, Any]) -> list[str]:
    """Check a Trust Map's dimension set (C10, dimension part only).

    A v2/v3 map must carry exactly :const:`DECLARED_TRUST_MAP_DIMENSIONS`:
    unique names, no unknown names, no missing names, and every state
    in the version's vocabulary.  A v1 map is a legacy capability view
    with no declared set, so it is exempt here; an unknown map version
    is left to the schema/version checks.  Metadata and coverage are
    checked by :func:`validate_trust_map_completeness`, not here — the
    casefile replay path re-derives states from a registry and must
    not fail a map over metadata it does not consume.

    Returns:
        List of error strings (empty when the dimension set is complete).
    """
    errors: list[str] = []
    if not isinstance(trust_map, Mapping):
        return ["trust_map must be an object"]
    version = _trust_map_version(trust_map)
    if version not in ("v2", "v3"):
        return []
    allowed_states = (
        DECLARED_TRUST_MAP_STATES_V3 if version == "v3" else DECLARED_TRUST_MAP_STATES_V2
    )
    dims = trust_map.get("dimensions")
    if not isinstance(dims, list):
        return ["trust_map dimensions is not a list"]
    names: list[str] = []
    for dim in dims:
        if not isinstance(dim, Mapping):
            errors.append("trust_map dimension is not an object")
            continue
        name = dim.get("dimension")
        if not isinstance(name, str) or not name:
            errors.append("trust_map dimension has a missing or empty dimension name")
            continue
        names.append(name)
        state = dim.get("state")
        if state not in allowed_states:
            errors.append(
                f"trust_map dimension {name!r} has invalid state {state!r} for trust-map/{version}"
            )
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        errors.append(f"trust_map dimensions are duplicated: {', '.join(duplicates)}")
    unknown = sorted(set(names) - DECLARED_TRUST_MAP_DIMENSIONS)
    if unknown:
        errors.append(f"trust_map dimensions are not declared: {', '.join(unknown)}")
    missing = sorted(DECLARED_TRUST_MAP_DIMENSIONS - set(names))
    if missing:
        errors.append(f"trust_map dimensions are missing declared dimensions: {', '.join(missing)}")
    return errors


def validate_trust_map_completeness(trust_map: Mapping[str, Any]) -> list[str]:
    """Check a Trust Map v2/v3 for full completeness (C10).

    This is :func:`validate_trust_map_dimensions` plus the per-dimension
    and metadata consistency a v2/v3 map must carry: every dimension has
    a non-empty reason, the v2/v3 required metadata (``input_conditions``,
    ``evidence_registry``, ``coverage``, ``generated_at_utc``) is present
    and well-typed, and the coverage counts match the dimension states
    exactly (including ``stale`` for v3; a v2 map must not carry a
    ``stale`` coverage key).  A v1 legacy map is exempt, as in
    :func:`validate_trust_map_dimensions`.

    ``strong`` may only be derived from a map that passes this check:
    a subset, a duplicated dimension, an arbitrary name, or a coverage
    count that disagrees with the dimensions can never stand in for
    the complete declared set.

    Returns:
        List of error strings (empty when the map is complete).
    """
    errors = validate_trust_map_dimensions(trust_map)
    if not isinstance(trust_map, Mapping):
        return errors
    version = _trust_map_version(trust_map)
    if version not in ("v2", "v3"):
        return errors
    dims = trust_map.get("dimensions")
    if isinstance(dims, list):
        for dim in dims:
            if not isinstance(dim, Mapping):
                continue
            reason = dim.get("reason")
            if not isinstance(reason, str) or not reason:
                errors.append(
                    f"trust_map dimension {dim.get('dimension')!r} has a missing or empty reason"
                )
    if not isinstance(trust_map.get("input_conditions"), Mapping):
        errors.append("trust_map input_conditions is missing or not an object")
    if not isinstance(trust_map.get("evidence_registry"), Mapping):
        errors.append("trust_map evidence_registry is missing or not an object")
    generated_at_utc = trust_map.get("generated_at_utc")
    if not isinstance(generated_at_utc, str) or not generated_at_utc:
        errors.append("trust_map generated_at_utc is missing or empty")
    coverage = trust_map.get("coverage")
    expected_keys = (
        {"supported", "partial", "unknown", "out_of_scope", "stale"}
        if version == "v3"
        else {"supported", "partial", "unknown", "out_of_scope"}
    )
    if not isinstance(coverage, Mapping):
        errors.append("trust_map coverage is missing or not an object")
    else:
        extra = sorted(set(coverage) - expected_keys)
        if extra:
            errors.append(
                f"trust_map coverage has unexpected keys for trust-map/{version}: "
                f"{', '.join(extra)}"
            )
        missing_keys = sorted(expected_keys - set(coverage))
        if missing_keys:
            errors.append(
                f"trust_map coverage is missing keys for trust-map/{version}: "
                f"{', '.join(missing_keys)}"
            )
        if isinstance(dims, list):
            counts: dict[str, int] = {key: 0 for key in expected_keys}
            for dim in dims:
                if isinstance(dim, Mapping) and dim.get("state") in counts:
                    counts[dim["state"]] += 1
            for key in sorted(expected_keys):
                value = coverage.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    errors.append(f"trust_map coverage[{key!r}] is not a non-negative integer")
                elif value != counts[key]:
                    errors.append(
                        f"trust_map coverage[{key!r}] is {value} "
                        f"but {counts[key]} dimensions carry that state"
                    )
    return errors


def validate_bundle_trust_map_pair(bundle_schema: Any, trust_map_schema: Any) -> list[str]:
    """Check a (forensic-bundle version, trust-map version) pair (C23).

    The pair must be in :const:`ACCEPTED_BUNDLE_TRUST_MAP_PAIRS`.
    Unknown versions are refused deliberately, never treated as
    "close enough" to a supported pair.

    Returns:
        List of error strings (empty when the pair is accepted).
    """
    if (bundle_schema, trust_map_schema) in ACCEPTED_BUNDLE_TRUST_MAP_PAIRS:
        return []
    accepted = ", ".join(
        f"{bundle} + {map_schema}" for bundle, map_schema in sorted(ACCEPTED_BUNDLE_TRUST_MAP_PAIRS)
    )
    return [
        "unsupported forensic-bundle/trust-map version pair: "
        f"{bundle_schema!r} with {trust_map_schema!r}; accepted pairs are: {accepted}"
    ]


__all__ = [
    "ACCEPTED_BUNDLE_TRUST_MAP_PAIRS",
    "DECLARED_TRUST_MAP_DIMENSIONS",
    "DECLARED_TRUST_MAP_STATES_V2",
    "DECLARED_TRUST_MAP_STATES_V3",
    "get_schema_by_name",
    "list_schemas",
    "load_schema",
    "supported_versions",
    "validate",
    "validate_bundle_trust_map_pair",
    "validate_case_file",
    "validate_detector_result",
    "validate_evidence_manifest",
    "validate_evidence_record",
    "validate_evidence_registry",
    "validate_enterprise_policy",
    "validate_forensic_bundle",
    "validate_mixed_origin_report",
    "validate_probe_run",
    "validate_run_artifact",
    "validate_sealed_bundle_manifest",
    "validate_trust_map",
    "validate_trust_map_completeness",
    "validate_trust_map_dimensions",
    "validate_validation_registry",
]
