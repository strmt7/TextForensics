#!/usr/bin/env python3
"""
Validate JSON schema files against JSON Schema Draft 2020-12 meta-schema.

This script validates that all schema files in the packaged
``src/textforensics/schemas/`` directory are valid JSON Schema
documents. That directory is the single source of truth for schemas;
there is no top-level ``schemas/`` copy.
"""

import json
import sys
from pathlib import Path

import jsonschema
from jsonschema import Draft202012Validator


def validate_schema_file(schema_path: Path) -> tuple[bool, str]:
    """Validate a single schema file against the meta-schema."""
    try:
        with schema_path.open("r", encoding="utf-8") as f:
            schema = json.load(f)

        # Check if it has the required $schema field
        if "$schema" not in schema:
            return False, f"Missing $schema field in {schema_path.name}"

        # Validate against the meta-schema
        Draft202012Validator.check_schema(schema)

        # Also validate the schema can validate itself (basic sanity check)
        # This is just a sanity check - the schema should be valid JSON Schema
        Draft202012Validator(schema)

        return True, f"OK: {schema_path.name}"

    except json.JSONDecodeError as e:
        return False, f"Invalid JSON in {schema_path.name}: {e}"
    except jsonschema.exceptions.SchemaError as e:
        return False, f"Schema validation error in {schema_path.name}: {e}"
    except Exception as e:
        return False, f"Unexpected error validating {schema_path.name}: {e}"


def main() -> int:
    """Main entry point."""
    schemas_dir = Path(__file__).parent.parent / "src" / "textforensics" / "schemas"

    if not schemas_dir.exists():
        print(f"Schemas directory not found: {schemas_dir}")
        return 1

    schema_files = list(schemas_dir.glob("*.json"))

    if not schema_files:
        print("No schema files found")
        return 0

    all_ok = True
    for schema_file in schema_files:
        ok, message = validate_schema_file(schema_file)
        print(message)
        if not ok:
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
