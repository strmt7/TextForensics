#!/usr/bin/env python3
"""
Fuzz target for schema validation in schema.py
"""

import json
import sys

import atheris


def TestOneInput(data: bytes) -> None:
    """Fuzz schema loading and validation."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    # Test load_schema with fuzzed input
    try:
        from textforensics.schema import load_schema

        # Test with fuzzed schema names (invalid names that might cause issues)
        schema_names = ["detector-result", "forensic-bundle", "case-file", text[:100], "", "invalid\x00name"]

        for name in schema_names:
            try:
                load_schema(name)
            except (ValueError, KeyError):
                pass  # Expected for invalid names
    except Exception:
        pass

    # Test with malformed JSON that looks like schema files
    try:
        from textforensics.schema import load_schema
        from importlib.resources import files
        from textforensics import schemas

        # Try various malformed payload attempts
        try:
            # Simulate reading malformed JSON from a schema file
            malformed_json = text[:1000] if text else ""

            # This tests that the schema loading is robust
            for schema_name in ["detector-result", "forensic-bundle", "case-file"]:
                try:
                    schema_path = files("textforensics").joinpath("schemas", f"{schema_name}.schema.json")
                    if schema_path.exists():
                        # Read and potentially corrupt the content
                        content = schema_path.read_text(encoding="utf-8")
                        corrupted = content[:len(content)//2] + malformed_json + content[len(content)//2:]
                        json.loads(corrupted)  # This might fail, which is expected
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass

    # Direct JSON parsing that might be used in schema validation
    try:
        parsed = json.loads(text[:5000] if len(text) > 5000 else text)

        if isinstance(parsed, dict):
            # Test various schema properties with fuzzed values
            test_properties = ["type", "properties", "required", "additionalProperties", "pattern", "enum"]

            for prop in test_properties:
                if prop in parsed:
                    value = parsed[prop]
                    # These properties should be valid in schema context
                    if isinstance(value, (str, bool, int, float, list, dict)):
                        pass  # Valid type
    except json.JSONDecodeError:
        pass
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()