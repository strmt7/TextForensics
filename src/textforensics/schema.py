from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

_SCHEMA_NAMES = {
    "detector-result": "detector-result.schema.json",
    "forensic-bundle": "forensic-bundle.schema.json",
    "case-file": "case-file.schema.json",
}


def load_schema(name: str) -> dict[str, Any]:
    try:
        filename = _SCHEMA_NAMES[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown schema {name!r}. Available: {', '.join(sorted(_SCHEMA_NAMES))}"
        ) from exc
    resource = files("textforensics").joinpath("schemas", filename)
    return json.loads(resource.read_text(encoding="utf-8"))
