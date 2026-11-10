"""Tests for the W0 evidence-manifest schema (textforensics.evidence-manifest/v1).

The schema is loaded directly from the packaged schemas directory; the
test deliberately does not depend on schema discovery (``schema.py``),
which is itself under repair (audit CORE-10).
"""

import copy
import importlib.util
import json
import unittest
from pathlib import Path

import textforensics

SCHEMA_PATH = (
    Path(textforensics.__file__).resolve().parent
    / "schemas"
    / "evidence-manifest.schema.json"
)

ZERO_SHA256 = "0" * 64


def minimal_manifest() -> dict:
    """Smallest manifest that must validate."""
    return {
        "schema": "textforensics.evidence-manifest/v1",
        "manifest_version": "1",
        "candidate_source_sha": "3ff365031faf48bc0d14212d81d147ac11c7b232",
        "source_tree_digest": {"method": "git-tree", "value": "0" * 40},
        "package_inputs": [
            {
                "name": "textforensics",
                "version": "0.2.0",
                "digest": {"algorithm": "sha256", "value": ZERO_SHA256},
            }
        ],
        "schema_versions": {"case-file": "textforensics.case-file/v1"},
        "test_suites": [{"suite": "core", "run_id": "example-run-1"}],
        "scientific_run_ids": [],
        "artifacts": [
            {
                "path": "dist/textforensics-0.2.0-py3-none-any.whl",
                "sha256": ZERO_SHA256,
                "role": "wheel",
            }
        ],
        "gate_results": {
            "verify_release_output": {
                "path": "verify-release.json",
                "sha256": ZERO_SHA256,
            },
            "gates": {"core-pytest": {"status": "pass"}},
            "required_gates": ["core-pytest"],
        },
        "recorded_at_utc": "2026-11-10T19:17:39Z",
    }


@unittest.skipUnless(
    importlib.util.find_spec("jsonschema"),
    "jsonschema is a development dependency",
)
class EvidenceManifestSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import jsonschema

        cls.jsonschema = jsonschema
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_minimal_valid_manifest_validates(self):
        self.jsonschema.validate(minimal_manifest(), self.schema)

    def test_unknown_gate_status_string_rejected(self):
        manifest = minimal_manifest()
        manifest["gate_results"]["gates"]["core-pytest"]["status"] = "passed"
        with self.assertRaises(self.jsonschema.ValidationError):
            self.jsonschema.validate(manifest, self.schema)

    def test_missing_artifact_digest_rejected(self):
        manifest = minimal_manifest()
        del manifest["artifacts"][0]["sha256"]
        with self.assertRaises(self.jsonschema.ValidationError):
            self.jsonschema.validate(manifest, self.schema)


if __name__ == "__main__":
    unittest.main()
