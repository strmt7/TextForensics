from __future__ import annotations

import unittest

from textforensics.schema import load_schema
from textforensics.version import get_version


class SchemaLoaderTests(unittest.TestCase):
    def test_all_packaged_schemas_load(self):
        for name in ("detector-result", "forensic-bundle", "case-file"):
            schema = load_schema(name)
            self.assertIsInstance(schema, dict)
            self.assertTrue(schema.get("title"))

    def test_unknown_schema_raises_with_available_list(self):
        with self.assertRaises(ValueError) as ctx:
            load_schema("does-not-exist")
        self.assertIn("Available:", str(ctx.exception))


class VersionTests(unittest.TestCase):
    def test_version_is_a_string(self):
        self.assertIsInstance(get_version(), str)
        self.assertTrue(len(get_version()) > 0)


if __name__ == "__main__":
    unittest.main()
