from __future__ import annotations

import unittest
from unittest.mock import patch

from textforensics.version import get_version


class VersionFunctionTests(unittest.TestCase):
    """Tests for get_version function edge cases."""

    def test_get_version_returns_string(self):
        """Test that get_version returns a string."""
        version = get_version()
        self.assertIsInstance(version, str)

    def test_get_version_format(self):
        """Test that get_version returns a valid version-like string."""
        version = get_version()
        # Version should not be empty
        self.assertTrue(len(version) > 0)

    @patch('textforensics.version.version')
    def test_get_version_package_not_found_returns_fallback(self, mock_version):
        """Test that get_version returns fallback when package not found (lines 10-11)."""
        from importlib.metadata import PackageNotFoundError
        
        mock_version.side_effect = PackageNotFoundError("textforensics")
        
        result = get_version()
        self.assertEqual(result, "0+unknown")


if __name__ == "__main__":
    unittest.main()