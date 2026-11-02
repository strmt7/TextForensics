"""Tests for exit code constants."""

import unittest

from textforensics.constants import (
    EXIT_DOWNGRADED,
    EXIT_ERROR,
    EXIT_INCOMPLETE,
    EXIT_OK,
    exit_code_description,
    exit_code_name,
    validate_exit_code,
)


class ExitCodeConstantsTests(unittest.TestCase):
    """Tests for exit code constant definitions."""

    def test_exit_ok_value(self):
        self.assertEqual(EXIT_OK, 0)

    def test_exit_downgraded_value(self):
        self.assertEqual(EXIT_DOWNGRADED, 1)

    def test_exit_incomplete_value(self):
        self.assertEqual(EXIT_INCOMPLETE, 2)

    def test_exit_error_value(self):
        self.assertEqual(EXIT_ERROR, 3)


class ExitCodeHelpersTests(unittest.TestCase):
    """Tests for exit code helper functions."""

    def test_exit_code_name_for_valid_codes(self):
        self.assertEqual(exit_code_name(EXIT_OK), "EXIT_OK")
        self.assertEqual(exit_code_name(EXIT_DOWNGRADED), "EXIT_DOWNGRADED")
        self.assertEqual(exit_code_name(EXIT_INCOMPLETE), "EXIT_INCOMPLETE")
        self.assertEqual(exit_code_name(EXIT_ERROR), "EXIT_ERROR")

    def test_exit_code_name_for_invalid_code(self):
        self.assertEqual(exit_code_name(99), "UNKNOWN_EXIT_99")

    def test_exit_code_description_for_valid_codes(self):
        self.assertEqual(
            exit_code_description(EXIT_OK),
            "analysis complete, Trust Map sufficient",
        )
        self.assertEqual(
            exit_code_description(EXIT_DOWNGRADED),
            "analysis complete, coverage partial/insufficient",
        )
        self.assertEqual(
            exit_code_description(EXIT_INCOMPLETE),
            "abstained detectors, missing calibration",
        )
        self.assertEqual(
            exit_code_description(EXIT_ERROR),
            "configuration/runtime error",
        )

    def test_exit_code_description_for_invalid_code(self):
        self.assertEqual(exit_code_description(99), "unknown exit code")

    def test_validate_exit_code_accepts_valid_codes(self):
        self.assertEqual(validate_exit_code(EXIT_OK), EXIT_OK)
        self.assertEqual(validate_exit_code(EXIT_DOWNGRADED), EXIT_DOWNGRADED)
        self.assertEqual(validate_exit_code(EXIT_INCOMPLETE), EXIT_INCOMPLETE)
        self.assertEqual(validate_exit_code(EXIT_ERROR), EXIT_ERROR)

    def test_validate_exit_code_rejects_invalid_codes(self):
        with self.assertRaises(ValueError):
            validate_exit_code(-1)
        with self.assertRaises(ValueError):
            validate_exit_code(4)
        with self.assertRaises(ValueError):
            validate_exit_code(99)


class ExitCodeSemanticsTests(unittest.TestCase):
    """Tests for exit code semantics and usage patterns."""

    def test_codes_are_integers(self):
        self.assertIsInstance(EXIT_OK, int)
        self.assertIsInstance(EXIT_DOWNGRADED, int)
        self.assertIsInstance(EXIT_INCOMPLETE, int)
        self.assertIsInstance(EXIT_ERROR, int)

    def test_codes_are_distinct(self):
        codes = [EXIT_OK, EXIT_DOWNGRADED, EXIT_INCOMPLETE, EXIT_ERROR]
        self.assertEqual(len(codes), len(set(codes)), "Exit codes must be unique")

    def test_exit_codes_not_consecutive_starting_at_zero(self):
        # This documents that codes are fixed product contract values
        # They should not be renumbered on a whim
        self.assertEqual([EXIT_OK, EXIT_DOWNGRADED, EXIT_INCOMPLETE, EXIT_ERROR], [0, 1, 2, 3])

    def test_exit_ok_means_success(self):
        """EXIT_OK should represent a successful analysis."""
        self.assertEqual(EXIT_OK, 0)  # Conventional success

    def test_error_codes_nonzero(self):
        """Non-zero exit codes indicate failure states."""
        self.assertNotEqual(EXIT_DOWNGRADED, EXIT_OK)
        self.assertNotEqual(EXIT_INCOMPLETE, EXIT_OK)
        self.assertNotEqual(EXIT_ERROR, EXIT_OK)


if __name__ == "__main__":
    unittest.main()