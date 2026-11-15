"""Kill tests for the W4 mutation-proof survivors in
``textforensics.calibration.CalibrationArtifact.validation_issues``.

Worker F2 (audit W4): the cosmic-ray proof of the W4-changed
``validation_issues`` (CORE-04 content-hash tamper check, worker C)
left 2 survivors, both ``core/ExceptionReplacer`` mutants in the new
``try/except`` blocks:

- ``[925, 15]`` ``except Exception as exc:`` -> ``except
  CosmicRayTestingException as exc:`` — the handler around
  ``check_content_hash()`` never matches, so an exception raised
  while verifying the content hash escapes ``validation_issues()``
  instead of being recorded as an issue.
- ``[960, 15]`` ``except CalibrationError as exc:`` -> ``except
  CosmicRayTestingException as exc:`` — the handler around
  ``_parse_iso8601(self.created_at, ...)`` never matches, so a
  malformed ``created_at`` raises out of ``validation_issues()``
  instead of being recorded as an issue.

No pre-W4 test exercised either exception path (the tamper tests only
cover ``check_content_hash()`` returning ``False``). Each test below
drives the exception path on the unmutated code and asserts the issue
is recorded and no exception escapes; under either mutant the
exception propagates (the replacement name is never defined in the
module, so evaluating the handler raises ``NameError``; even if it
were defined, the original exception would escape uncaught) and the
test fails.
"""

import unittest

from test_audit_w4_worker_c import _eligible_artifact


class TestValidationIssuesExceptionPaths(unittest.TestCase):
    def test_unhashable_content_records_cannot_verify_issue(self):
        """A content hash that cannot even be computed (corrupt
        content) is recorded as an issue, not an escaping exception
        (kills ExceptionReplacer [925, 15])."""
        artifact = _eligible_artifact()
        # Tamper past the frozen dataclass (the established CORE-04
        # pattern): a non-JSON-serializable metric value makes
        # compute_content_hash() raise TypeError.
        object.__setattr__(artifact, "metrics", {"brier": object()})
        with self.assertRaises(TypeError):
            artifact.check_content_hash()
        issues = artifact.validation_issues()
        self.assertTrue(
            any("content_hash cannot be verified" in issue for issue in issues),
            issues,
        )

    def test_malformed_created_at_records_issue(self):
        """A malformed ``created_at`` is recorded as an issue, not an
        escaping exception (kills ExceptionReplacer [960, 15])."""
        artifact = _eligible_artifact()
        # __post_init__ validates created_at, so tamper past the
        # frozen dataclass after construction.
        object.__setattr__(artifact, "created_at", "not-a-date")
        issues = artifact.validation_issues()
        self.assertIn("created_at must be ISO-8601.", issues)


if __name__ == "__main__":
    unittest.main()
