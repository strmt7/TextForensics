"""W3 Worker F (recovery) kill tests for result_codec (audit-w3-f).

Each test kills one proof survivor from the W3 re-proof
(hidden_files/audit-w3-f2-survivors-result_codec.json): the test
asserts the original behaviour on a distinguishing input, so the
mutant fails it. See hidden_files/audit-w3-worker-f.md §5 for the
per-mutant kill evidence (mutate_code re-proof) and §6 for the
proven-equivalent survivors (Mul_Div ``*,`` marker and the dead
second ``reject_nonfinite_value`` handler).
"""

from unittest import mock

from textforensics.result_codec import _accepted_versions


class TestWorkerFResultCodecKill:
    """Kill the one killable result_codec survivor."""

    def test_accepted_versions_falls_back_when_registry_raises(self):
        """ExceptionReplacer [111,15] occ 0: the ``except ValueError``
        in ``_accepted_versions`` must catch a registry failure and
        fall back to the current-version singleton. The mutant replaces
        the caught type, so the ValueError propagates."""
        with mock.patch(
            "textforensics.schema.supported_versions",
            side_effect=ValueError("registry unavailable"),
        ):
            assert _accepted_versions("trust-map") == frozenset({"textforensics.trust-map/v3"})
