"""W4 mutation kill tests: textforensics.retry (Worker F2).

Each test kills one or more phase-1 survivors from the W4 proof set
(audit-w4-f-proofset.json / audit-w4-f-survivors.json). The tests drive
RetryGate with fake clocks (the ``now`` parameters) and direct state
setup where the mutant changes a default or a transition the public API
cannot otherwise reach. Equivalent retry mutants (StrEnum identity /
ordering coincidences, never-negative / never-reached defaults, the
zero-jitter branch) are documented in
audit-w4-f-equiv-reasons-retry.json and must SURVIVE this file.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import patch

import pytest

from textforensics.retry import (
    CircuitState,
    CircuitTransition,
    RetryGate,
    RetryPolicy,
    create_retry_gate,
    with_retry_gate,
)


def _gate(**policy_kwargs) -> RetryGate:
    return RetryGate(RetryPolicy(**policy_kwargs))


def _open_gate(now: float = 0.0) -> RetryGate:
    """A gate driven OPEN by five failures at *now* (default policy)."""
    gate = _gate(jitter_factor=0.0)
    for _ in range(5):
        gate.failure(now=now)
    assert gate.state is CircuitState.OPEN
    return gate


# ---------------------------------------------------------------------------
# RetryPolicy.__post_init__ validation
# ---------------------------------------------------------------------------


def test_policy_rejects_bool_duration() -> None:
    """A bool is not a finite number for duration fields."""
    with pytest.raises(ValueError, match="must be a finite number"):
        RetryPolicy(base_delay=True)


def test_policy_rejects_negative_base_delay() -> None:
    with pytest.raises(ValueError, match="base_delay must be positive"):
        RetryPolicy(base_delay=-1.0)


def test_policy_accepts_max_delay_equal_to_base_delay() -> None:
    """max_delay == base_delay is allowed (only strictly less is rejected)."""
    RetryPolicy(base_delay=1.0, max_delay=1.0)


def test_policy_rejects_negative_max_provider_retry_after() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        RetryPolicy(max_provider_retry_after=-1.0)


def test_policy_rejects_zero_max_provider_retry_after() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        RetryPolicy(max_provider_retry_after=0.0)


def test_policy_accepts_small_max_provider_retry_after() -> None:
    """0.5 is a positive cap."""
    RetryPolicy(max_provider_retry_after=0.5)


def test_policy_rejects_slightly_negative_max_provider_retry_after() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        RetryPolicy(max_provider_retry_after=-0.5)


def test_policy_rejects_negative_max_retries_minus_one() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        RetryPolicy(max_retries=-1)


def test_policy_rejects_negative_jitter() -> None:
    with pytest.raises(ValueError, match="jitter_factor must be in"):
        RetryPolicy(jitter_factor=-0.5)


def test_policy_accepts_jitter_one() -> None:
    """jitter_factor == 1 is the top of the allowed [0, 1] range."""
    RetryPolicy(jitter_factor=1.0)


def test_policy_rejects_negative_circuit_open_after() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        RetryPolicy(circuit_open_after=-1)


def test_policy_rejects_zero_circuit_reset_timeout() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        RetryPolicy(circuit_reset_timeout=0.0)


def test_policy_rejects_slightly_negative_circuit_reset_timeout() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        RetryPolicy(circuit_reset_timeout=-0.5)


# ---------------------------------------------------------------------------
# RetryGate construction shape
# ---------------------------------------------------------------------------


def test_gate_rejects_extra_positional_arg() -> None:
    """RetryGate.__init__ takes only the policy: its internal fields are
    init=False."""
    with pytest.raises(TypeError):
        RetryGate(RetryPolicy(), 5.0)


def test_gate_repr_excludes_lock() -> None:
    assert "_lock" not in repr(_gate())


def test_gate_equality_ignores_lock() -> None:
    """Two gates in the same observable state compare equal: the lock is
    excluded from comparison."""
    gate1 = _gate()
    gate2 = _gate()
    gate2._next_allowed = gate1._next_allowed
    assert gate1 == gate2


# ---------------------------------------------------------------------------
# Defaults and release/reset
# ---------------------------------------------------------------------------


def test_half_open_probe_default_is_zero() -> None:
    """A fresh gate owns no half-open probe: in HALF_OPEN with no grant,
    ready() admits a probe immediately even for a small clock."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    assert gate.ready(now=0.5) == (True, 0.0)


def test_provider_not_before_default_is_zero() -> None:
    """A fresh gate has no provider deadline in force: with the backoff
    deadline cleared, ready() admits immediately for a small clock."""
    gate = _gate()
    gate._next_allowed = 0.0
    assert gate.ready(now=0.5) == (True, 0.0)


def test_release_half_open_probe_resets_to_zero() -> None:
    gate = _gate()
    gate._half_open_probe_until = 5.0
    gate._release_half_open_probe()
    assert gate._half_open_probe_until == 0.0


def test_success_clears_provider_deadline() -> None:
    """A success spends the provider's Retry-After instruction."""
    gate = _gate(jitter_factor=0.0)
    gate.failure(now=0.0, retry_after=100.0)
    assert gate._provider_not_before == 100.0
    gate.success(now=200.0)
    assert gate._provider_not_before == 0.0


def test_success_resets_failures() -> None:
    gate = _gate(jitter_factor=0.0)
    for _ in range(3):
        gate.failure(now=0.0)
    assert gate.failures == 3
    gate.success(now=10.0)
    assert gate.failures == 0


def test_success_uses_given_now() -> None:
    """success(now) advances the backoff deadline to the given clock."""
    gate = _gate()
    gate.success(now=100.0)
    assert gate._next_allowed == 100.0


# ---------------------------------------------------------------------------
# ready()
# ---------------------------------------------------------------------------


def test_ready_open_transition_returns_zero_delay() -> None:
    """An open gate whose reset deadline has passed admits the probe
    immediately."""
    gate = _open_gate(now=0.0)
    assert gate.ready(now=100.0) == (True, 0.0)


def test_ready_open_reports_remaining_delay() -> None:
    """An open gate still inside its reset timeout reports the wait."""
    gate = _open_gate(now=0.0)
    assert gate.ready(now=30.0) == (False, 30.0)


def test_ready_half_open_provider_deadline_reports_delay() -> None:
    """In HALF_OPEN an in-force provider deadline blocks with its wait."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    gate._provider_not_before = 100.0
    assert gate.ready(now=30.0) == (False, 70.0)


def test_ready_half_open_grants_probe() -> None:
    """In HALF_OPEN with no live probe, ready() grants one immediately."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    assert gate.ready(now=50.0) == (True, 0.0)


def test_ready_half_open_live_probe_reports_delay() -> None:
    """In HALF_OPEN with a live probe claim, other callers wait."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    gate._half_open_probe_until = 100.0
    assert gate.ready(now=30.0) == (False, 70.0)


def test_ready_half_open_expired_probe_grants() -> None:
    """In HALF_OPEN with an expired probe claim, a fresh probe is granted."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    gate._half_open_probe_until = 1.0
    assert gate.ready(now=2.0) == (True, 0.0)


def test_ready_half_open_probe_until_one_denies_early() -> None:
    """A probe claim until 1.0 still blocks at 0.5."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    gate._half_open_probe_until = 1.0
    assert gate.ready(now=0.5) == (False, 0.5)


def test_ready_closed_reports_remaining_delay() -> None:
    """A closed gate inside its backoff deadline reports the wait."""
    gate = _gate()
    gate._next_allowed = 100.0
    assert gate.ready(now=30.0) == (False, 70.0)


# ---------------------------------------------------------------------------
# failure(): retry_after validation
# ---------------------------------------------------------------------------


def test_failure_rejects_bool_retry_after() -> None:
    gate = _gate()
    with pytest.raises(ValueError, match="retry_after"):
        gate.failure(now=0.0, retry_after=True)


def test_failure_accepts_zero_retry_after() -> None:
    """retry_after == 0 is a valid (immediate) hint."""
    gate = _gate(jitter_factor=0.0)
    delay, _transition = gate.failure(now=0.0, retry_after=0.0)
    assert delay == 0.0


def test_failure_accepts_half_second_retry_after() -> None:
    gate = _gate(jitter_factor=0.0)
    delay, _transition = gate.failure(now=0.0, retry_after=0.5)
    assert delay == 0.5


# ---------------------------------------------------------------------------
# failure(): backoff math
# ---------------------------------------------------------------------------


def test_failure_backoff_doubles_on_second_failure() -> None:
    """Exponential backoff: failure 2 (shift 1, factor 2) waits 2.0s."""
    gate = _gate(base_delay=1.0, jitter_factor=0.0, max_retries=20, circuit_open_after=20)
    gate.failure(now=0.0)
    delay, _transition = gate.failure(now=0.0)
    assert delay == 2.0


def test_failure_backoff_shift_two_on_third_failure() -> None:
    """Failure 3 (shift 2, factor 4) waits 4.0s."""
    gate = _gate(base_delay=1.0, jitter_factor=0.0, max_retries=20, circuit_open_after=20)
    for _ in range(2):
        gate.failure(now=0.0)
    delay, _transition = gate.failure(now=0.0)
    assert delay == 4.0


def test_failure_backoff_caps_shift_at_ten() -> None:
    """The shift caps at 10: failure 12 waits 2**10 == 1024s."""
    gate = _gate(
        base_delay=1.0, max_delay=1e9, jitter_factor=0.0, max_retries=20, circuit_open_after=20
    )
    for _ in range(11):
        gate.failure(now=0.0)
    delay, _transition = gate.failure(now=0.0)
    assert delay == 1024.0


def test_failure_retry_after_zero_delay() -> None:
    """A zero Retry-After hint yields a zero delay (not a 1.0 floor)."""
    gate = _gate(jitter_factor=0.0)
    delay, _transition = gate.failure(now=0.0, retry_after=0.0)
    assert delay == 0.0


def test_failure_small_backoff_delay() -> None:
    """A 0.5s base delay yields a 0.5s first delay (not a 1.0 floor)."""
    gate = _gate(base_delay=0.5, jitter_factor=0.0)
    delay, _transition = gate.failure(now=0.0)
    assert delay == 0.5


def test_failure_jitter_first_factor() -> None:
    """Jitter is delay * factor * uniform: 2.0 * 0.5 * 0.5 == 0.5."""
    gate = _gate(base_delay=1.0, jitter_factor=0.5, max_retries=20, circuit_open_after=20)
    with patch("random.uniform", return_value=0.5):
        gate.failure(now=0.0)
        delay, _transition = gate.failure(now=0.0)
    assert delay == 2.5


def test_failure_jitter_second_factor() -> None:
    """Jitter is (delay * factor) * uniform: 2.0 * 0.5 * 0.25 == 0.25."""
    gate = _gate(base_delay=1.0, jitter_factor=0.5, max_retries=20, circuit_open_after=20)
    with patch("random.uniform", return_value=0.25):
        gate.failure(now=0.0)
        delay, _transition = gate.failure(now=0.0)
    assert delay == 2.25


def test_failure_jitter_uniform_range() -> None:
    """The jitter draw is uniform(-1, 1)."""
    gate = _gate(base_delay=1.0, jitter_factor=0.5)
    with patch("random.uniform", return_value=0.5) as uniform:
        gate.failure(now=0.0)
    uniform.assert_called_once_with(-1, 1)


def test_failure_caps_failure_count() -> None:
    """_failures caps at max_retries + circuit_open_after (3 + 5 == 8)."""
    gate = _gate(jitter_factor=0.0)
    for _ in range(12):
        gate.failure(now=0.0)
    assert gate.failures == 8


# ---------------------------------------------------------------------------
# failure(): transitions and deadlines
# ---------------------------------------------------------------------------


def test_failure_half_open_probe_reopens() -> None:
    """A failed half-open probe reopens the circuit."""
    gate = _gate(jitter_factor=0.0)
    gate._state = CircuitState.HALF_OPEN
    _delay, transition = gate.failure(now=100.0)
    assert gate.state is CircuitState.OPEN
    assert transition is CircuitTransition.OPENED


def test_failure_open_gate_stays_open_without_transition() -> None:
    """A further failure on an already-open gate reports no transition."""
    gate = _open_gate(now=0.0)
    _delay, transition = gate.failure(now=1000.0)
    assert gate.state is CircuitState.OPEN
    assert transition is CircuitTransition.NONE


def test_failure_beyond_threshold_resets_deadline() -> None:
    """A failure past the open threshold still resets the reset deadline
    (now + circuit_reset_timeout), it does not leave the backoff delay."""
    gate = _open_gate(now=0.0)
    gate.failure(now=1000.0)
    assert gate._next_allowed == 1060.0


def test_failure_half_open_sets_reset_deadline() -> None:
    """A failed half-open probe sets the reset deadline (now + 60)."""
    gate = _gate(jitter_factor=0.0)
    gate._state = CircuitState.HALF_OPEN
    gate.failure(now=100.0)
    assert gate._next_allowed == 160.0


def test_failure_threshold_open_sets_reset_deadline() -> None:
    """The fifth failure opens the circuit with now + 60 as the deadline."""
    gate = _gate(jitter_factor=0.0)
    for _ in range(4):
        gate.failure(now=100.0)
    gate.failure(now=100.0)
    assert gate.state is CircuitState.OPEN
    assert gate._next_allowed == 160.0


def test_failure_next_allowed_is_now_plus_delay() -> None:
    """The backoff deadline is now + delay."""
    gate = _gate(base_delay=1.0, jitter_factor=0.0)
    gate.failure(now=100.0)
    assert gate._next_allowed == 101.0


# ---------------------------------------------------------------------------
# get_status()
# ---------------------------------------------------------------------------


def test_status_probe_in_flight_when_live() -> None:
    """A live half-open probe claim shows as in flight."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    gate._half_open_probe_until = time.monotonic() + 100.0
    assert gate.get_status()["half_open_probe_in_flight"] is True


def test_status_probe_not_in_flight_when_no_probe() -> None:
    """HALF_OPEN with no probe claim shows no probe in flight."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    gate._half_open_probe_until = 0.0
    assert gate.get_status()["half_open_probe_in_flight"] is False


def test_status_probe_not_in_flight_at_exact_deadline() -> None:
    """A probe claim exactly at its deadline is no longer in flight."""
    gate = _gate()
    gate._state = CircuitState.HALF_OPEN
    gate._half_open_probe_until = 1000.0
    with patch("textforensics.retry.time.monotonic", return_value=1000.0):
        assert gate.get_status()["half_open_probe_in_flight"] is False


def test_status_next_allowed_future() -> None:
    """A future backoff deadline renders as an ISO timestamp."""
    gate = _gate(base_delay=1.0, jitter_factor=0.0)
    gate.failure(now=time.monotonic())
    assert gate.get_status()["next_allowed_at"] is not None


def test_status_next_allowed_past() -> None:
    """A past backoff deadline renders as None."""
    gate = _gate()
    gate._next_allowed = 0.0
    assert gate.get_status()["next_allowed_at"] is None


def test_status_next_allowed_at_exact_now() -> None:
    """A deadline exactly now renders as None (strictly future only)."""
    gate = _gate()
    gate._next_allowed = 1000.0
    with patch("textforensics.retry.time.monotonic", return_value=1000.0):
        assert gate.get_status()["next_allowed_at"] is None


# ---------------------------------------------------------------------------
# with_retry_gate()
# ---------------------------------------------------------------------------


async def _never_called() -> str:
    return "ok"


def test_with_retry_gate_rejects_bool_max_retries() -> None:
    gate = create_retry_gate()
    with pytest.raises(ValueError, match="max_retries"):
        asyncio.run(with_retry_gate(gate, _never_called, max_retries=True))


def test_with_retry_gate_rejects_negative_max_retries() -> None:
    gate = create_retry_gate()
    with pytest.raises(ValueError, match="max_retries"):
        asyncio.run(with_retry_gate(gate, _never_called, max_retries=-1))
