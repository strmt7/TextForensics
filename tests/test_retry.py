"""Tests for Retry Gate with Circuit Breaker."""

from __future__ import annotations

import time

import pytest

from textforensics.retry import (
    CircuitState,
    CircuitTransition,
    RetryPolicy,
    create_retry_gate,
    with_retry_gate,
)


class TestRetryPolicy:
    def test_default_policy(self):
        policy = RetryPolicy()
        assert policy.base_delay == 1.0
        assert policy.max_delay == 300.0
        assert policy.max_retries == 3
        assert policy.jitter_factor == 0.1
        assert policy.circuit_open_after == 5
        assert policy.circuit_reset_timeout == 60.0

    def test_custom_policy(self):
        policy = RetryPolicy(
            base_delay=2.0,
            max_delay=600.0,
            max_retries=5,
            jitter_factor=0.2,
            circuit_open_after=3,
            circuit_reset_timeout=30.0,
        )
        assert policy.base_delay == 2.0
        assert policy.max_delay == 600.0
        assert policy.max_retries == 5
        assert policy.jitter_factor == 0.2
        assert policy.circuit_open_after == 3
        assert policy.circuit_reset_timeout == 30.0

    def test_invalid_base_delay(self):
        with pytest.raises(ValueError):
            RetryPolicy(base_delay=0)

    def test_invalid_max_delay(self):
        with pytest.raises(ValueError):
            RetryPolicy(base_delay=10.0, max_delay=5.0)

    def test_invalid_jitter(self):
        with pytest.raises(ValueError):
            RetryPolicy(jitter_factor=1.5)

    def test_invalid_circuit_open_after(self):
        with pytest.raises(ValueError):
            RetryPolicy(circuit_open_after=0)


class TestRetryGate:
    def test_initial_state(self):
        gate = create_retry_gate()
        assert gate.state == CircuitState.CLOSED
        assert gate.failures == 0
        assert gate.last_transition == CircuitTransition.NONE

    def test_ready_when_closed(self):
        gate = create_retry_gate()
        allowed, delay = gate.ready()
        assert allowed is True
        assert delay == 0.0

    def test_success_resets_failures(self):
        gate = create_retry_gate()
        gate._failures = 3
        gate._state = CircuitState.OPEN
        gate._next_allowed = time.monotonic() + 10

        transition = gate.success()
        assert transition == CircuitTransition.CLOSED
        assert gate.failures == 0
        assert gate._state == CircuitState.CLOSED

    def test_success_closes_half_open(self):
        gate = create_retry_gate()
        # HALF_OPEN: state=CircuitState.HALF_OPEN
        gate._state = CircuitState.HALF_OPEN
        gate._next_allowed = time.monotonic() - 1  # Was in future, now past
        gate._failures = 5

        transition = gate.success()
        assert transition == CircuitTransition.CLOSED
        assert gate.failures == 0
        assert gate.state == CircuitState.CLOSED

    def test_failure_increments_counter(self):
        gate = create_retry_gate()
        delay, transition = gate.failure()

        assert gate.failures == 1
        assert transition == CircuitTransition.NONE
        assert delay >= 0.0

    def test_failure_opens_circuit(self):
        gate = create_retry_gate(circuit_open_after=3)

        gate.failure()
        gate.failure()
        assert gate.state == CircuitState.CLOSED

        delay, transition = gate.failure()
        assert gate.state == CircuitState.OPEN
        assert transition == CircuitTransition.OPENED

    def test_half_open_after_timeout(self):
        gate = create_retry_gate(circuit_open_after=2, circuit_reset_timeout=0.01)

        gate.failure()
        gate.failure()
        assert gate.state == CircuitState.OPEN

        # Wait for circuit reset timeout
        time.sleep(0.02)

        allowed, delay = gate.ready()
        assert allowed is True
        assert gate.state == CircuitState.HALF_OPEN

    def test_failure_records_retry_after(self):
        gate = create_retry_gate(jitter_factor=0.0)
        delay, _ = gate.failure(retry_after=10.0)
        assert delay == 10.0

        # Should respect max_provider_retry_after
        delay2, _ = gate.failure(retry_after=5000.0)
        assert delay2 == gate.policy.max_provider_retry_after

    def test_exponential_backoff(self):
        gate = create_retry_gate(base_delay=1.0, max_delay=100.0, jitter_factor=0.0)

        gate.failure()  # failure 1
        d1, _ = gate.failure()  # failure 2
        d2, _ = gate.failure()  # failure 3

        # Should roughly double each time (with jitter=0)
        assert d2 > d1

    def test_jitter_added(self):
        gate = create_retry_gate(base_delay=10.0, max_delay=100.0, jitter_factor=0.5)

        # Run multiple times and check variation
        delays = []
        for _ in range(10):
            gate._failures = 1
            delay, _ = gate.failure()
            delays.append(delay)

        # With 50% jitter, should see variation
        assert max(delays) > min(delays)

    def test_max_delay_cap(self):
        gate = create_retry_gate(base_delay=1.0, max_delay=5.0, jitter_factor=0.0)

        for _ in range(10):
            gate.failure()

        delay, _ = gate.failure()
        assert delay <= 5.0

    def test_get_status(self):
        gate = create_retry_gate()
        status = gate.get_status()

        assert "state" in status
        assert "failures" in status
        assert "next_allowed_at" in status
        assert "last_transition" in status
        assert "policy" in status


class TestCreateRetryGate:
    def test_create_with_defaults(self):
        gate = create_retry_gate()
        assert gate.policy.base_delay == 1.0
        assert gate.policy.max_delay == 300.0
        assert gate.policy.max_retries == 3
        assert gate.policy.circuit_open_after == 5

    def test_create_with_custom_values(self):
        gate = create_retry_gate(
            base_delay=2.0,
            max_delay=600.0,
            max_retries=5,
            circuit_open_after=3,
            circuit_reset_timeout=30.0,
        )
        assert gate.policy.base_delay == 2.0
        assert gate.policy.max_delay == 600.0
        assert gate.policy.max_retries == 5
        assert gate.policy.circuit_open_after == 3
        assert gate.policy.circuit_reset_timeout == 30.0


class TestWithRetryGate:
    @pytest.mark.asyncio
    async def test_successful_operation(self):
        gate = create_retry_gate()
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            return "success"

        result = await with_retry_gate(gate, operation)
        assert result == "success"
        assert call_count == 1
        assert gate.state == CircuitState.CLOSED

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        gate = create_retry_gate(max_retries=3)
        call_count = 0

        async def operation():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Temporary failure")
            return "success"

        result = await with_retry_gate(gate, operation, retry_on=(ConnectionError,))
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self):
        gate = create_retry_gate(max_retries=2)

        async def operation():
            raise ConnectionError("Persistent failure")

        with pytest.raises(ConnectionError):
            await with_retry_gate(gate, operation, max_retries=2, retry_on=(ConnectionError,))

    @pytest.mark.asyncio
    async def test_non_retryable_exception(self):
        gate = create_retry_gate()

        async def operation():
            raise ValueError("Non-retryable")

        with pytest.raises(ValueError):
            await with_retry_gate(gate, operation, retry_on=(ConnectionError,))

    @pytest.mark.asyncio
    async def test_circuit_opens_during_retries(self):
        gate = create_retry_gate(circuit_open_after=2, max_retries=5, circuit_reset_timeout=0.01)

        async def operation():
            raise ConnectionError("Persistent")

        with pytest.raises(ConnectionError):
            await with_retry_gate(gate, operation, max_retries=5, retry_on=(ConnectionError,))

        assert gate.state == CircuitState.OPEN


class TestRetryGateEdgeCases:
    def test_zero_jitter(self):
        gate = create_retry_gate(jitter_factor=0.0)
        delays = []
        for _ in range(5):
            gate._failures = 2
            delay, _ = gate.failure()
            delays.append(delay)

        # All delays should be identical with no jitter
        assert all(d == delays[0] for d in delays)

    def test_max_retries_zero(self):
        gate = create_retry_gate(max_retries=0)
        assert gate.policy.max_retries == 0

    def test_circuit_reset_timeout_zero(self):
        # Very small timeout
        gate = create_retry_gate(circuit_open_after=1, circuit_reset_timeout=0.001)
        gate.failure()
        assert gate.state == CircuitState.OPEN
        time.sleep(0.01)
        # Call ready() to trigger the transition
        allowed, _ = gate.ready()
        assert allowed is True
        assert gate.state == CircuitState.HALF_OPEN

    def test_negative_delay_prevention(self):
        gate = create_retry_gate()
        gate._failures = 0
        gate._next_allowed = time.monotonic() + 100

        # Even with large next_allowed, delay should not be negative
        delay, _ = gate.failure()
        assert delay >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
