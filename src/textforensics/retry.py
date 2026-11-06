"""Retry Gate with Circuit Breaker for TextForensics.

Provides bounded scheduled-operation retry logic with exponential backoff,
jitter, and explicit circuit-breaker state transitions after repeated failures.

Inspired by the canonical rejection-rejector patterns for resilient
scheduled operations against external dependencies.

Features:
- Exponential backoff with jitter
- Circuit breaker with open/half-open/closed states
- Configurable failure thresholds
- Retry-After header support
- Thread-safe operation
- Observable state transitions

Design principles:
- Local-first: No network dependencies for state
- Fail-closed: Uncertainty defaults to circuit open
- Observable: State transitions are explicit
- Configurable: All thresholds tunable
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

__all__ = [
    "CircuitState",
    "CircuitTransition",
    "RetryGate",
    "RetryPolicy",
    "create_retry_gate",
]


class CircuitState(StrEnum):
    """Circuit breaker state."""

    CLOSED = "closed"  # Normal operation, requests pass through
    OPEN = "open"  # Failing, requests blocked
    HALF_OPEN = "half_open"  # Testing recovery, limited requests allowed


class CircuitTransition(StrEnum):
    """Circuit breaker state transition."""

    NONE = "none"  # No state change
    OPENED = "opened"  # Circuit opened after failures
    CLOSED = "closed"  # Circuit closed after successful probe
    HALF_OPENED = "half_opened"  # Transitioned to half-open


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Configuration for retry behavior."""

    base_delay: float = 1.0  # Initial delay in seconds
    max_delay: float = 300.0  # Cap on delay (5 minutes)
    max_retries: int = 3  # Max retry attempts
    jitter_factor: float = 0.1  # Jitter as fraction of delay
    circuit_open_after: int = 5  # Failures before opening circuit
    circuit_reset_timeout: float = 60.0  # Seconds before half-open
    max_provider_retry_after: float = 3600.0  # Cap on Retry-After header (1 hour)

    def __post_init__(self):
        if self.base_delay <= 0:
            raise ValueError("base_delay must be positive")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if not 0 <= self.jitter_factor <= 1:
            raise ValueError("jitter_factor must be in [0, 1]")
        if self.circuit_open_after <= 0:
            raise ValueError("circuit_open_after must be positive")
        if self.circuit_reset_timeout <= 0:
            raise ValueError("circuit_reset_timeout must be positive")


@dataclass
class RetryGate:
    """Bounded scheduled-operation retry gate with exponential backoff,
    jitter, and explicit circuit-breaker state transitions.

    Manual/operator-triggered actions deliberately do not have to consult this
    gate; they are explicit probes. Scheduled callers should call `ready` before
    probing, `failure` after a retryable failure, and `success` after a real
    successful dependency interaction.
    """

    policy: RetryPolicy
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failures: int = field(default=0, init=False)
    _next_allowed: float = field(default=0.0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _last_transition: CircuitTransition = field(default=CircuitTransition.NONE, init=False)

    def __post_init__(self):
        self._next_allowed = time.monotonic()

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state

    @property
    def failures(self) -> int:
        """Number of consecutive failures."""
        return self._failures

    @property
    def last_transition(self) -> CircuitTransition:
        """Last circuit state transition."""
        return self._last_transition

    def ready(self) -> tuple[bool, float]:
        """Check if a request can proceed.

        Returns:
            (allowed: bool, delay_until_ready: float)
        """
        now = time.monotonic()
        if self._state == CircuitState.OPEN:
            if now >= self._next_allowed:
                # Transition to half-open
                self._state = CircuitState.HALF_OPEN
                self._last_transition = CircuitTransition.HALF_OPENED
                return True, 0.0
            return False, self._next_allowed - now
        elif self._state == CircuitState.HALF_OPEN:
            # Allow one probe in half-open state
            return True, 0.0
        return True, 0.0

    def success(self, now: float | None = None) -> CircuitTransition:
        """Record a successful call and potentially close the circuit.

        Args:
            now: Current time (defaults to time.monotonic())

        Returns:
            CircuitTransition indicating state change
        """
        if now is None:
            now = time.monotonic()

        if self._state in (CircuitState.HALF_OPEN, CircuitState.OPEN):
            # Successful probe in half-open or open closes the circuit
            self._state = CircuitState.CLOSED
            self._failures = 0
            self._next_allowed = now
            self._last_transition = CircuitTransition.CLOSED
            return CircuitTransition.CLOSED

        self._failures = 0
        self._next_allowed = now
        return CircuitTransition.NONE

    def failure(
        self,
        now: float | None = None,
        retry_after: float | None = None,
    ) -> tuple[float, CircuitTransition]:
        """Record a failed call and compute the next retry delay.

        Args:
            now: Current time (defaults to time.monotonic())
            retry_after: Upstream Retry-After hint in seconds

        Returns:
            (delay_before_next_attempt: float, CircuitTransition)
        """
        if now is None:
            now = time.monotonic()

        self._failures = min(
            self._failures + 1, self.policy.max_retries + self.policy.circuit_open_after
        )
        self._last_failure_time = now

        # Determine delay
        if retry_after is not None:
            # Cap upstream retry-after hint
            delay = min(retry_after, self.policy.max_provider_retry_after)
            # When retry_after is provided, cap at max_provider_retry_after, not max_delay
            delay = max(0.0, min(delay, self.policy.max_provider_retry_after))
        else:
            # Exponential backoff with jitter
            shift = min(self._failures - 1, 10)
            factor = 1 << shift
            exponential = self.policy.base_delay * factor
            delay = min(exponential, self.policy.max_delay)

            # Add jitter
            if self.policy.jitter_factor > 0:
                jitter = delay * self.policy.jitter_factor * random.uniform(-1, 1)
                delay += jitter

            delay = max(0.0, min(delay, self.policy.max_delay))

        self._next_allowed = now + delay

        # Check for circuit opening
        transition = CircuitTransition.NONE
        if self._failures >= self.policy.circuit_open_after and self._state != CircuitState.OPEN:
            self._state = CircuitState.OPEN
            self._next_allowed = now + self.policy.circuit_reset_timeout
            transition = CircuitTransition.OPENED

        self._last_transition = transition
        return delay, transition

    def get_status(self) -> dict[str, Any]:
        """Get current gate status."""
        return {
            "state": self.state.value,
            "failures": self._failures,
            "next_allowed_at": datetime.fromtimestamp(self._next_allowed, UTC).isoformat()
            if self._next_allowed > time.monotonic()
            else None,
            "last_transition": self._last_transition.value,
            "policy": {
                "base_delay": self.policy.base_delay,
                "max_delay": self.policy.max_delay,
                "max_retries": self.policy.max_retries,
                "circuit_open_after": self.policy.circuit_open_after,
                "circuit_reset_timeout": self.policy.circuit_reset_timeout,
            },
        }


def create_retry_gate(
    base_delay: float = 1.0,
    max_delay: float = 300.0,
    max_retries: int = 3,
    circuit_open_after: int = 5,
    circuit_reset_timeout: float = 60.0,
    jitter_factor: float = 0.1,
) -> RetryGate:
    """Create a retry gate with common defaults."""
    policy = RetryPolicy(
        base_delay=base_delay,
        max_delay=max_delay,
        max_retries=max_retries,
        circuit_open_after=circuit_open_after,
        circuit_reset_timeout=circuit_reset_timeout,
        jitter_factor=jitter_factor,
    )
    return RetryGate(policy)


# Convenience function for detector operations
async def with_retry_gate(
    gate: RetryGate,
    operation: callable,
    *args,
    max_retries: int | None = None,
    retry_on: tuple[type[Exception], ...] = (Exception,),
    **kwargs,
) -> Any:
    """Execute an operation with retry gate protection.

    Args:
        gate: RetryGate instance
        operation: Async callable to execute
        max_retries: Override gate's max_retries
        retry_on: Exception types to retry on
        **kwargs: Arguments passed to operation

    Returns:
        Result of operation

    Raises:
        Last exception if all retries exhausted
    """
    max_attempts = max_retries if max_retries is not None else gate.policy.max_retries
    last_exception = None

    for attempt in range(max_attempts + 1):
        allowed, delay = gate.ready()
        if not allowed:
            await asyncio.sleep(delay)
            continue

        try:
            result = await operation(*args, **kwargs)
            gate.success()
            return result
        except retry_on:
            delay, _ = gate.failure()
            if attempt < max_attempts:
                await asyncio.sleep(delay)
                continue
            raise
        except Exception:
            # Non-retryable exception
            gate.failure()
            raise

    raise RuntimeError("Retry gate exhausted") from last_exception
