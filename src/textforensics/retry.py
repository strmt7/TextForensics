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
import math
import random
import threading
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
        # S15: every duration must be a finite number — a NaN bound
        # silently disables its comparison (NaN <= x is False) and an
        # infinite bound disables the cap it was meant to enforce.
        for name in (
            "base_delay",
            "max_delay",
            "circuit_reset_timeout",
            "max_provider_retry_after",
            "jitter_factor",
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
            ):
                raise ValueError(f"{name} must be a finite number")
        if self.base_delay <= 0:
            raise ValueError("base_delay must be positive")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if self.max_provider_retry_after <= 0:
            raise ValueError("max_provider_retry_after must be positive")
        if not isinstance(self.max_retries, int) or isinstance(self.max_retries, bool):
            raise ValueError("max_retries must be an integer")
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if not 0 <= self.jitter_factor <= 1:
            raise ValueError("jitter_factor must be in [0, 1]")
        if not isinstance(self.circuit_open_after, int) or isinstance(
            self.circuit_open_after, bool
        ):
            raise ValueError("circuit_open_after must be an integer")
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
    # Monotonic deadline of the single half-open probe claim, or 0.0
    # when no probe is currently owned (S15).
    _half_open_probe_until: float = field(default=0.0, init=False)
    # Monotonic "do not call before" deadline from the most recent
    # provider Retry-After instruction, or 0.0 when none is in force
    # (S15). This is tracked separately from the backoff/reset
    # deadlines: the exponential backoff paces retries while the gate
    # is closed and the reset timeout paces half-open probes, but a
    # provider Retry-After is an explicit instruction that neither
    # may shorten. It is honoured in every state and only a success
    # clears it.
    _provider_not_before: float = field(default=0.0, init=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

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

    def _grant_half_open_probe(self, now: float) -> None:
        """Mark the single half-open probe as owned until its deadline.

        A granted probe that never resolves must not wedge the gate
        forever: the claim expires after ``circuit_reset_timeout``,
        after which a fresh probe may be granted. Caller holds the lock.
        """
        self._half_open_probe_until = now + self.policy.circuit_reset_timeout

    def _release_half_open_probe(self) -> None:
        """Release any half-open probe claim. Caller holds the lock."""
        self._half_open_probe_until = 0.0

    def ready(self, now: float | None = None) -> tuple[bool, float]:
        """Check if a request can proceed.

        Readiness respects the backoff deadline in every state: a
        closed gate is not ready before ``_next_allowed`` or before
        an in-force provider Retry-After deadline. An open gate
        becomes half-open only once both its reset timeout and any
        provider deadline have passed, and half-open admits exactly
        one probe — the caller that is granted it. Further callers
        are denied until that probe resolves (success/failure) or
        its claim expires.

        Args:
            now: Monotonic time (defaults to time.monotonic(); tests
                pass a fake clock).

        Returns:
            (allowed: bool, delay_until_ready: float)
        """
        if now is None:
            now = time.monotonic()
        with self._lock:
            if self._state == CircuitState.OPEN:
                not_before = max(self._next_allowed, self._provider_not_before)
                if now >= not_before:
                    # Transition to half-open; this caller owns the
                    # single probe.
                    self._state = CircuitState.HALF_OPEN
                    self._last_transition = CircuitTransition.HALF_OPENED
                    self._grant_half_open_probe(now)
                    return True, 0.0
                return False, not_before - now
            elif self._state == CircuitState.HALF_OPEN:
                if now < self._provider_not_before:
                    return False, self._provider_not_before - now
                if self._half_open_probe_until == 0.0 or now >= self._half_open_probe_until:
                    # No live claim (entered half-open without a grant,
                    # or the previous claim expired): grant a fresh probe.
                    self._grant_half_open_probe(now)
                    return True, 0.0
                return False, self._half_open_probe_until - now
            not_before = max(self._next_allowed, self._provider_not_before)
            if now < not_before:
                return False, not_before - now
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

        with self._lock:
            self._release_half_open_probe()
            # A success spends the provider's Retry-After instruction.
            self._provider_not_before = 0.0
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
            retry_after: Upstream Retry-After hint in seconds; must be
                a finite, non-negative number when given.

        Returns:
            (delay_before_next_attempt: float, CircuitTransition)

        Opening the circuit never shortens a provider deadline: a
        Retry-After instruction is recorded separately and honoured
        in every state, so the reset timeout cannot overwrite it
        (S15). The exponential backoff delay paces the closed gate;
        the reset timeout paces half-open probes.
        """
        if now is None:
            now = time.monotonic()
        if retry_after is not None and (
            not isinstance(retry_after, (int, float))
            or isinstance(retry_after, bool)
            or not math.isfinite(retry_after)
            or retry_after < 0
        ):
            raise ValueError("retry_after must be a finite, non-negative number")

        with self._lock:
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
                # Record the provider deadline separately: a later,
                # shorter instruction never shortens one already in
                # force, and opening the circuit never overwrites it.
                self._provider_not_before = max(self._provider_not_before, now + delay)
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

            # Check for circuit opening. A failed half-open probe always
            # reopens the circuit: the dependency is still broken. The
            # open deadline is the reset timeout; an in-force provider
            # Retry-After deadline (tracked separately) still applies
            # on top of it via ready().
            transition = CircuitTransition.NONE
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                self._release_half_open_probe()
                self._next_allowed = now + self.policy.circuit_reset_timeout
                transition = CircuitTransition.OPENED
            elif self._failures >= self.policy.circuit_open_after:
                if self._state != CircuitState.OPEN:
                    transition = CircuitTransition.OPENED
                self._state = CircuitState.OPEN
                self._release_half_open_probe()
                self._next_allowed = now + self.policy.circuit_reset_timeout

            self._last_transition = transition
            return delay, transition

    def get_status(self) -> dict[str, Any]:
        """Get current gate status."""
        with self._lock:
            probe_in_flight = (
                self._state == CircuitState.HALF_OPEN
                and self._half_open_probe_until > time.monotonic()
            )
            return {
                "state": self.state.value,
                "failures": self._failures,
                "half_open_probe_in_flight": probe_in_flight,
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
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 0:
        raise ValueError("max_retries must be a non-negative integer")
    # S16: readiness waiting and operation-attempt counting are
    # separate. Waiting for the gate (backoff, open circuit, another
    # caller's half-open probe) never consumes an attempt; only an
    # actual call of the operation does. The loop therefore waits
    # until the gate grants a probe, calls exactly once per attempt,
    # and raises the last real failure once the initial attempt plus
    # ``max_attempts`` retries have all been used.
    calls = 0

    while True:
        allowed, delay = gate.ready()
        while not allowed:
            await asyncio.sleep(delay)
            allowed, delay = gate.ready()

        try:
            result = await operation(*args, **kwargs)
            gate.success()
            return result
        except retry_on:
            calls += 1
            gate.failure()
            if calls > max_attempts:
                raise
            # Loop back: ready() enforces the failure's backoff (or
            # the open-circuit deadline) before the next call.
        except Exception:
            # Non-retryable exception
            gate.failure()
            raise
