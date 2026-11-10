"""Shared execution, consent, stop and privacy boundary (W1).

This module is the ONE channel every public surface (CLI, HTTP API,
MCP, web UI, observatory) uses to decide whether detector work may run
and what it may do. It is defined by W1 Worker A; no other worker
invents a competing policy, stop check, or error-redaction rule.

Contents
--------
* :class:`ExecutionPolicy` — one validated command boundary carrying
  allowed local/remote adapters, explicit outbound consent, input/output
  byte limits, deadlines, cancellation and retention choices. Default
  is local-only: no remote detector runs unless its ID is explicitly
  listed *and* ``remote_consent`` is true. This is outbound adapter
  consent; it is unrelated to the inbound ``allow_remote`` bind
  permission in :mod:`textforensics.config`.
* :func:`assert_execution_allowed` / :func:`is_execution_stopped` —
  the ONE shared stop check, backed by the canonical filesystem
  sentinel in :mod:`textforensics.emergency_stop`. Call it before each
  new operation and between detector/probe calls. A stopped or
  cancelled operation raises instead of returning a result, so it can
  never become evidence of a clean run.
* :class:`CancellationToken` / :class:`ExecutionCancelled` — explicit
  in-flight cancellation. Cancelling a token does NOT terminate a
  detector already running in an executor thread (that is impossible
  to do safely); the running call completes, its result is discarded,
  and no further operation starts. Callers check the token between
  operations.
* :class:`CompletenessAccounting` — the shared probe-completeness type
  (CORE-07). It records selected/attempted/succeeded/abstained/failed
  counts for one prescribed probe set. Support requires the complete
  set with every probe succeeded; adding failures can never increase
  support. Worker D consumes this exact type in ``trust.py`` /
  ``validation.py`` — do not redefine it.
* The shared redacting error-handler contract (IF-07):
  :func:`register_redacting_handlers`, :func:`public_error_body`,
  :func:`error_status_for_exception`, :func:`diagnostic_record`.
  Public errors carry a stable generic message, a stable error code
  and a request ID, and never contain rejected input, raw provider
  bodies, tracebacks or filesystem paths. Private diagnostics are
  text-free (error type + request ID only) and correlated by request
  ID. Oversize text is 413, invalid type is 422, unexpected errors
  are 500.
"""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .emergency_stop import EmergencyStopError

__all__ = [
    "CancellationToken",
    "CompletenessAccounting",
    "ExecutionCancelled",
    "ExecutionPolicy",
    "ExecutionPolicyError",
    "RemoteConsentError",
    "assert_execution_allowed",
    "check_execution_allowed",
    "diagnostic_record",
    "error_status_for_exception",
    "is_execution_stopped",
    "new_request_id",
    "public_error_body",
    "public_message_for_status",
    "register_redacting_handlers",
]


# ---------------------------------------------------------------------------
# Policy errors
# ---------------------------------------------------------------------------


class ExecutionPolicyError(ValueError):
    """Raised when an execution policy is invalid or violated."""


class RemoteConsentError(ExecutionPolicyError):
    """Raised for missing, incomplete or unknown remote consent."""


class ExecutionCancelled(RuntimeError):
    """Raised when a cancelled operation is refused before it starts.

    Cancellation is cooperative: it is checked between operations. A
    detector already running in an executor thread is not forcibly
    terminated; its result is discarded and no further work starts.
    """


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


class CancellationToken:
    """Cooperative cancellation flag shared across an operation.

    Thread-safe. ``cancel()`` only marks the token; it never interrupts
    running code. Callers check it (via
    :func:`assert_execution_allowed` or :meth:`assert_not_cancelled`)
    before each new operation and between detector/probe calls.
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Request cancellation of the operation holding this token."""
        self._event.set()

    def is_cancelled(self) -> bool:
        """Return ``True`` once :meth:`cancel` has been called."""
        return self._event.is_set()

    def assert_not_cancelled(self) -> None:
        """Raise :class:`ExecutionCancelled` if cancellation was requested."""
        if self._event.is_set():
            raise ExecutionCancelled(
                "Operation was cancelled. No further detector work will start; "
                "any result produced after cancellation is discarded and is "
                "not evidence of a clean run."
            )


# ---------------------------------------------------------------------------
# Execution policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    """Validated command boundary for one detector operation.

    Default is local-only. Remote execution requires BOTH an explicit
    list of detector IDs (``remote_detector_ids``) AND explicit consent
    (``remote_consent=True``). Consent without IDs authorizes nothing;
    IDs without consent authorize nothing; consent for an ID that is
    not among the detectors selected for the operation is rejected by
    :meth:`resolve_against`.

    Byte limits, deadlines and retention are carried here so every
    surface enforces the same bounds; transports enforce the deadline
    by checking :meth:`remaining_seconds` between operations.
    """

    remote_detector_ids: frozenset[str] = frozenset()
    remote_consent: bool = False
    max_input_bytes: int | None = None
    max_output_bytes: int | None = None
    deadline_seconds: float | None = None
    retain_raw_text: bool = False
    cancellation: CancellationToken | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        ids = frozenset(str(item) for item in (self.remote_detector_ids or frozenset()))
        object.__setattr__(self, "remote_detector_ids", ids)
        self.validate()

    # -- constructors ----------------------------------------------------
    @classmethod
    def default_local_only(
        cls,
        *,
        max_input_bytes: int | None = None,
        max_output_bytes: int | None = None,
        deadline_seconds: float | None = None,
        retain_raw_text: bool = False,
        cancellation: CancellationToken | None = None,
    ) -> ExecutionPolicy:
        """Return the default policy: local detectors only, no consent."""
        return cls(
            remote_detector_ids=frozenset(),
            remote_consent=False,
            max_input_bytes=max_input_bytes,
            max_output_bytes=max_output_bytes,
            deadline_seconds=deadline_seconds,
            retain_raw_text=retain_raw_text,
            cancellation=cancellation,
        )

    @classmethod
    def with_remote_consent(
        cls,
        remote_detector_ids: Any,
        *,
        max_input_bytes: int | None = None,
        max_output_bytes: int | None = None,
        deadline_seconds: float | None = None,
        retain_raw_text: bool = False,
        cancellation: CancellationToken | None = None,
    ) -> ExecutionPolicy:
        """Return a policy authorizing exactly ``remote_detector_ids``."""
        return cls(
            remote_detector_ids=frozenset(str(item) for item in remote_detector_ids),
            remote_consent=True,
            max_input_bytes=max_input_bytes,
            max_output_bytes=max_output_bytes,
            deadline_seconds=deadline_seconds,
            retain_raw_text=retain_raw_text,
            cancellation=cancellation,
        )

    # -- validation ------------------------------------------------------
    def validate(self) -> None:
        """Raise :class:`RemoteConsentError`/:class:`ValueError` if invalid."""
        for detector_id in self.remote_detector_ids:
            if not detector_id.strip():
                raise RemoteConsentError("Remote detector IDs must be non-empty.")
        if self.remote_consent and not self.remote_detector_ids:
            raise RemoteConsentError(
                "Remote consent without remote detector IDs authorizes nothing; "
                "list the remote detector IDs explicitly."
            )
        if not self.remote_consent and self.remote_detector_ids:
            raise RemoteConsentError(
                "Remote detector IDs without explicit remote consent authorize "
                "nothing; set remote_consent to confirm outbound use."
            )
        for name, value in (
            ("max_input_bytes", self.max_input_bytes),
            ("max_output_bytes", self.max_output_bytes),
        ):
            if value is not None and (isinstance(value, bool) or value <= 0):
                raise ValueError(f"{name} must be a positive integer or null.")
        if self.deadline_seconds is not None and (
            isinstance(self.deadline_seconds, bool) or self.deadline_seconds <= 0
        ):
            raise ValueError("deadline_seconds must be a positive number or null.")

    def resolve_against(self, available_detector_ids: Any) -> ExecutionPolicy:
        """Return this policy, or raise if a consented ID is unavailable.

        A consented ID that is not among the detectors selected for the
        operation is a misconfiguration, not a silent no-op.
        """
        available = {str(item) for item in available_detector_ids}
        unknown = sorted(self.remote_detector_ids - available)
        if unknown:
            raise RemoteConsentError("Unknown remote detector ID(s): " + ", ".join(unknown) + ".")
        return self

    # -- authorization ---------------------------------------------------
    def allows_remote(self, detector_id: str) -> bool:
        """Return ``True`` iff this ID is explicitly consented for remote use."""
        return bool(self.remote_consent) and detector_id in self.remote_detector_ids

    def allows_detector(self, detector_id: str, execution: str) -> bool:
        """Return ``True`` iff a detector with this execution mode may run.

        ``"remote"`` requires explicit consent for the ID; ``"local"``
        and ``"unknown"`` (undeclared) may start, subject to the
        post-call refusal in :func:`detectors.execute_detector`, which
        discards a remote prediction from an adapter that only reveals
        its remoteness after running.
        """
        if execution == "remote":
            return self.allows_remote(detector_id)
        return True

    def remaining_seconds(self, started_monotonic: float) -> float | None:
        """Return seconds left on the deadline, or ``None`` if unbounded."""
        if self.deadline_seconds is None:
            return None
        return max(0.0, self.deadline_seconds - (time.monotonic() - started_monotonic))

    # -- serialization (provenance; never contains submitted text) --------
    def to_dict(self) -> dict[str, Any]:
        """Serialize the policy for provenance records (deterministic)."""
        return {
            "remote_detector_ids": sorted(self.remote_detector_ids),
            "remote_consent": bool(self.remote_consent),
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "deadline_seconds": self.deadline_seconds,
            "retain_raw_text": bool(self.retain_raw_text),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutionPolicy:
        """Rebuild a policy from :meth:`to_dict` output (validates)."""
        return cls(
            remote_detector_ids=frozenset(data.get("remote_detector_ids") or ()),
            remote_consent=bool(data.get("remote_consent", False)),
            max_input_bytes=data.get("max_input_bytes"),
            max_output_bytes=data.get("max_output_bytes"),
            deadline_seconds=data.get("deadline_seconds"),
            retain_raw_text=bool(data.get("retain_raw_text", False)),
        )


# ---------------------------------------------------------------------------
# Completeness accounting (CORE-07 shared type)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CompletenessAccounting:
    """Counts for one prescribed probe set (CORE-07).

    Semantics (frozen here for W2 consumers in ``trust.py`` /
    ``validation.py`` — do not redefine this type):

    * ``selected`` — probes in the prescribed set for this detector.
    * ``attempted`` — probes actually started (``<= selected``).
    * ``succeeded`` / ``abstained`` / ``failed`` — a partition of
      ``attempted``. ``succeeded`` means the probe returned a usable
      non-abstaining verdict; ``abstained`` means it returned a
      prediction with verdict ``abstain``; ``failed`` means the probe
      errored (no prediction).
    * ``is_complete`` — every prescribed probe was attempted and the
      three outcome counts partition the attempts.
    * ``support_eligible`` — the set is complete AND every prescribed
      probe succeeded (no failures, no abstentions). Partial
      measurements stay visible with their denominators (see
      :meth:`to_dict`); they are never promoted to support. Adding
      failures can never increase support.
    """

    selected: int
    attempted: int
    succeeded: int
    abstained: int
    failed: int

    def __post_init__(self) -> None:
        for name in ("selected", "attempted", "succeeded", "abstained", "failed"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer.")
        if self.attempted > self.selected:
            raise ValueError("attempted cannot exceed selected.")
        if self.succeeded + self.abstained + self.failed != self.attempted:
            raise ValueError("succeeded + abstained + failed must equal attempted.")

    @property
    def is_complete(self) -> bool:
        """True iff every prescribed probe was attempted."""
        return self.attempted == self.selected

    @property
    def support_eligible(self) -> bool:
        """True iff the complete set ran with every probe succeeding."""
        return self.is_complete and self.failed == 0 and self.succeeded == self.selected

    def to_dict(self) -> dict[str, Any]:
        """Serialize counts plus the derived completeness verdicts."""
        return {
            "selected": self.selected,
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "abstained": self.abstained,
            "failed": self.failed,
            "is_complete": self.is_complete,
            "support_eligible": self.support_eligible,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompletenessAccounting:
        """Rebuild from :meth:`to_dict` output (derived keys ignored)."""
        return cls(
            selected=int(data["selected"]),
            attempted=int(data["attempted"]),
            succeeded=int(data["succeeded"]),
            abstained=int(data["abstained"]),
            failed=int(data["failed"]),
        )


# ---------------------------------------------------------------------------
# Shared stop check
# ---------------------------------------------------------------------------


def is_execution_stopped() -> bool:
    """Return ``True`` when the canonical emergency stop is active.

    This is the ONE stop predicate every surface uses; it reads the
    filesystem sentinel via :mod:`textforensics.emergency_stop` on
    every call (no cached state) and fails closed on malformed
    configuration. The sentinel check is resolved at call time so
    tests and embedders patching the sentinel see the same result.
    """
    from .emergency_stop import check_emergency_stop

    return check_emergency_stop()


def assert_execution_allowed(
    policy: ExecutionPolicy | None = None,
    *,
    cancellation: CancellationToken | None = None,
) -> None:
    """Raise if execution must not start/continue.

    Checks, in order: (1) the canonical emergency stop — raises
    :class:`EmergencyStopError`; (2) cooperative cancellation — raises
    :class:`ExecutionCancelled`; (3) policy validity — raises
    :class:`ExecutionPolicyError`. Call this before each new operation
    and between detector/probe calls. The raised error is terminal:
    callers must propagate it, never convert it into an ordinary
    detector failure or a clean-run record.
    """
    if policy is None:
        policy = ExecutionPolicy.default_local_only()
    else:
        policy.validate()
    from .emergency_stop import check_emergency_stop

    if check_emergency_stop():
        raise EmergencyStopError(
            "Emergency stop is active. All analysis and API calls are "
            "blocked until the sentinel is deactivated."
        )
    token = cancellation if cancellation is not None else policy.cancellation
    if token is not None:
        token.assert_not_cancelled()


def check_execution_allowed(
    policy: ExecutionPolicy | None = None,
    *,
    cancellation: CancellationToken | None = None,
) -> bool:
    """Non-raising form of :func:`assert_execution_allowed`."""
    try:
        assert_execution_allowed(policy, cancellation=cancellation)
    except (EmergencyStopError, ExecutionCancelled, ExecutionPolicyError):
        return False
    return True


# ---------------------------------------------------------------------------
# Shared redacting error-handler contract (IF-07)
# ---------------------------------------------------------------------------

_ERROR_MESSAGES: dict[int, str] = {
    400: "Invalid request.",
    401: "Authentication required.",
    403: "Forbidden.",
    404: "Not found.",
    413: "Invalid text input.",
    422: "Request validation failed.",
    429: "Too many requests.",
    500: "Internal error.",
    503: "Emergency stop is active.",
}

_ERROR_CODES: dict[int, str] = {
    400: "invalid_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    413: "invalid_text_input",
    422: "invalid_request",
    429: "rate_limited",
    500: "internal_error",
    503: "emergency_stop_active",
}

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def new_request_id() -> str:
    """Return a fresh opaque request ID for error correlation."""
    return uuid.uuid4().hex


def public_message_for_status(status_code: int) -> str:
    """Return the stable generic public message for an HTTP status."""
    return _ERROR_MESSAGES.get(status_code, "Request failed.")


def public_error_body(
    status_code: int,
    *,
    code: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Build a public error body.

    Contains only a stable generic message, a stable error code and a
    request ID. It never contains rejected input, exception text, raw
    provider bodies, tracebacks or filesystem paths.
    """
    return {
        "detail": public_message_for_status(status_code),
        "error_code": code or _ERROR_CODES.get(status_code, "request_failed"),
        "request_id": request_id or new_request_id(),
    }


def error_status_for_exception(exc: BaseException) -> int:
    """Map an exception to its public HTTP status.

    Oversize text is 413, invalid type/value is 422, an active
    emergency stop is 503, anything unexpected is 500. ``HTTPException``
    keeps its own status. Never inspects exception text beyond the
    fail-closed ``exceeds`` marker used by the input validator. FastAPI
    is imported lazily so this module stays usable in a core-only
    install (where no ``HTTPException`` can exist).
    """
    try:
        from fastapi import HTTPException as _FastAPIHTTPException
    except ImportError:  # pragma: no cover - core-only install
        _FastAPIHTTPException = None  # type: ignore[assignment]

    if _FastAPIHTTPException is not None and isinstance(exc, _FastAPIHTTPException):
        return int(exc.status_code)
    if isinstance(exc, EmergencyStopError):
        return 503
    if isinstance(exc, (RemoteConsentError, ExecutionPolicyError)):
        return 422
    if isinstance(exc, ValueError):
        return 413 if "exceeds" in str(exc) else 422
    return 500


def diagnostic_record(exc: BaseException, *, request_id: str) -> dict[str, Any]:
    """Build a text-free private diagnostic record for one failure.

    Contains only the request ID and the exception type — never the
    exception message, which may echo submitted text or provider
    bodies. Log this record; do not put it in a public response.
    """
    return {"request_id": request_id, "error_type": type(exc).__name__}


def _request_id_for(request: Any) -> str:
    header = request.headers.get("x-request-id") if request is not None else None
    if isinstance(header, str) and _REQUEST_ID_PATTERN.match(header):
        return header
    return new_request_id()


def register_redacting_handlers(app: Any) -> Any:
    """Register the shared redacting handlers on a FastAPI application.

    Installs handlers for request-validation errors, ``HTTPException``
    and unexpected exceptions, shared by both HTTP applications (the
    ``/v1/*`` API and the web UI). Rules:

    * Request-validation failures are 422. Pydantic's error entries
      are sanitized: only the stable, input-free fields ``loc``,
      ``msg`` and ``type`` are kept — the ``input`` and ``ctx``
      fields are dropped, because they echo the rejected value (this
      is the audit's ``api_validation_echo`` vector: a list sent
      where a string was expected came back inside the 422 body).
      The sanitized list keeps the public contract stable
      (``"Field required"``, ``"json_invalid"``) without the value.
    * ``HTTPException`` keeps its status code AND its ``detail``
      verbatim — string or ``dict`` — because every string detail
      raised in these applications is a server-constructed constant
      (for example ``"Invalid text input."``); the live-host smoke
      tests pin that exact body. Rule for handlers: never raise
      ``HTTPException`` with a detail built from caller input or a
      caught exception. Correlation for these errors is via the
      ``x-request-id`` header only, so the body stays byte-identical
      to the pre-handler contract.
    * Unexpected exceptions are 500 with a stable generic body and no
      traceback or path disclosure.
    * Every public error carries an ``x-request-id`` header for
      correlation with the text-free private diagnostic record (see
      :func:`diagnostic_record`); validation and unexpected errors
      also carry a ``request_id`` field in the body.

    Returns the application, for chaining.
    """
    from fastapi import HTTPException as _FastAPIHTTPException
    from fastapi.exceptions import RequestValidationError as _ValidationError
    from fastapi.responses import JSONResponse as _JSONResponse

    async def _validation_handler(request: Any, exc: Any) -> Any:
        request_id = _request_id_for(request)
        # Sanitize each pydantic error entry: keep only the stable,
        # input-free fields. ``input``/``ctx`` echo the rejected value.
        sanitized: list[dict[str, Any]] = []
        for error in exc.errors():
            if not isinstance(error, dict):
                continue
            entry: dict[str, Any] = {}
            if "loc" in error:
                entry["loc"] = list(error["loc"])
            if "msg" in error:
                entry["msg"] = error["msg"]
            if "type" in error:
                entry["type"] = error["type"]
            sanitized.append(entry)
        return _JSONResponse(
            status_code=422,
            content={
                "detail": sanitized,
                "error_code": "invalid_request",
                "request_id": request_id,
            },
            headers={"x-request-id": request_id},
        )

    async def _http_exception_handler(request: Any, exc: Any) -> Any:
        request_id = _request_id_for(request)
        status = int(exc.status_code)
        # Detail preserved verbatim (see docstring): the body stays
        # byte-identical to the pre-handler public contract; the
        # request ID travels in the header only.
        return _JSONResponse(
            status_code=status,
            content={"detail": exc.detail},
            headers={"x-request-id": request_id},
        )

    async def _unhandled_handler(request: Any, exc: Any) -> Any:
        request_id = _request_id_for(request)
        return _JSONResponse(
            status_code=500,
            content=public_error_body(500, request_id=request_id),
            headers={"x-request-id": request_id},
        )

    app.add_exception_handler(_ValidationError, _validation_handler)
    app.add_exception_handler(_FastAPIHTTPException, _http_exception_handler)
    app.add_exception_handler(Exception, _unhandled_handler)
    return app
