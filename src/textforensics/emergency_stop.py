"""Emergency stop sentinel for TextForensics.

Out-of-band, filesystem-based emergency stop mechanism following the
rejection-rejector pattern. The sentinel is independent of application
state and configured via the ``TEXTFORENSICS_EMERGENCY_STOP`` environment
variable.

Fail-closed semantics:
- If the env var is unset/empty, emergency stop is **not** active.
- If the env var points to a malformed path, emergency stop is treated as
  **active** (fail-closed).
- If the sentinel file exists at the configured path, emergency stop is
  **active**.
- If the sentinel file does not exist, emergency stop is **not** active.

Activation and deactivation are explicit file-creation / file-removal
operations. There is no implicit activation path.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_VAR = "TEXTFORENSICS_EMERGENCY_STOP"

# Default sentinel path used when the env var is unset but a caller
# explicitly configures a path via ``EmergencyStopSentinel.configure``.
_DEFAULT_SENTINEL = ".textforensics-emergency-stop"


class EmergencyStopError(RuntimeError):
    """Raised when an emergency stop is active and the caller is blocked."""


def _resolve_sentinel_path(path: str | os.PathLike[str] | None) -> Path | None:
    """Resolve a sentinel path string to a ``Path``.

    Returns ``None`` when no path is configured. Raises ``ValueError``
    when the configured path is malformed (e.g. empty string, null
    byte, or unresolvable).
    """
    if path is None:
        return None
    raw = os.fspath(path) if isinstance(path, os.PathLike) else str(path)
    if not raw:
        raise ValueError("emergency stop path must not be empty")
    if "\x00" in raw:
        raise ValueError("emergency stop path contains null byte")
    return Path(raw)


def check_emergency_stop(
    path: str | os.PathLike[str] | None = None,
) -> bool:
    """Check whether the emergency stop sentinel is active.

    Resolution order:
    1. Explicit ``path`` argument, if provided.
    2. ``TEXTFORENSICS_EMERGENCY_STOP`` environment variable.
    3. No configuration -> returns ``False`` (stop not active).

    Fail-closed behaviour:
    - Malformed path (empty, null byte) -> returns ``True`` (STOP).
    - Path resolves but file exists -> returns ``True`` (STOP).
    - Path resolves but file does not exist -> returns ``False``.
    """
    if path is None:
        path = os.environ.get(ENV_VAR)
        if not path:
            return False

    try:
        sentinel = _resolve_sentinel_path(path)
    except ValueError:
        # Malformed configuration: fail-closed.
        return True

    if sentinel is None:
        return False

    try:
        return sentinel.exists()
    except OSError:
        # If we cannot stat the path, treat as active (fail-closed).
        return True


class EmergencyStopSentinel:
    """Programmatic interface for the emergency stop sentinel.

    The sentinel is configured either via the environment variable
    ``TEXTFORENSICS_EMERGENCY_STOP`` or by calling ``configure``.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self._path = path

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    def configure(self, path: str | os.PathLike[str]) -> None:
        """Set the sentinel file path.

        Malformed paths are stored as-is and cause ``is_active`` to
        return ``True`` (fail-closed). This keeps the emergency stop
        mechanism robust even under misconfiguration.
        """
        self._path = path

    def _resolve(self) -> Path | None:
        """Resolve the effective sentinel path.

        Returns ``None`` when no path is configured (env var unset and
        no explicit configuration).
        """
        if self._path is not None:
            return _resolve_sentinel_path(self._path)
        env = os.environ.get(ENV_VAR)
        if not env:
            return None
        return _resolve_sentinel_path(env)

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------
    def is_active(self) -> bool:
        """Return ``True`` when the emergency stop is active.

        Fail-closed: a malformed configured path is treated as active.
        """
        try:
            sentinel = self._resolve()
        except ValueError:
            return True
        if sentinel is None:
            return False
        try:
            return sentinel.exists()
        except OSError:
            return True

    # ------------------------------------------------------------------
    # Explicit activation / deactivation
    # ------------------------------------------------------------------
    def activate(self) -> Path:
        """Create the sentinel file and return its path.

        Raises ``ValueError`` if no path is configured.
        """
        sentinel = self._resolve()
        if sentinel is None:
            raise ValueError(
                "emergency stop path is not configured; set "
                f"{ENV_VAR} or call configure() before activate()"
            )
        sentinel.parent.mkdir(parents=True, exist_ok=True)
        sentinel.write_text("emergency stop\n", encoding="utf-8")
        return sentinel

    def deactivate(self) -> bool:
        """Remove the sentinel file if present.

        Returns ``True`` if the file was removed, ``False`` if it did not
        exist. Raises ``ValueError`` if no path is configured.
        """
        sentinel = self._resolve()
        if sentinel is None:
            raise ValueError(
                "emergency stop path is not configured; set "
                f"{ENV_VAR} or call configure() before deactivate()"
            )
        if sentinel.exists():
            sentinel.unlink()
            return True
        return False

    # ------------------------------------------------------------------
    # Guard helper
    # ------------------------------------------------------------------
    def assert_not_stopped(self) -> None:
        """Raise :class:`EmergencyStopError` if the stop is active."""
        if self.is_active():
            raise EmergencyStopError(
                "Emergency stop is active. All analysis and API calls are "
                "blocked until the sentinel is deactivated."
            )


# ----------------------------------------------------------------------
# Module-level convenience singleton
# ----------------------------------------------------------------------
_sentinel: EmergencyStopSentinel | None = None


def get_sentinel() -> EmergencyStopSentinel:
    """Return a process-wide :class:`EmergencyStopSentinel` instance."""
    global _sentinel
    if _sentinel is None:
        _sentinel = EmergencyStopSentinel()
    return _sentinel


def assert_not_stopped() -> None:
    """Module-level guard: raise if emergency stop is active."""
    get_sentinel().assert_not_stopped()
