"""Exit code constants as a product contract.

These codes form a stable API for shell/CI consumers. They must not be
reassigned without a deliberate schema bump.
"""

from __future__ import annotations

EXIT_OK = 0  # analysis complete, Trust Map sufficient
EXIT_DOWNGRADED = 1  # analysis complete, coverage partial/insufficient
EXIT_INCOMPLETE = 2  # abstained detectors, missing calibration
EXIT_ERROR = 3  # configuration/runtime error

_EXIT_NAMES: dict[int, str] = {
    EXIT_OK: "EXIT_OK",
    EXIT_DOWNGRADED: "EXIT_DOWNGRADED",
    EXIT_INCOMPLETE: "EXIT_INCOMPLETE",
    EXIT_ERROR: "EXIT_ERROR",
}

_EXIT_DESCRIPTIONS: dict[int, str] = {
    EXIT_OK: "analysis complete, Trust Map sufficient",
    EXIT_DOWNGRADED: "analysis complete, coverage partial/insufficient",
    EXIT_INCOMPLETE: "abstained detectors, missing calibration",
    EXIT_ERROR: "configuration/runtime error",
}


def exit_code_name(code: int) -> str:
    """Return the canonical name for an exit code, or a fallback string."""
    return _EXIT_NAMES.get(code, f"UNKNOWN_EXIT_{code}")


def exit_code_description(code: int) -> str:
    """Return the human-readable description for an exit code."""
    return _EXIT_DESCRIPTIONS.get(code, "unknown exit code")


def validate_exit_code(code: int) -> int:
    """Validate that *code* is a known exit code; raise ValueError otherwise."""
    if code not in _EXIT_NAMES:
        raise ValueError(f"Unknown exit code: {code!r}")
    return code


__all__ = [
    "EXIT_OK",
    "EXIT_DOWNGRADED",
    "EXIT_INCOMPLETE",
    "EXIT_ERROR",
    "exit_code_name",
    "exit_code_description",
    "validate_exit_code",
]
