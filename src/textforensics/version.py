from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


def get_version() -> str:
    """Return the installed package version without duplicating it in source code."""
    try:
        return version("textforensics")
    except PackageNotFoundError:
        return "0+unknown"
