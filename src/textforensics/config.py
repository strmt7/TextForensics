from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

_ENV_PREFIX = "TEXTFORENSICS_"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(_ENV_PREFIX + name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{_ENV_PREFIX}{name} must be a boolean value.")


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(_ENV_PREFIX + name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{_ENV_PREFIX}{name} must be an integer.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(
            f"{_ENV_PREFIX}{name} must be between {minimum} and {maximum}."
        )
    return value


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized in {"localhost", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(normalized.strip("[]")).is_loopback
    except ValueError:
        return False


def is_unspecified_host(host: str) -> bool:
    """Return True when the host means "every interface" (e.g. 0.0.0.0 or ::).

    Wildcard binds cannot be opened directly in a browser, so callers use
    this to substitute a concrete loopback address for display purposes.
    """
    normalized = host.strip().lower().strip("[]")
    if normalized == "*":
        return True
    try:
        return ipaddress.ip_address(normalized).is_unspecified
    except ValueError:
        return False


def ensure_bind_allowed(host: str, *, allow_remote: bool) -> None:
    if not is_loopback_host(host) and not allow_remote:
        raise ValueError(
            "Refusing to bind a network-visible interface without explicit opt-in. "
            "Pass --allow-remote or set TEXTFORENSICS_ALLOW_REMOTE=1."
        )


@dataclass(frozen=True, slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8765
    max_input_bytes: int = 2_000_000
    allow_remote: bool = False
    access_log: bool = False
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> Settings:
        defaults = cls()
        host = os.getenv(_ENV_PREFIX + "HOST", defaults.host).strip()
        host = host or defaults.host
        port = _env_int(
            "PORT",
            defaults.port,
            minimum=1,
            maximum=65535,
        )
        max_input_bytes = _env_int(
            "MAX_INPUT_BYTES",
            defaults.max_input_bytes,
            minimum=1_024,
            maximum=100_000_000,
        )
        allow_remote = _env_bool(
            "ALLOW_REMOTE",
            defaults.allow_remote,
        )
        access_log = _env_bool(
            "ACCESS_LOG",
            defaults.access_log,
        )
        log_level = os.getenv(
            _ENV_PREFIX + "LOG_LEVEL",
            defaults.log_level,
        ).strip().upper()
        if log_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError(
                f"{_ENV_PREFIX}LOG_LEVEL must be one of "
                "CRITICAL, ERROR, WARNING, INFO, DEBUG."
            )
        return cls(
            host=host,
            port=port,
            max_input_bytes=max_input_bytes,
            allow_remote=allow_remote,
            access_log=access_log,
            log_level=log_level,
        )


def validate_text_input(
    text: str,
    *,
    max_input_bytes: int,
) -> str:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Text must be a non-empty string.")
    encoded_size = len(text.encode("utf-8"))
    if encoded_size > max_input_bytes:
        raise ValueError(
            f"Text exceeds the configured input limit of "
            f"{max_input_bytes} bytes."
        )
    return text


def read_text_file(path: str | os.PathLike[str], *, max_input_bytes: int) -> str:
    from pathlib import Path

    target = Path(path)
    size = target.stat().st_size
    if size > max_input_bytes:
        raise ValueError(
            f"File exceeds the configured input limit of {max_input_bytes} bytes."
        )
    return validate_text_input(
        target.read_text(encoding="utf-8"),
        max_input_bytes=max_input_bytes,
    )
