from __future__ import annotations

from .config import Settings, ensure_bind_allowed


def serve_api(settings: Settings | None = None) -> None:
    settings = settings or Settings.from_env()
    ensure_bind_allowed(settings.host, allow_remote=settings.allow_remote)

    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Install API support with: pip install 'textforensics[api]'"
        ) from exc

    from .api import create_app

    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        access_log=settings.access_log,
        log_level=settings.log_level.lower(),
    )


def main() -> None:  # pragma: no cover - integration entry point
    serve_api()


if __name__ == "__main__":
    main()
