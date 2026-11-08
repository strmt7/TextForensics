# Installation

TextForensics is designed to avoid coupling to one package manager, operating system, container runtime, cloud provider, or orchestration platform.

## Requirements

Core:
- Python 3.11–3.15
- no mandatory runtime dependencies
- curl (recommended system tool, not a Python dependency): large
  benchmark downloads (DetectRL-X, ~879 MB) fall back to curl when
  the stdlib downloader cannot ride out an egress stall. curl ships
  with macOS, Windows 10+, and most Linux distributions; without it
  the download fails with a clear error naming curl instead of
  silently succeeding.

Optional surfaces:
- API server: `textforensics[api]`
- MCP server: `textforensics[mcp]`
- both: `textforensics[all]`

## pip / virtualenv

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -U pip
python -m pip install .
textforensics --version
```

For API support:

```bash
python -m pip install ".[api]"
textforensics serve
```

## pipx

After a published package is available:

```bash
pipx install textforensics
```

For optional extras, use the package-manager syntax supported by your pipx version.

## uv

```bash
uv venv
uv pip install -e .
uv run textforensics --version
```

TextForensics does not require uv; this is only an alternative installer.

## Docker

```bash
docker build -t textforensics:local .
docker run --rm -p 127.0.0.1:8765:8765 textforensics:local
```

Then check:

```text
http://127.0.0.1:8765/healthz
```

The image runs `textforensics serve` (see `Dockerfile`: `CMD
["serve"]`), so it serves the JSON API only — the browser UI is not
available from the container (`GET /` returns 404; the API has no
root route). To run the browser UI, use `textforensics web` on a
bare server (see below) instead of the container image.

The image:
- runs as an unprivileged numeric UID/GID;
- contains only the API runtime, not build tools;
- has a health check;
- disables access logging by default;
- uses environment variables rather than cloud-specific configuration.

> **Warning — do not publish the container port on a network interface.**
> The API has no authentication. The image binds `0.0.0.0` *inside* its
> own network namespace (required: Docker forwards published ports to
> the container IP, so a loopback bind inside the container would refuse
> connections). Exposure is controlled on the host side: always publish
> loopback-only (`-p 127.0.0.1:8765:8765` as above) and never `-p
> 8765:8765`. The bare-server defaults (loopback, port 8765) are unchanged.

## Podman

The same OCI image is intentionally compatible with rootless Podman:

```bash
podman build -t textforensics:local .
podman run --rm -p 127.0.0.1:8765:8765 textforensics:local
```

No Docker-specific daemon API is used by the application.

## Compose

```bash
docker compose up --build
```

or a compatible Compose implementation.

The supplied `compose.yaml` binds to loopback by default and uses a read-only container filesystem.

## Bare server / VM

Install the API extra into a dedicated virtual environment, then use your operating system's service manager to run:

```bash
textforensics serve --host 127.0.0.1
```

Place TLS/authentication/reverse-proxy policy in front of the process if exposing it beyond the local machine.

To bind a non-loopback address, TextForensics requires explicit consent:

```bash
textforensics serve --host 0.0.0.0 --allow-remote
```

This guard reduces accidental exposure; it is not authentication.

## Browser UI (bare server / VM)

`textforensics serve` is API-only: it serves no HTML at `/` (that
route returns 404). The browser UI is a separate command,
`textforensics web` (equivalently `textforensics web-fastapi` or the
`textforensics-web` console script), which serves the FastAPI UI
(including its `/api/*` endpoints) as its own process:

```bash
textforensics web --host 127.0.0.1
```

It binds `127.0.0.1:8765` by default and opens the browser
automatically; pass `--no-browser` to skip that. The same
non-loopback guard applies: `--host 0.0.0.0` without
`--allow-remote` is refused (exit 3).

## Kubernetes / Nomad / ECS / other schedulers

Use the OCI image and override environment variables. The application has no dependency on Kubernetes APIs, service meshes, cloud metadata endpoints, or vendor SDKs.

Health endpoints:
- `GET /healthz`
- `GET /readyz`

Container port: `8765` by default.

## Configuration

Environment variables:

| Variable | Default | Meaning |
|---|---:|---|
| `TEXTFORENSICS_HOST` | `127.0.0.1` | Bind host |
| `TEXTFORENSICS_PORT` | `8765` | Bind port |
| `TEXTFORENSICS_MAX_INPUT_BYTES` | `2000000` | Maximum submitted text size |
| `TEXTFORENSICS_ALLOW_REMOTE` | `0` | Permit non-loopback bind |
| `TEXTFORENSICS_ACCESS_LOG` | `0` | Uvicorn access log |
| `TEXTFORENSICS_LOG_LEVEL` | `INFO` | Process log level |

Invalid configuration fails fast.

## Offline environments

The core package has no mandatory third-party runtime dependency. Build/download wheels for optional extras in a connected environment, transfer the wheelhouse, then install with:

```bash
python -m pip install --no-index --find-links=/path/to/wheels textforensics
```

Detector model adapters may have their own model-weight and dependency requirements. Each adapter must document those separately.
