# Installation

TextForensics is designed to avoid coupling to one package manager, operating system, container runtime, cloud provider, or orchestration platform.

## Requirements

Core:
- Python 3.11–3.15
- no mandatory runtime dependencies

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

The image:
- runs as an unprivileged numeric UID/GID;
- contains only the API runtime, not build tools;
- has a health check;
- disables access logging by default;
- uses environment variables rather than cloud-specific configuration.

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
