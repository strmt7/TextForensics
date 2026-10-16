# Installation

TextForensics is designed to avoid coupling to one package manager, operating system, container runtime, cloud provider, or orchestration platform.

## Requirements

Core:
- Python 3.11–3.15
- no mandatory runtime dependencies

Optional surfaces:
- API server: `textforensics[api]`
- MCP server: `textforensics[mcp]`
- both lightweight surfaces: `textforensics[all]`
- pinned Desklib supervised detector: `textforensics[desklib]`
- Qwen Raw Alignment Imprint detector: `textforensics[rai]`
- shared ML dependencies for both detector adapters: `textforensics[ml]`

The `all` extra intentionally excludes heavyweight ML runtimes and model weights.

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


## Local model adapters

### Desklib supervised detector

```bash
python -m pip install ".[desklib]"
textforensics report \
  --detector desklib/ai-text-detector-v1.01 \
  --file document.txt
```

The code pins the model to an immutable revision. The approximately 1.7 GB model-weight file downloads on first use unless already present in the configured cache.

Useful variables:

```text
TEXTFORENSICS_DESKLIB_DEVICE=auto
TEXTFORENSICS_DESKLIB_CACHE_DIR=/path/to/cache
TEXTFORENSICS_DESKLIB_OFFLINE=0
TEXTFORENSICS_DESKLIB_MAX_LENGTH=768
TEXTFORENSICS_DESKLIB_MIN_WORDS=80
TEXTFORENSICS_DESKLIB_THRESHOLD=0.5
```

The native sigmoid score is recorded as a detector score, not automatically promoted to a TextForensics-calibrated authorship probability.

### Raw Alignment Imprint detector

```bash
python -m pip install ".[rai]"
textforensics report \
  --detector textforensics/qwen2.5-0.5b-rai \
  --file document.txt
```

This adapter uses pinned Apache-2.0 Qwen2.5-0.5B base and instruction-tuned model revisions. It computes the raw aligned-minus-base mean token log-likelihood statistic. It deliberately abstains from a categorical verdict until a separately validated threshold is available.

Useful variables:

```text
TEXTFORENSICS_RAI_DEVICE=auto
TEXTFORENSICS_RAI_CACHE_DIR=/path/to/cache
TEXTFORENSICS_RAI_OFFLINE=0
TEXTFORENSICS_RAI_MAX_LENGTH=768
TEXTFORENSICS_RAI_MIN_WORDS=80
```

### Select detectors consistently across interfaces

```bash
export TEXTFORENSICS_DETECTORS="desklib/ai-text-detector-v1.01,textforensics/qwen2.5-0.5b-rai"
textforensics report --file document.txt
textforensics serve
textforensics-mcp
```

The same setting is honored by the CLI report/case paths, ASGI API, MCP server, and local browser server.

### Python 3.15 and PyTorch

The dependency-free core and lightweight surfaces support Python 3.15. As of October 2026, PyTorch 2.14 provides Python 3.15 binaries through PyTorch's official wheel index rather than ordinary PyPI. On Python 3.15, install PyTorch according to the current official PyTorch installation instructions first, then install the `desklib`, `rai`, or `ml` TextForensics extra.

### Offline model operation

Pre-populate the Hugging Face cache in a connected environment, transfer that cache according to your organization's artifact policy, set the adapter cache directory, and enable:

```text
TEXTFORENSICS_DESKLIB_OFFLINE=1
TEXTFORENSICS_RAI_OFFLINE=1
```

Pinned revisions and recorded model-weight SHA-256 values make the expected model artifacts explicit.

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
| `TEXTFORENSICS_DETECTORS` | empty | Comma-separated explicit detector IDs |

Invalid configuration fails fast.

## Offline environments

The core package has no mandatory third-party runtime dependency. Build/download wheels for optional extras in a connected environment, transfer the wheelhouse, then install with:

```bash
python -m pip install --no-index --find-links=/path/to/wheels textforensics
```

For offline ML deployments, transfer both the Python wheelhouse and the separately cached pinned model snapshots. See [Model adapters](MODELS.md).
