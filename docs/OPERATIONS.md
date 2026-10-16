# Operations guide

## Deployment model

TextForensics is stateless for ordinary analyze/report API calls. Horizontal scaling is therefore handled outside the application with standard process/container replicas.

The application does not require:
- a database,
- a message broker,
- object storage,
- cloud metadata,
- Kubernetes,
- Docker,
- systemd,
- or a specific reverse proxy.

Provenance ledgers and exported case files are user-controlled filesystem artifacts.

## Network safety

The CLI/API/browser UI bind to loopback by default.

A non-loopback bind requires:
- `--allow-remote`, or
- `TEXTFORENSICS_ALLOW_REMOTE=1`.

That flag is an exposure acknowledgement, **not authentication**.

For shared or public deployments, put an authentication/TLS layer in front of TextForensics and enforce request limits there as well.

## Health checks

- `GET /healthz`: process is responding.
- `GET /readyz`: application initialization is complete.

These endpoints intentionally do not analyze text or exercise remote detector providers.

## Privacy

Core behavior:
- no telemetry;
- no raw input text persisted;
- no raw input in forensic bundles/case files;
- remote adapters are opt-in;
- plugin failures suppress raw exception text because providers may echo submitted text.

Infrastructure logs should be reviewed separately; a reverse proxy can log URLs, headers or request sizes depending on configuration.

## Input limits

Default maximum submitted text size is 2,000,000 UTF-8 bytes.

Set:
`TEXTFORENSICS_MAX_INPUT_BYTES`

The application validates this at CLI/API/MCP/browser-entry boundaries. Upstream proxies should use equal or stricter limits.

## Access logs

Uvicorn access logs are disabled by default. They do not normally contain request bodies, but disabling them minimizes metadata exposure.

Enable only when operationally required:

```bash
textforensics serve --access-log
```

## Reverse proxy

A reverse proxy can provide:
- TLS termination;
- authentication/SSO;
- IP allowlists;
- rate limiting;
- body-size enforcement;
- audit policy.

TextForensics deliberately does not hard-code Nginx, Traefik, Caddy, Envoy, a service mesh, or a cloud load balancer.

## Scaling

The built-in heuristic is CPU-light. Future model-backed detectors may be CPU/GPU intensive.

Scale based on adapter characteristics:
- isolate GPU-backed adapters if needed;
- limit concurrency to available accelerator memory;
- use queueing at the platform layer if requests become long-running;
- do not share a mutable global detector object unless the adapter documents thread safety.

The bundled Desklib and Qwen-RAI adapters lazy-load pinned model weights and serialize inference per adapter instance. The Desklib weight file is roughly 1.7 GB; the RAI pair is roughly 2 GB of published weights. Budget additional RAM/VRAM for activations and framework overhead.

## Filesystem

The container image supports a read-only root filesystem.

Writable paths are only needed when a user explicitly asks to create:
- provenance ledgers;
- benchmark/calibration artifacts;
- case files.

For API-only deployments using only the dependency-free baseline, no persistent application data directory is required.

Model-backed containers need a writable model-cache mount. Keep the root filesystem read-only and mount only the cache path, for example `/models/hf`. Set the adapter-specific cache variables to that location. The supplied `compose.models.yaml` demonstrates this pattern.

## Backup and restore

There is no internal database to back up.

Back up user-chosen artifact locations if you rely on:
- provenance ledgers;
- calibration artifacts;
- benchmark run manifests;
- case files;
- future observatory snapshots.

Integrity hashes help detect modification but are not a substitute for backups.

## Upgrade policy

Before upgrading:
1. read `CHANGELOG.md`;
2. check schema/version changes;
3. rebuild/reinstall the package or image;
4. run `textforensics --version`;
5. check `/healthz`;
6. revalidate detector calibration when detector/model/provider versions changed.

Never assume old calibration remains valid across detector changes.

## Troubleshooting

### Non-loopback bind refused
Enable it explicitly only if intended:
`TEXTFORENSICS_ALLOW_REMOTE=1`

### API extra missing
Install:
`python -m pip install "textforensics[api]"`

### MCP extra missing
Install:
`python -m pip install "textforensics[mcp]"`

### Plugin missing from detector list
Run:
`textforensics detectors --health`

Plugin load errors are reported without exposing raw exception messages that could contain document text.


## Model-backed OCI deployments

The default image installs only the API extra.

Build an image with model runtime dependencies:

```bash
docker build \
  --build-arg TEXTFORENSICS_EXTRAS="api,ml" \
  -t textforensics:ml .
```

Model weights are still downloaded separately at first use. Mount a persistent cache rather than baking mutable caches into the image. This keeps code/runtime layers reproducible and model artifacts independently governable.

For air-gapped production, populate and verify the cache before deployment, then enable the adapters' offline modes.
