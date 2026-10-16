# TextForensics

## AI-text detection, audited

TextForensics is a **local-first reliability and forensic layer for AI-text detectors**. It preserves what each detector actually reports, keeps score semantics explicit, exposes disagreement and failures, checks basic stability, and asks the more important question:

> **How well does the available validation evidence cover this exact text and detector configuration?**

The project is deliberately different from a single "AI percentage" and from a rewrite-until-a-detector-passes loop.

> **Status: pre-1.0 alpha.** The platform/runtime has a tested CLI, browser UI, API, MCP surface, detector protocol, Trust Map, case artifacts, packaging, and OCI deployment. The built-in detector is a transparent development baseline. **TextForensics does not yet claim parity with leading commercial AI-text detectors.** See [Commercial readiness](docs/COMMERCIAL_READINESS.md).

## Why TextForensics

AI-text detector results can vary with:
- detector/model version;
- language and genre;
- document length;
- generator/model family;
- human revision or mixed-origin writing;
- score calibration and decision threshold;
- provider/model drift over time.

TextForensics therefore keeps these evidence classes separate:

1. **Detector observations** — native scores, verdicts, versions, method families, failures.
2. **Validation evidence** — where a detector/version has actually been benchmarked.
3. **Applicability and stability** — whether that evidence covers the current input.
4. **Process provenance** — draft/history evidence, kept separate from linguistic inference.

A detector score is not automatically a probability. Agreement is not independence. Text-only evidence is not proof of authorship.

## Current capabilities

### TFDP/1 detector protocol

Detector adapters expose explicit fields for:
- detector/model identity and version;
- methodological family;
- local vs remote execution;
- native score and **score semantics**;
- verdict: `ai_like`, `human_like`, or `abstain`;
- threshold when defined;
- calibrated probability only with calibration provenance;
- declared language/length limits;
- warnings, evidence, and runtime metadata.

Malformed plugin outputs are rejected. Plugin-loading failures are visible through health metadata instead of being silently swallowed.

See [SPEC.md](SPEC.md).

### Trust Map

Reports include a conservative qualitative `textforensics.trust-map/v1`.

Current dimensions include:
- language coverage;
- text-length coverage;
- domain/genre coverage;
- editing/revision evidence;
- nearest-slice human false-positive evidence;
- detector-family diversity;
- benign representation stability;
- detector/provider temporal stability.

States are:
- `supported`
- `partial`
- `unknown`
- `out_of_scope`

The overall state is `strong`, `mixed`, or `insufficient`.

**The Trust Map is not an authorship probability.** In the current alpha, several benchmark-backed dimensions are intentionally `unknown`, so evidence coverage is commonly `insufficient`.

### Safe consensus semantics

TextForensics can form family-balanced categorical consensus, but it does **not** average detector-local calibrated probabilities and pretend the result is a calibrated ensemble probability.

A top-level probability requires a separately validated ensemble calibration for the exact detector set and missing-detector policy.

### Forensic reports

`textforensics report` records:
- SHA-256 of the analyzed text;
- detector observations and failures;
- plugin health;
- method-family-aware consensus;
- Trust Map;
- benign-normalization probes;
- optional provenance-ledger verification;
- explicit limitations.

Raw submitted text is not included in the report.

### Sealed case files

Case files add deterministic integrity sealing around a forensic bundle:

```bash
textforensics case export --file essay.txt --output case.json
textforensics case verify case.json
```

Case files omit raw text by default. Verification checks artifact structure and integrity; it does **not** prove the underlying authorship conclusion.

### Local provenance

```bash
textforensics snapshot draft.txt
# edit draft.txt
textforensics snapshot draft.txt
textforensics verify-ledger
```

The ledger is tamper-evident and refuses to append to an already-invalid chain.

A local hash ledger is **not** an independent trusted timestamp.

### Split-aware calibration diagnostics

The built-in baseline can fit a threshold artifact on one dataset and evaluate it on a different dataset:

```bash
textforensics calibrate calibration.jsonl --target-fpr 0.01 --output calibration.json
textforensics benchmark held-out.jsonl --calibration calibration.json
```

By default, TextForensics rejects evaluation when the evaluation file has the same SHA-256 fingerprint as the calibration file.

This prevents one easy form of in-sample performance inflation; it is not a complete replacement for source/near-duplicate leakage control on serious benchmarks.

## Install

### Core

The core has **no mandatory third-party runtime dependency**.

```bash
git clone https://github.com/strmt7/TextForensics.git
cd TextForensics
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

python -m pip install .
textforensics --version
```

### API

```bash
python -m pip install ".[api]"
textforensics serve
```

### MCP

```bash
python -m pip install ".[mcp]"
textforensics-mcp
```

### All optional surfaces

```bash
python -m pip install ".[all]"
```

See [Installation](docs/INSTALLATION.md) for pip, uv, pipx, offline wheelhouses, Docker, Podman, Compose, VM, Kubernetes/Nomad/ECS-style deployments, and configuration.

## Use

### Local browser UI

```bash
textforensics web
```

The browser UI binds to `127.0.0.1` by default and leads with Trust Map evidence coverage rather than a giant certainty percentage.

### CLI report

```bash
textforensics report --file essay.txt --output report.json
```

### Inspect detector/plugin health

```bash
textforensics detectors --health
```

### Pattern baseline

```bash
textforensics scan --file essay.txt
```

The built-in pattern score and diagnostic reliability are **uncalibrated alpha diagnostics**.

### Locate heterogeneous regions

```bash
textforensics localize --file paper.txt --sentences 4
```

Chunk values are diagnostic baseline outputs, not sentence-level authorship probabilities.

### Audit formulaic writing

```bash
textforensics audit --file draft.txt
```

This identifies writing patterns and quality suggestions. It does not guarantee or optimize for a particular third-party detector outcome.

### Compare versions

```bash
textforensics compare draft-v1.txt draft-v2.txt --json
```

## HTTP API

Install the API extra and run:

```bash
textforensics serve
```

Default bind: `127.0.0.1:8765`.

Selected endpoints:
- `GET /healthz`
- `GET /readyz`
- `GET /version`
- `GET /v1/detectors`
- `POST /v1/analyze`
- `POST /v1/report`
- `POST /v1/case`
- `POST /v1/audit`
- `POST /v1/compare`

Non-loopback binding requires explicit acknowledgement:

```bash
textforensics serve --host 0.0.0.0 --allow-remote
```

That flag is **not authentication**. Shared/public deployments need an appropriate external TLS/authentication/rate-limiting layer.

## MCP

The MCP surface uses the same core semantics as the CLI/API and includes tools for:
- alpha pattern analysis;
- forensic reports;
- sealed case files;
- detector/plugin health;
- diagnostic localization;
- version comparison;
- naturalness auditing.

MCP is an integration surface, not the project's scientific novelty.

## OCI containers

Build and run with Docker:

```bash
docker build -t textforensics:local .
docker run --rm -p 127.0.0.1:8765:8765 textforensics:local
```

The same image is intended for OCI-compatible runtimes such as rootless Podman.

The supplied image:
- is multi-stage;
- runs as an unprivileged numeric UID/GID;
- exposes a health check;
- contains the API runtime but not build tools;
- disables API access logging by default;
- requires no cloud-provider SDK.

A hardened `compose.yaml` example uses loopback publishing, a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, and tmpfs for `/tmp`.

See [Operations](docs/OPERATIONS.md).

## Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TEXTFORENSICS_HOST` | `127.0.0.1` | Bind host |
| `TEXTFORENSICS_PORT` | `8765` | Bind port |
| `TEXTFORENSICS_MAX_INPUT_BYTES` | `2000000` | Maximum input size |
| `TEXTFORENSICS_ALLOW_REMOTE` | `0` | Permit non-loopback bind |
| `TEXTFORENSICS_ACCESS_LOG` | `0` | Enable Uvicorn access log |
| `TEXTFORENSICS_LOG_LEVEL` | `INFO` | Process log level |

Invalid configuration fails fast.

## Detector plugins

Packages can register adapters through Python entry points:

```toml
[project.entry-points."textforensics.detectors"]
my_detector = "my_package:MyDetector"
```

Third-party detector plugins are trusted Python code. TextForensics validates their result contract but does not sandbox arbitrary plugin packages.

A serious detector adapter must document:
- immutable model/provider version where possible;
- method family;
- license;
- language/domain/length constraints;
- local/remote data flow;
- hardware/dependency requirements;
- benchmark and calibration status.

See [AGENTS.md](AGENTS.md) and [Contributing](CONTRIBUTING.md).

## Quality and release engineering

CI validates:
- Python 3.11–3.15;
- Linux, Windows, and macOS CLI/install smoke paths;
- unit/integration tests;
- critical Ruff checks;
- wheel build + clean wheel installation;
- packaged schemas;
- optional API surface;
- optional MCP surface;
- OCI build/start/health/non-root runtime.

The repository also includes:
- CodeQL;
- dependency review;
- scheduled dependency audit;
- Dependabot;
- release build/checksum workflow;
- CODEOWNERS;
- structured issue templates;
- security/support/release policies.

See:
- [Security](SECURITY.md)
- [Support](SUPPORT.md)
- [Release checklist](docs/RELEASE.md)
- [Commercial readiness](docs/COMMERCIAL_READINESS.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Quality gates](docs/QUALITY_GATES.md)

## Scientific roadmap

Before TextForensics can claim detector-performance parity with major commercial products, the project still needs:
- serious independent detector-family adapters;
- RAID/DetectRL/M4 evaluation;
- held-out calibration and final evaluation;
- human false-positive operating points and confidence intervals;
- language/domain/length/revision slices;
- empirical detector-correlation/ablation work;
- versioned calibration registry;
- benchmark-backed Trust Map dimensions;
- detector/provider drift observatory.

See [Roadmap](ROADMAP.md).

## What TextForensics will not claim

- A detector score proves authorship.
- A clean score proves human authorship.
- Raw scores from different instruments are directly comparable.
- Component probabilities automatically create a calibrated ensemble.
- The built-in heuristic baseline is state of the art.
- The legacy alpha integrity grade is a validated trust score.
- Text-only evidence should be the sole basis for high-stakes sanctions.
- Rewriting can guarantee a specific detector outcome.

## Development

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
ruff check src tests
```

Coding agents and human contributors should read [AGENTS.md](AGENTS.md) first.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
