# Enterprise Patterns Research for TextForensics

> Date: 2026-11-02
> Purpose: Analyze 10 established open-source projects for patterns, practices, and configurations that TextForensics should adopt or adapt to raise its engineering maturity to enterprise-grade standards.

---

## Table of Contents

1. [OpenTelemetry Python — Observability, Metrics, Tracing](#1-opentelemetry-python)
2. [Pydantic v2 — Validation, Serialization, Settings](#2-pydantic-v2)
3. [FastAPI — API Design, Dependency Injection, OpenAPI](#3-fastapi)
4. [Typer — CLI Design, Type Hints, Auto-completion](#4-typer)
5. [Rich — Terminal Formatting, Progress Bars, Tables](#5-rich)
6. [Loguru — Structured Logging](#6-loguru)
7. [pytest-benchmark — Performance Regression Testing](#7-pytest-benchmark)
8. [pre-commit — Git Hooks, Code Quality Gates](#8-pre-commit)
9. [Renovate — Automated Dependency Updates](#9-renovate)
10. [GitHub Actions — Reusable Workflows, Matrix Strategies](#10-github-actions)
11. [Prioritized Implementation Roadmap](#11-prioritized-implementation-roadmap)

---

## 1. OpenTelemetry Python

**Repo:** [`open-telemetry/opentelemetry-python`](https://github.com/open-telemetry/opentelemetry-python)
**Pattern:** Structured observability — traces, metrics, and logs unified through a single instrumentation layer.

### What TextForensics Gets

TextForensics operates a detector pipeline with multiple families, calibration steps, drift observatory snapshots, and benchmark runs. Today these operations are black boxes: you either get a result or an error, with no visibility into timing, failure rates, or resource consumption.

OpenTelemetry gives us:

- **Traces** to follow a single `scan` or `benchmark` invocation through every detector, analyzer, calibration step, and report generation stage.
- **Metrics** to aggregate detector latency (histograms), failure counts (counters), and drift snapshot frequency across time.
- **Structured context propagation** so that when a remote detector call fails, the trace includes the local analysis steps that led up to it.

### Key Patterns

#### Pattern 1: Tracer-per-module with module-level tracer instances

Each module creates a tracer once at module load time, not per-request:

```python
# src/textforensics/observability.py
from opentelemetry import trace, metrics
from opentelemetry.sdk.resources import Resource

resource = Resource.create(
    {
        "service.name": "textforensics",
        "service.version": __version__,
    }
)

_tracer = trace.get_tracer(__name__)
_meter = metrics.get_meter(__name__)

# Meter-level instruments (create once)
detector_latency = _meter.create_histogram(
    "tf.detector.latency_ms",
    unit="ms",
    description="Detector execution latency in milliseconds",
)

detector_calls = _meter.create_counter(
    "tf.detector.calls",
    unit="1",
    description="Total detector invocations",
)

detector_failures = _meter.create_counter(
    "tf.detector.failures",
    unit="1",
    description="Detector invocation failures",
)
```

#### Pattern 2: Span wrapping around detector protocol calls

```python
# In src/textforensics/detectors.py
from .observability import _tracer, detector_latency, detector_calls, detector_failures


class BuiltinHeuristicDetector(Detector):
    def predict(self, text: str) -> DetectorPrediction:
        with _tracer.start_as_current_span(
            "detector.predict",
            attributes={"detector.id": self.id, "detector.family": self.family},
        ) as span:
            start = time.monotonic()
            try:
                result = self._run(text)
                elapsed = (time.monotonic() - start) * 1000
                detector_latency.record(
                    elapsed,
                    {
                        "detector.id": self.id,
                        "detector.family": self.family,
                    },
                )
                detector_calls.add(1, {"detector.id": self.id})
                return result
            except Exception:
                detector_failures.add(1, {"detector.id": self.id})
                span.set_status(StatusCode.ERROR)
                span.record_exception()
                raise
```

#### Pattern 3: Batch span processor for production, console exporter for development

```python
# src/textforensics/observability.py
def init_observability(endpoint: str | None = None) -> None:
    """Initialize OpenTelemetry tracing and metrics.

    If TEXTFORENSICS_OTLP_ENDPOINT is set, export to that OTLP endpoint.
    Otherwise, use a console exporter (dev mode).
    """
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces")
    else:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        exporter = ConsoleSpanExporter()

    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
```

### Concrete Steps for TextForensics

1. Add `opentelemetry-api` and `opentelemetry-sdk` as an optional dependency group (`[observability]`).
2. Create `src/textforensics/observability.py` with tracer and meter setup, respecting the local-first principle: zero network calls unless `TEXTFORENSICS_OTLP_ENDPOINT` is explicitly set.
3. Wrap `engine.analyze_text()`, each detector `predict()` call, `benchmark_jsonl()`, and `drift.take_snapshot()` in spans.
4. Add a `--trace` CLI flag that enables the console exporter for debugging slow scans.
5. **Do not** add observability as a hard dependency — it is diagnostic tooling, not core logic.

### Why This Matters

- Drift observatory already collects longitudinal data; OpenTelemetry traces would give per-run breakdowns explaining *why* a detector's output changed.
- Benchmark results could include trace-based timing, not just wall-clock.
- Remote detector adapter failures (a key AGENTS.md concern) become fully auditable with context propagation.

---

## 2. Pydantic v2

**Repo:** [`pydantic/pydantic`](https://github.com/pydantic/pydantic)
**Pattern:** Declarative validation, serialization, and settings management via type hints and descriptors.

### What TextForensics Gets

TextForensics already uses Pydantic in `api.py` for request models (`TextRequest`, `CompareRequest`). However, `config.py` uses a manual `Settings` dataclass with hand-written `_env_bool`/`_env_int` helpers. The `models.py` types are likely dataclasses. Pydantic v2 replaces all three patterns with one system.

### Key Patterns

#### Pattern 1: `Settings` from environment variables, config files, and CLI

Pydantic's `SettingsConfigDict` auto-loads from environment variables, `.env` files, and CLI args:

```python
# src/textforensics/config.py (refactored)
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    host: str = "127.0.0.1"
    port: int = Field(8765, ge=1, le=65535)
    max_input_bytes: int = Field(2_000_000, ge=1_024, le=100_000_000)
    allow_remote: bool = False
    access_log: bool = False
    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        v_upper = v.strip().upper()
        if v_upper not in valid:
            raise ValueError(f"LOG_LEVEL must be one of {', '.join(sorted(valid))}")
        return v_upper

    model_config = SettingsConfigDict(
        env_prefix="TEXTFORENSICS_",
        env_file=".env",
        env_file_encoding="utf-8",
    )
```

This replaces ~70 lines of manual parsing with ~30 lines of declarative configuration. It adds `.env` file support, auto-documentation of all settings, and validation errors that name the specific field.

#### Pattern 2: Model-level validators for cross-field constraints

The AGENTS.md hard rules include constraints like "a score is not a probability" and "detector-local calibration is not ensemble calibration." These can be enforced declaratively:

```python
# src/textforensics/models.py
from pydantic import BaseModel, model_validator


class DetectorPredictionV2(BaseModel):
    detector_id: str
    detector_version: str
    detector_family: str
    score: float | None
    calibrated_ai_probability: float | None = None
    calibration_id: str | None = None

    @model_validator(mode="after")
    def probability_requires_calibration(self) -> "DetectorPredictionV2":
        if self.calibrated_ai_probability is not None:
            if self.calibration_id is None:
                raise ValueError(
                    "calibrated_ai_probability requires a non-null calibration_id. "
                    "See AGENTS.md rule #2: a score is not a probability."
                )
        return self
```

This codifies AGENTS.md rule #2 into a schema-level invariant that fails fast, with a clear error message.

#### Pattern 3: JSON Schema generation for API and MCP contracts

Pydantic v2 generates JSON Schema from model definitions. TextForensics has JSON schemas for forensic-bundle, detector-result, case-file, and trust-map. Instead of maintaining separate JSON schema files, they can be generated from Pydantic models:

```python
# Generate schemas from models
schema_json = ForensicBundle.model_json_schema()
with open("schemas/forensic-bundle.schema.json", "w") as f:
    json.dump(schema_json, f, indent=2)
```

This eliminates the drift risk between model definitions and JSON schema files — a single source of truth.

### Concrete Steps for TextForensics

1. Replace `config.py` dataclass with `pydantic_settings.BaseSettings`.
2. Add `pydantic_settings` to `dev` and `all` optional dependency groups.
3. Convert key dataclasses in `models.py` to Pydantic `BaseModel` subclasses for `DetectorPrediction`, `ForensicBundle`, and `TrustMap`.
4. Add `@model_validator` methods that encode AGENTS.md hard rules (calibration requirements, abstention semantics, score-direction constraints).
5. Add a script to regenerate JSON schemas from Pydantic models as a pre-release step.

### Why This Matters

- Hard rules #2, #3, #15, and #18 in AGENTS.md become enforceable code invariants, not just documentation.
- Settings management is consistent across CLI, API, and MCP entry points.
- Schema drift between code and JSON files is eliminated.

---

## 3. FastAPI

**Repo:** [`fastapi/fastapi`](https://github.com/fastapi/fastapi)
**Pattern:** Declarative REST API with dependency injection, automatic OpenAPI docs, and request/response validation.

### What TextForensics Gets

TextForensics already uses FastAPI in `api.py` and `server.py`. The current implementation is functional but has several enterprise patterns it can adopt.

### Key Patterns

#### Pattern 1: Dependency injection for shared concerns

Currently, text validation, settings loading, and detector health checks are either inlined or repeated. FastAPI's DI system centralizes them:

```python
# src/textforensics/api.py
from typing import Annotated
from fastapi import Depends


# Shared dependency
def get_settings() -> Settings:
    return Settings()


def validate_text_input(
    req: TextRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    try:
        return textforensics.config.validate_text_input(
            req.text, max_input_bytes=settings.max_input_bytes
        )
    except ValueError as exc:
        status = 413 if "exceeds" in str(exc) else 422
        raise HTTPException(status_code=status, detail="Invalid text input.") from exc


TextDep = Annotated[str, Depends(validate_text_input)]


@app.post("/v1/analyze", response_model=AnalysisResponse)
async def analyze(req: TextRequest, text: TextDep):
    result = analyze_text(text)
    return result.to_dict()
```

This replaces the current `checked()` helper defined inside `create_app()` with testable, composable dependencies.

#### Pattern 2: `response_model` for output filtering and documentation

The current API returns raw `to_dict()` output. Adding `response_model` ensures:

- Only declared fields are returned (defense-in-depth against accidental data leakage).
- OpenAPI docs reflect the actual response shape.
- Invalid response data fails before it reaches the client.

```python
from pydantic import BaseModel


class AnalysisResponse(BaseModel):
    verdict: str
    score: float
    diagnostic_reliability: float
    disagreement: float
    robustness_stability: float
    word_count: int
    analyzers: list[AnalyzerResult]
    warnings: list[str]


@app.post("/v1/analyze", response_model=AnalysisResponse)
async def analyze(text: TextDep) -> AnalysisResponse: ...
```

#### Pattern 3: Background tasks for non-critical side effects

Drift snapshots, benchmark archiving, and capability ledger updates could be offloaded:

```python
from fastapi import BackgroundTasks


@app.post("/v1/analyze")
async def analyze(text: TextDep, background: BackgroundTasks):
    result = analyze_text(text)
    # Non-blocking: archive the result for drift monitoring
    background.add_task(drift_observatory.record_prediction, result.to_dict())
    return result.to_dict()
```

#### Pattern 4: Lifespan events for setup/teardown

```python
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    from .observability import init_observability

    settings = Settings()
    if hasattr(settings, "otel_endpoint") and settings.otel_endpoint:
        init_observability(settings.otel_endpoint)
    yield
    # Shutdown
    logger.info("TextForensics API shutting down")
```

### Concrete Steps for TextForensics

1. Replace inlined `checked()` helper with `Depends()`-based input validation.
2. Add `response_model` to all endpoints.
3. Migrate to `lifespan` context manager for startup/shutdown (replaces `@app.on_event`).
4. Add `BackgroundTasks` for drift observatory recording.
5. Parameterize the security headers middleware with settings instead of hardcoded values.

### Why This Matters

- AGENTS.md rule #7 (local-first) and #17 (no silent telemetry) are better enforced when network behavior flows through explicit dependencies.
- Response filtering prevents accidental data leakage in case files (rule #22).
- OpenAPI docs become accurate API contracts (rule #15: schemas are public contracts).

---

## 4. Typer

**Repo:** [`fastapi/typer`](https://github.com/fastapi/typer)
**Pattern:** Type-driven CLI with decorator-based commands, auto-generated help, and shell auto-completion.

### What TextForensics Gets

TextForensics' `cli.py` is ~940 lines of `argparse` with manual `build_parser()`, a large `_run()` dispatch, and ad-hoc formatting. Typer would reduce this by:

- Eliminating the manual parser construction (functions *are* commands).
- Generating `--help` from docstrings.
- Providing `--install-completion` for bash/zsh/fish auto-completion out of the box.
- Supporting type coercion (e.g., `--threshold` as `float` with validation via Pydantic-compatible annotations).

### Key Patterns

#### Pattern 1: Function-as-command with type-driven parsing

Current pattern:

```python
calibrate = sub.add_parser("calibrate", help="Fit a threshold artifact on calibration-only JSONL.")
calibrate.add_argument("dataset")
calibrate.add_argument("--target-fpr", type=float, default=0.01)
calibrate.add_argument("--output", "-o")

# In _run():
elif args.command == "calibrate":
    artifact = calibrate_threshold_jsonl(
        args.dataset, target_fpr=args.target_fpr,
    )
    _write_json(args.output, artifact)
```

Typer equivalent:

```python
@app.command()
def calibrate(
    dataset: Path,
    target_fpr: float = 0.01,
    output: Optional[Path] = typer.Option(None, "-o", "--output"),
) -> None:
    """Fit a threshold artifact on calibration-only JSONL."""
    artifact = calibrate_threshold_jsonl(dataset, target_fpr=target_fpr)
    _write_json(output, artifact)
```

The function body *is* the command logic — no central dispatch.

#### Pattern 2: `Typer` app groups as sub-commands

TextForensics has natural command groups (`drift`, `bundle`, `capability`, `case`, `schema`):

```python
import typer

app = typer.Typer(no_args_is_help=True, add_completion=True)
drift_app = typer.Typer()
bundle_app = typer.Typer()
capability_app = typer.Typer()

app.add_typer(drift_app, name="drift", help="Longitudinal detector reliability tracking.")
app.add_typer(bundle_app, name="bundle", help="Pack, verify, and list case file bundles.")
app.add_typer(capability_app, name="capability", help="Inspect detector capability claims.")


@drift_app.command()
def snapshot(
    corpus: Path = typer.Option(..., help="Path to drift corpus JSON."),
    label: Optional[str] = None,
    allow_remote: bool = False,
    output: Optional[Path] = typer.Option(None, "-o"),
) -> None:
    """Take a detector snapshot."""
    ...
```

#### Pattern 3: Shell auto-completion

Typer generates completion scripts automatically:

```bash
textforensics --install-completion    # installs for current shell
textforensics --show-completion       # prints script for manual sourcing
```

This works for bash, zsh, and fish out of the box — no custom completion logic needed.

#### Pattern 4: Shared callback for settings initialization

```python
@app.callback()
def common(
    log_level: str = typer.Option("INFO", help="Logging level."),
) -> None:
    """Audit AI-text detector evidence and reliability locally."""
    pass
```

### Concrete Steps for TextForensics

1. Add `typer` as an optional dependency (or include it in `all`).
2. Create a new `cli_v2.py` (to avoid breaking existing CLI) using Typer.
3. Migrate commands in priority order: `scan`, `report`, `benchmark`, `drift`, `case`.
4. Add `--install-completion` support.
5. Replace `argparse` with Typer once all commands are migrated and tested.

### Why This Matters

- 940 lines of argparse → ~600 lines of Typer with auto-help, type coercion, and completion.
- Command documentation lives in function docstrings — single source of truth.
- Shell completion makes the tool more discoverable for forensic auditors who use it interactively.
- Typer's decorator-based design means each command function is independently testable.

---

## 5. Rich

**Repo:** [`Textualize/rich`](https://github.com/Textualize/rich)
**Pattern:** Terminal rendering with styled output, tables, progress bars, status indicators, and console logging.

### What TextForensics Gets

The current CLI has a `_pretty_analysis()` function that prints plain text. Rich would transform scan results, benchmark summaries, and drift comparisons into readable, colored, structured output — while remaining optional for scripts and CI.

### Key Patterns

#### Pattern 1: Rich console output for scan results

```python
from rich.console import Console
from rich.table import Table
from rich.panel import Panel


def _pretty_analysis(result) -> None:
    console = Console()

    table = Table(title="TextForensics — Analysis Result")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Verdict", result.verdict)
    table.add_row("Pattern Score", f"{result.score:.1%}")
    table.add_row("Diagnostic Reliability", f"{result.diagnostic_reliability:.1%}")
    table.add_row("Analyzer Disagreement", f"{result.disagreement:.1%}")
    table.add_row("Robustness Stability", f"{result.robustness_stability:.1%}")
    table.add_row("Words", str(result.word_count))

    console.print(Panel(table, title="TextForensics"))

    if result.analyzers:
        ana_table = Table(title="Analyzers")
        ana_table.add_column("Name", style="green")
        ana_table.add_column("Score", style="yellow")
        ana_table.add_column("Reliability", style="blue")
        for item in result.analyzers:
            ana_table.add_row(item.name, f"{item.score:.1%}", f"{item.reliability:.1%}")
        console.print(ana_table)

    if result.warnings:
        console.print("\n[yellow bold]Warnings[/yellow bold]")
        for warning in result.warnings:
            console.print(f"  [red]⚠[/red] {warning}")
```

#### Pattern 2: Progress bar for benchmark runs

```python
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn


def benchmark_jsonl_enhanced(path: str) -> None:
    samples = list(jsonl_iter(path))
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
    ) as progress:
        task = progress.add_task("Running detectors...", total=len(samples))
        for sample in samples:
            result = analyze_text(sample["text"])
            progress.advance(task)
```

#### Pattern 3: Console logging handler

```python
from rich.logging import RichHandler
import logging

logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)
```

This replaces plain `print()`-based logging with timestamped, colored, trace-aware output — while still being log-file compatible when `RichHandler` detects a non-TTY.

### Concrete Steps for TextForensics

1. Add `rich` to the optional `[dev]` or `[all]` dependency group.
2. Wrap `_pretty_analysis()` and `_write_json()` to use Rich when stdout is a TTY, falling back to plain JSON/Text in CI.
3. Add `rich.progress` to `scripts/benchmark.py` for live progress feedback.
4. Add `RichHandler` as the default logging handler (optional, gated behind a setting).

### Why This Matters

- Forensic auditors reading CLI output directly benefit from structured, color-coded results.
- The project remains script-friendly: `--json` flag still outputs parseable JSON.
- AGENTS.md rule #19 (short-text limitations must be visible) — Rich can highlight these warnings prominently.

---

## 6. Loguru

**Repo:** [`Delgan/loguru`](https://github.com/Delgan/loguru)
**Pattern:** Drop-in structured logging with zero boilerplate, rotation, compression, colors, and exception diagnostics.

### What TextForensics Gets

TextForensics currently has no logging configuration visible in the source — it uses `print()` for output and relies on uvicorn's logging for the API. Loguru provides a production-ready logger in one import statement.

### Key Patterns

#### Pattern 1: Zero-boilerplate setup

```python
# src/textforensics/logging_config.py
from loguru import logger

# Remove default handler, add structured output
logger.remove()

# Console output with colors (dev)
logger.add(
    sys.stderr,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>",
    level="DEBUG",
)

# Rotating file log for the API server
logger.add(
    "textforensics_{time:YYYY-MM-DD}.log",
    rotation="500 MB",
    retention="30 days",
    compression="zip",
    level="INFO",
    serialize=False,
)
```

#### Pattern 2: Structured logging for JSON parsers

```python
# JSON log output for CI or pipeline consumption
logger.add(
    "textforensics-structured.json",
    serialize=True,  # Each line is a JSON object
    rotation="100 MB",
    retention="7 days",
)
```

#### Pattern 3: `@logger.catch` for unhandled exception safety

```python
# src/textforensics/cli.py
from loguru import logger


@logger.catch
def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.from_env()
    return _run(args, settings)
```

This ensures every unhandled exception gets logged with full diagnostics (variable values, full stack trace) before the process exits.

#### Pattern 4: `bind()` for contextual logging

```python
# Attach detector identity to all log messages in a block
detector_logger = logger.bind(detector_id="builtin-heuristic", detector_version="1.0.0")
detector_logger.info("Processing text, {} words", word_count)
```

#### Pattern 5: Library-friendly disable pattern

For library use, disable logging by default — let the consuming application decide:

```python
# src/textforensics/__init__.py
from loguru import logger

# As a library: silent by default
logger.disable("textforensics")

# The application that imports us can re-enable:
# logger.enable("textforensics")
```

This is critical for TextForensics, which is both a library and a CLI tool. AGENTS.md rule #8 (no silent telemetry) extends to logging: the library should not write to the user's filesystem without their consent.

### Concrete Steps for TextForensics

1. Add `loguru` to the `[dev]` optional dependency group (or `[all]`).
2. Create `src/textforensics/logging_config.py` with the disable-by-default pattern.
3. Replace `print()` calls in `engine.py`, `detectors.py`, `benchmark.py`, and `drift.py` with `logger.debug/info/warning`.
4. In `server.py`, re-enable logging and add the rotating file handler.
5. Add `@logger.catch` to CLI `main()` as the outermost exception handler.

### Why This Matters

- AGENTS.md rule #7 (local-first): file logging is optional and explicit.
- AGENTS.md rule #8 (no silent telemetry): library mode is silent by default.
- Exception diagnostics include variable values (with `diagnose=True`) for faster debugging — but this can be disabled in production.
- Structured JSON logs enable pipeline integration without custom formatters.

---

## 7. pytest-benchmark

**Repo:** [`ionelmc/pytest-benchmark`](https://github.com/ionelmc/pytest-benchmark)
**Pattern:** pytest fixture that benchmarks functions with automatic calibration, statistics, regression detection, and JSON export.

### What TextForensics Gets

TextForensics already has `scripts/benchmark.py` for wall-clock benchmarking. However, it is a standalone script, not integrated with the test suite. pytest-benchmark brings benchmarking into the test harness with:

- Automatic calibration (it determines the right number of iterations for stable measurements).
- Outlier detection and removal.
- Regression comparison against saved baselines.
- Exhaustive statistics: mean, median, stddev, min, max, rounds, iterations.
- JSON export and SVG histogram generation.

### Key Patterns

#### Pattern 1: Benchmark fixture with automatic calibration

```python
# tests/test_benchmark_perf.py
def test_analyze_text_latency(benchmark):
    """Benchmark analyze_text on a 200-word sample."""
    sample = "The quick brown fox" * 13  # ~52 words, padded
    result = benchmark(analyze_text, sample)
    assert result.word_count > 0
```

The fixture handles warm-up, iteration count, and outlier removal automatically. The `assert` validates correctness after the benchmark run.

#### Pattern 2: Regression comparison

Save a baseline:
```bash
pytest tests/test_benchmark_perf.py --benchmark-save=baseline
```

Compare on CI:
```bash
pytest tests/test_benchmark_perf.py --benchmark-compare=baseline
```

Output shows percentage change, allowing regression detection:

```
Name (time in ms)           Min                Max              Mean
---------------------------------------------------------------------
test_analyze_text_latency  2.1300 (1.0)      5.2100 (1.0)     2.4500 (1.0)
---------------------------------------------------------------------
Previous:
test_analyze_text_latency  2.1000 (1.0)      5.0000 (1.0)     2.3800 (1.0)
---------------------------------------------------------------------
Change:
test_analyze_text_latency  +0.0030 (+0.1%)   +0.2100 (+4.2%)  +0.0070 (+2.9%)
```

#### Pattern 3: Histogram and JSON export

```bash
pytest --benchmark-histogram=benchmarks --benchmark-json=bench.json
```

The JSON export can be archived as a workflow artifact for longitudinal tracking.

### Concrete Steps for TextForensics

1. Add `pytest-benchmark` to the `[dev]` dependency group in `pyproject.toml`.
2. Create `tests/test_benchmark_perf.py` with benchmarks for:
   - `analyze_text()` on 50, 200, and 1000-word samples.
   - `build_forensic_bundle()` on the same sizes.
   - `DriftObservatory.take_snapshot()` with the test corpus.
   - `benchmark_jsonl()` on a small labeled set.
3. Save an initial baseline and commit it (or store as a GitHub Actions artifact on release).
4. Add `--benchmark-compare` to the CI workflow to detect regressions.
5. Keep `scripts/benchmark.py` for comprehensive profiling (memory, wall-clock); use pytest-benchmark for CI regression gates.

### Why This Matters

- AGENTS.md rule #16 (tests accompany behavior changes): performance tests alongside correctness tests.
- Drift observatory already tracks score distributions; latency regression would catch "silent" performance drift.
- Benchmark contamination (rule #12) is separate from performance benchmarking — pytest-benchmark measures speed, not accuracy, on the same corpus.

---

## 8. pre-commit

**Repo:** [`pre-commit/pre-commit`](https://github.com/pre-commit/pre-commit)
**Pattern:** Multi-language git hook framework that runs linters, formatters, and checks before each commit.

### What TextForensics Gets

TextForensics already uses ruff (linting/formatting) and has quality gates in `docs/QUALITY_GATES.md`. pre-commit automates these gates before each commit, preventing bad code from entering any branch.

### Key Patterns

#### Pattern 1: `.pre-commit-config.yaml` — declarative hook configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-toml
      - id: check-merge-conflict
      - id: check-case-conflict
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.9.6
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.14.1
    hooks:
      - id: mypy
        additional_dependencies:
          - "pydantic>=2"
        exclude: ^tests/

  - repo: local
    hooks:
      - id: schema-consistency
        name: Verify JSON schemas are valid
        entry: python -m pytest tests/test_schema.py
        language: python
        pass_filenames: false
        additional_dependencies:
          - "jsonschema>=4.23"
          - "pytest>=8"
```

#### Pattern 2: TextForensics-specific local hooks

```yaml
  - repo: local
    hooks:
      - id: check-agents-rules
        name: Verify AGENTS.md is not orphaned
        entry: git diff --name-only HEAD~1 | grep -q AGENTS.md
        language: fail
        pass_filenames: false
        always_run: false
        stages: [pre-commit]

      - id: no-raw-text-in-logs
        name: No raw text in log messages
        entry: grep -rn 'logger\.\(info\|warning\|debug\).*text[^a-z]' src/textforensics/
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-commit]
```

These encode AGENTS.md rules directly into the commit gate:
- Rule #22: Raw text excluded from case files by default — check that logging doesn't accidentally include input text.
- Rule #8: No silent telemetry — ensure no network calls in library mode.

#### Pattern 3: Run in CI as well

```yaml
# In CI workflow
- name: Run pre-commit
  run: pip install pre-commit && pre-commit run --all-files
```

This ensures the same gates run on every PR, not just locally.

### Concrete Steps for TextForensics

1. Create `.pre-commit-config.yaml` with ruff, pre-commit-hooks, and schema validation hooks.
2. Add `pre-commit` to the `[dev]` dependency group.
3. Add a pre-commit CI step to the existing GitHub Actions workflow.
4. Consider adding `mypy` for type checking (TextForensics has `from __future__ import annotations` in files, suggesting type hints are in use).
5. Run `pre-commit autoupdate` quarterly to keep hook revisions current.

### Why This Matters

- AGENTS.md rule #16 (tests accompany behavior changes) — pre-commit runs them before the commit.
- Quality gates in `docs/QUALITY_GATES.md` are enforced mechanically, not just checked in PR review.
- Cross-language hooks work with the existing JSON schemas, Python source, and YAML/TOML config files.

---

## 9. Renovate (Automated Dependency Updates)

**Repo:** [`renovatebot/renovate`](https://github.com/renovatebot/renovate)
**Pattern:** Automated, policy-driven dependency updates with version grouping, scheduling, and supply-chain cooldown.

### What TextForensics Gets

TextForensics has pinned dependencies with version ranges in `pyproject.toml`:
- `fastapi>=0.115,<1`
- `pytest>=8,<9`
- `ruff>=0.8,<1`

Renovate automatically detects these and opens PRs when updates are available. The AGENTS.md concern about "no silent telemetry" and dependency license compatibility (#18) makes automated updates with review even more valuable.

### Key Patterns

#### Pattern 1: `renovate.json` — declarative update policy

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:best-practices"],
  "minimumReleaseAge": "7 days",
  "prConcurrentLimit": 5,
  "packageRules": [
    {
      "description": "Group FastAPI ecosystem updates together",
      "matchPackageNames": ["fastapi", "uvicorn", "pydantic", "pydantic-settings"],
      "matchUpdateTypes": ["minor", "patch"],
      "groupName": "FastAPI ecosystem"
    },
    {
      "description": "Auto-merge patch updates for dev tooling",
      "matchDepTypes": ["dev"],
      "matchUpdateTypes": ["patch"],
      "automerge": true,
      "automergeType": "pr"
    },
    {
      "description": "Disable major version bumps — require manual review",
      "matchUpdateTypes": ["major"],
      "enabled": false
    },
    {
      "description": "Pinned build-system deps: never auto-update",
      "matchDepTypes": ["build-system.requires"],
      "enabled": false
    }
  ],
  "lockFileMaintenance": {
    "enabled": true
  }
}
```

#### Pattern 2: Supply-chain cooldown for AGENTS.md rule #18

The `minimumReleaseAge: "7 days"` setting prevents Renovate from proposing newly published packages — a defense against supply-chain attacks where a malicious package is published and immediately picked up.

```json
{
  "packageRules": [
    {
      "matchDatasources": ["pypi"],
      "minimumReleaseAge": "7 days"
    }
  ]
}
```

#### Pattern 3: GitHub App integration

Use Renovate's GitHub App (free for public repos) or self-host it for private repos:

1. Install the Renovate GitHub App on the repository.
2. Commit `renovate.json`.
3. Renovate starts scanning and opens PRs.

### Concrete Steps for TextForensics

1. Create `renovate.json` at the repository root with the configuration above.
2. Install the Renovate GitHub App (or configure Dependabot as an alternative if Renovate is not preferred).
3. Configure `minimumReleaseAge: "7 days"` for PyPI dependencies.
4. Group FastAPI/pydantic/uvicorn updates together since they are tightly coupled.
5. Disable automerge for dependencies that affect score semantics (any detector or calibration dependency).

### Why This Matters

- AGENTS.md rule #18 (model/data license compatibility): manual review of major version bumps ensures license changes are caught.
- AGENTS.md rule #21 (revalidate calibrations after detector/provider changes): Renovate can be configured to tag calibration-related dependency PRs for mandatory review.
- Reduces "dependency rot" — the project stays current without manual `pip list --outdated` checks.

---

## 10. GitHub Actions

**Repo:** Various community patterns, [`actions/actions-runner`](https://github.com/actions/actions-runner)
**Pattern:** Reusable workflows, matrix strategies, conditional execution, artifact management, and composite actions.

### What TextForensics Gets

TextForensics likely has a GitHub Actions workflow (given the `Dockerfile` and CI references). Enterprise-grade patterns would make the CI more reliable, faster, and easier to maintain.

### Key Patterns

#### Pattern 1: Reusable workflow composition

Instead of one monolithic workflow, split into reusable pieces:

```yaml
# .github/workflows/ci.yml — caller workflow
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    uses: ./.github/workflows/reusable-lint.yml

  test:
    needs: lint
    uses: ./.github/workflows/reusable-test.yml
    with:
      python-version: "3.12"

  benchmark:
    needs: test
    uses: ./.github/workflows/reusable-benchmark.yml
    with:
      python-version: "3.12"
```

Each reusable workflow is independently testable and versionable.

#### Pattern 2: Matrix strategy for multi-version testing

```yaml
# .github/workflows/reusable-test.yml
name: Test Matrix

on:
  workflow_call:
    inputs:
      python-version:
        required: true
        type: string

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        python-version: ["3.11", "3.12", "3.13", "3.14", "3.15"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e .[dev]
      - run: pytest -v --cov=textforensics
      - name: Upload coverage
        uses: codecov/test-results-action@v1
        if: matrix.python-version == '3.14' && matrix.os == 'ubuntu-latest'
```

This covers all declared Python versions in `pyproject.toml` (3.11 through 3.15) across two operating systems.

#### Pattern 3: Conditional job execution and `continue-on-error`

```yaml
jobs:
  test:
    uses: ./.github/workflows/reusable-test.yml
    with:
      python-version: "3.12"

  # Optional: benchmark is informational, not a gate
  benchmark:
    needs: test
    continue-on-error: true
    uses: ./.github/workflows/reusable-benchmark.yml

  # Only publish on main branch after all checks pass
  publish:
    needs: [test, benchmark]
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    uses: ./.github/workflows/reusable-publish.yml
```

#### Pattern 4: Artifact management for reproducibility

AGENTS.md rule #1 requires reproducible run artifacts. GitHub Actions artifacts preserve these:

```yaml
- name: Archive benchmark results
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: benchmark-results-${{ github.sha }}
    path: benchmark-output/
    retention-days: 90

- name: Archive case file
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: case-file-${{ github.sha }}
    path: testdata/case-files/
    retention-days: 90
```

#### Pattern 5: Composite actions for reusable steps

```yaml
# .github/actions/setup-python/action.yml
name: Setup Python Environment
description: Install Python and project dependencies

runs:
  using: composite
  steps:
    - name: Cache pip
      uses: actions/cache@v4
      with:
        path: ~/.cache/pip
        key: ${{ runner.os }}-pip-${{ hashFiles('**/pyproject.toml') }}

    - name: Install project
      shell: bash
      run: pip install -e .[dev,all]
```

### Concrete Steps for TextForensics

1. Refactor existing workflow(s) into reusable components: `reusable-lint.yml`, `reusable-test.yml`, `reusable-benchmark.yml`, `reusable-publish.yml`.
2. Add a Python version matrix covering all declared versions (3.11–3.15).
3. Add `continue-on-error: true` to benchmark and coverage jobs (informational, not gating).
4. Archive benchmark results and coverage reports as workflow artifacts with 90-day retention.
5. Add a security scan job (bandit, pip-audit) using the existing `[security]` extras.
6. Pin all action versions to specific SHAs or tags (security best practice).

### Why This Matters

- AGENTS.md rule #1 (never invent benchmark results): archived artifacts provide the trace from commit → benchmark run → result.
- AGENTS.md rule #34 (hardware/runtime/software versions recorded): matrix strategy ensures tests pass across all declared platforms.
- Rule #18 (license/model compatibility): security scan jobs run on every PR.
- Reusable workflows reduce maintenance burden when adding new checks.

---

## 11. Prioritized Implementation Roadmap

The following prioritization is based on:
1. **Impact on AGENTS.md compliance** — does this pattern help enforce a hard rule?
2. **Effort to implement** — can it be done incrementally without rewriting core modules?
3. **Risk** — does it change user-facing behavior?

### Phase 1: Foundation (low risk, high impact)

| Priority | Pattern | Project | Est. Effort | AGENTS.md Rules Affected |
|----------|---------|---------|-------------|--------------------------|
| 1 | Pre-commit hooks | pre-commit | 2h | #16 (tests), quality gates |
| 2 | Pydantic Settings | Pydantic v2 | 3h | #2, #3, #15 (score semantics, schemas) |
| 3 | Loguru logging | Loguru | 4h | #7, #8 (local-first, no silent telemetry) |
| 4 | Renovate config | Renovate | 1h | #18 (license compat) |

### Phase 2: Quality & Observability (medium risk, high value)

| Priority | Pattern | Project | Est. Effort | AGENTS.md Rules Affected |
|----------|---------|---------|-------------|--------------------------|
| 5 | pytest-benchmark integration | pytest-benchmark | 4h | #16 (tests), #34 (runtime versions) |
| 6 | GitHub Actions refactoring | GitHub Actions | 6h | #1 (reproducible results), #34 |
| 7 | FastAPI DI + response models | FastAPI | 4h | #15 (schema contracts), #22 (no raw text) |
| 8 | OpenTelemetry optional observability | OpenTelemetry | 6h | Drift monitoring, provenance |

### Phase 3: UX & Polish (low risk, incremental value)

| Priority | Pattern | Project | Est. Effort | AGENTS.md Rules Affected |
|----------|---------|---------|-------------|--------------------------|
| 9 | Rich terminal output | Rich | 3h | #19 (short-text visibility), #24 (authorship limitation) |
| 10 | Typer CLI migration | Typer | 8h | Usability, maintainability |

### Dependencies Between Patterns

```
Phase 1
  ├── pre-commit (standalone)
  ├── Pydantic Settings → feeds into FastAPI DI, CLI migration
  ├── Loguru → feeds into observability (OpenTelemetry can read structured logs)
  └── Renovate → standalone, but benefits from pre-commit (linting updated deps)

Phase 2
  ├── pytest-benchmark → standalone
  ├── GitHub Actions refactoring → needs pre-commit for CI lint step
  ├── FastAPI DI → needs Pydantic Settings
  └── OpenTelemetry → needs Loguru for log correlation

Phase 3
  ├── Rich → standalone, but works better with Typer CLI
  └── Typer → needs Pydantic for type validation
```

### Anti-Patterns to Avoid

1. **Do not** adopt these patterns wholesale from projects that have different trust requirements. TextForensics handles sensitive text data; every pattern must respect AGENTS.md rule #7 (local-first) and rule #8 (no silent telemetry).

2. **Do not** make observability a hard dependency. OpenTelemetry, Rich, and Loguru should all be optional extras. The forensic core must remain importable without GPU stacks (rule #14) or telemetry packages.

3. **Do not** let Renovate or pre-commit auto-merge changes that affect score semantics, calibration, or detector adapters. These require human review by AGENTS.md rule #3.

4. **Do not** replace `argparse` until all subcommands have Typer equivalents with passing tests. Use a migration period where both are available.

---

*This report is a research artifact, not a commitment. Each pattern should be evaluated against the current AGENTS.md hard rules before implementation. The goal is to raise engineering maturity without changing forensic semantics.*
