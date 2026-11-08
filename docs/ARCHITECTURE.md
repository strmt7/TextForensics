# Architecture — TextForensics

> Living document. Last major update: 2026-11-02.
> See [AGENTS.md](../AGENTS.md) for the non-negotiable development contract.

---

## 1. Component Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│  TextForensics                                                         │
│                                                                         │
│  ┌──────────┐  ┌───────────┐  ┌───────────┐  ┌──────────┐             │
│  │ Detectors │  │ Analyzers │  │  Trust    │  │Consensus │             │
│  │ (TFDP/2)  │  │ (Feature  │  │  Map      │  │(Family-  │             │
│  │           │  │  extract) │  │           │  │ balanced)│             │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘             │
│        │              │              │              │                   │
│  ┌─────▼──────────────▼──┐  ┌───────▼──────────────▼───────┐          │
│  │    Forensic Engine    │  │     Report Builder           │          │
│  │  (analyze_text,       │  │  (build_forensic_bundle)     │          │
│  │   execute_detector)   │  │                              │          │
│  └─────┬─────────────────┘  └───────┬──────────────────────┘          │
│        │                            │                                  │
│  ┌─────▼────────────────────────────▼───────────────────────────┐     │
│  │                   Forensic Bundle / Case File               │     │
│  │  (portable, raw-text-free, hash-sealed)                     │     │
│  └────────────────────────┬────────────────────────────────────┘     │
│                           │                                          │
│  ┌──────────┐  ┌──────────▼──────┐  ┌─────────────┐                 │
│  │Provenance│  │ Drift           │  │  Calibration│                 │
│  │ Ledger   │  │ Observatory     │  │  Registry   │                 │
│  └──────────┘  └─────────────────┘  └─────────────┘                 │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │  Integration Layer: CLI │ API (FastAPI) │ MCP │ Browser UI     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Detectors (`src/textforensics/detectors.py`)

The **TFDP/2 (TextForensics Detector Protocol v2)** defines a strict contract between the core and any detector adapter. TFDP/1 predictions remain accepted and are normalized to TFDP/2 (see `SPEC.md`).

**Key types:**
- `DetectorPrediction` — the canonical output. Contains raw/native score, verdict (`ai_like`, `human_like`, `abstain`), optional `calibrated_ai_probability` (only with `calibration_id`), detector identity, supported languages, minimum words, evidence, and warnings.
- `DetectorFailure` — structured failure record. Raw exception text is stripped to prevent source-text leakage.
- `DetectorContractError` — raised when an adapter violates the protocol.
- `Detector` (Protocol) — requires `detector_id`, `detector_version`, `detector_family`, and `detect(text) -> DetectorPrediction`.
- `DetectorRegistry` — discovered builtins + plugins via `textforensics.detectors` entry point group.

**Built-in detector:**
- `BuiltinHeuristicDetector` (`textforensics/builtin-heuristic`, family: `stylometric-heuristic`) — zero-dependency stylometric/structural baseline. Uses the internal `analyze_text` engine. Minimum 80 words, English only. Reliability is an uncalibrated diagnostic.

**Validation chain on every prediction:**
1. Schema version check
2. Required identity fields
3. Score finiteness
4. Verdict in allowed set
5. Calibrated probability ↔ calibration_id co-dependency
6. Source-text echo prevention (forbidden evidence key names, content-length checks)

### 1.2 Analyzers & Feature Extraction (`src/textforensics/analyzers.py`, `features.py`)

**Feature extraction** (`features.py`):
- `extract_features(text) -> dict` — word count, sentence count, paragraph count, punctuation ratio, lexical diversity, and other structural metrics.

**Built-in analyzers** (`analyzers.py`):
- Run against the feature vector from `extract_features`.
- Each analyzer returns `AnalyzerResult` with `name`, `score`, and `reliability`.
- The engine combines these into a weighted aggregate score and measures inter-analyzer disagreement.

### 1.3 Trust Map (`src/textforensics/trust.py`)

Evaluates whether a given input falls within validated operating conditions.

**Dimensions (8 total):**
| Dimension | What it measures |
|---|---|
| `language` | Language coverage of detectors vs. input |
| `text_length` | Word count vs. each detector's `min_words` |
| `domain_genre` | Domain/genre match against benchmark evidence |
| `editing_revision` | Robustness to paraphrase/editing regimes |
| `human_false_positive_evidence` | Nearest-slice held-out human FPR |
| `detector_diversity` | Methodological family diversity of observations |
| `benign_stability` | Verdict consistency under harmless normalization |
| `temporal_version_stability` | Longitudinal provider/detector version stability |

**States:** `supported`, `partial`, `unknown`, `out_of_scope`

**Overall assessment:**
- `strong` — all dimensions at least `supported` or `partial`, no `unknown`
- `mixed` — some `unknown` or `partial` dimensions present
- `insufficient` — any `out_of_scope` or ≥ 3 `unknown` dimensions

**Two construction paths:**
- `build_trust_map(predictions, word_count, robustness, failure_count)` — from live detector observations
- `trust_map_from_capability_ledger(ledger)` — from registered capability claims

### 1.4 Consensus (`src/textforensics/consensus.py`)

Family-balanced categorical consensus that does **not** fuse probabilities.

**Process:**
1. Group predictions by `detector_family`
2. Within each family, compute majority verdict (abstain if all abstained or tied)
3. Across families, compute majority vote → `ai_like`, `human_like`, or `abstain`
4. Family agreement = fraction of voting families in majority
5. A top-level calibrated probability is only emitted when `ensemble_probability` and `ensemble_calibration_id` are provided together

**Key invariants:**
- Detector-local calibrated probabilities are never averaged
- Fewer than 2 voting families → `abstain`
- Equal AI/human families → `abstain`

### 1.5 Calibration (`src/textforensics/calibration.py`, `benchmark.py`)

**Separation of concerns:**
- `select_threshold(calibration_path, target_fpr)` — selects threshold on calibration data only
- `evaluate_threshold(test_path, threshold)` — evaluates on held-out data
- `validate_no_contamination(cal_path, test_path)` — ensures disjointness via dataset and sample-level hashing
- `run_calibration_evaluation(cal_path, eval_path, target_fpr)` — full pipeline with contamination check

### 1.6 Provenance (`src/textforensics/provenance.py`)

Tamper-evident local draft ledger:
- JSONL format with chained `record_sha256` → `previous_record_sha256`
- File-level snapshots: hash, size, name, timestamp
- Cross-process lock serialization (Windows `msvcrt.locking`, POSIX `fcntl.flock`)
- Verification: `_verify_ledger_unlocked` checks chain integrity

### 1.7 Case File (`src/textforensics/casefile.py`)

Portable, reproducible audit artifact (schema
`textforensics.case-file/v4`; v1–v3 still verify):
- Wraps a forensic bundle with tool version and integrity seal
- `seal_case_file(bundle)` → adds schema, version, `case_sha256`,
  plus the v3/v4 sections: `input` (content hash only, no raw text),
  `detector_observations`, `validation_refs` (into the U1 validation
  registry), `limitations` (plain language, counterfactuals), `process`
  (the D1–D10 appeal checklist, "template, not legal advice"),
  `custody` (hash-chained entries), `seal`, and `gaps` (every absent
  item declared with a reason)
- v4 adds a per-observation determinism declaration
  (`determinism` / `determinism_reason` on `detector_observations`
  items, required on `kind: "observed"` items): the value the
  analysis recorded in the bundle's `detector_results`, or an
  explicit seal-time override (`seal_case_file(..., determinism={...},
  determinism_reasons={...})`, CLI `case export --determinism
  <detector_id>:<value>`), or `"unknown"` when neither exists. An
  override is recorded in the sealed bundle copy as well as the
  observations, so verification rebuilds exactly what was sealed.
  The builtin heuristic detector declares `deterministic`; the
  Ollama adapter declares `non_deterministic` (sampling).
- `verify_case_file(payload, public_key=None)` → validates structure,
  hash, raw-text policy, v3/v4 sections, custody chain and checklist
  re-derivation; a present T2 signature is verified only when a public
  key is supplied, otherwise reported as unverified, never as a pass
- `verify_case_file_combined(payload, public_key=None)` (in `verify.py`)
  → the single entry point for case-file verification: runs BOTH the
  N-version replay (Trust Map re-derivation, detector-result checks,
  independent seal recomputation — v3 Trust Maps accepted, `stale` a
  distinct state) AND the primary-path seal check (seal, manifest,
  raw-text portability, tool identity) and requires both to pass. Used
  by `case verify`, `verify`, and the MCP `verify_case_file` tool, so
  all three give one answer. The two verifiers stay separate code
  paths — that independence is the point of N-version replay.
- Deterministic mode strips `runtime_ms` and uses fixed timestamps
- Atomic write via temp file + `os.replace`

Sealed bundle (`src/textforensics/sealed_bundle.py`, Phase 3 U2):
packs a v3/v4 case into a deterministic MPL bundle (canonical JSON,
sorted stored ZIP entries, normalised ZipInfo, archive comment
`mpl-bundle-sha256:<manifest SHA-256>`) carrying `case.json`, the
standalone stdlib-only verifier (`_standalone_verify.py`, runs
without the package installed), an optional RFC 3161 token, and an
MPL manifest (`textforensics.sealed-bundle-manifest/v1`) with a
companion seal record (manifest/bundle/archive digests, signature,
timestamp record). Three seal tiers: T1 hash (always), T2 Ed25519/DSSE
(`sealing.py`, `dsse.py` — pure stdlib, RFC 8032), T3 RFC 3161
(`timestamp.py`; free TSAs labelled non-qualified). `case verify`
exits 0/1/2 (verified / seal failed / checks could not run); replay
runs only when the seal passes and aborts on a text-hash mismatch
before any detector runs. Replay returns `replay_outcome`
(`reproduced` / `inconclusive` / `failed`): a declared
`non_deterministic` detector whose replayed output differs is
`not_reproducible` (warning `not_reproducible:<detector_id>`,
valid-but-inconclusive), and a sealed-bundle verification of such a
replay exits 2; a `deterministic` or `unknown` declaration fails
closed on a mismatch.

One bundle format, three layers (not three formats): the forensic
bundle JSON is the data; the sealed case file is its integrity
wrapper; the bundle archive (`bundle.py`: `.tar.gz`/`.zip` +
manifest) is transport for case files, and the sealed bundle
(`sealed_bundle.py`) is the MPL-conformant transport. The result codec
speaks the current version for each format (case-file v3,
forensic-bundle and detector-result v2, trust-map v2 with v3
accepted); legacy v1 artifacts still decode, keeping their v1 label.

### 1.8 Drift Observatory (`src/textforensics/observatory.py`)

Longitudinal detector reliability tracking:
- `DriftObservatory` loads a probe corpus (`textforensics.drift-corpus/v1`)
- `take_snapshot()` runs all detectors against the probe corpus
- `compare_snapshots(baseline, current)` produces a per-detector drift report
- Metrics: score distribution shift, verdict flips, threshold changes, calibration drift, human-slice FPR, provider metadata changes, supported regime changes

### 1.9 Capability Ledger (`src/textforensics/policy.py`)

Mechanical claim gating for detector capabilities:
- Three evidence tiers: `READABLE`, `TOOL_BACKED`, `VALIDATED`
- Four evidence labels: `REPORTED`, `CALCULATED`, `PROPOSED`, `EXECUTED`
- `CapabilityLedger` stores claims per detector, with expiration dates
- `validate_claim(claim)` enforces: every claim needs evidence; VALIDATED needs EXECUTED label
- `ledger_to_trust_dimension(ledger, detector_id, prefix)` maps claims to Trust Map dimensions

### 1.10 Report Builder (`src/textforensics/report.py`)

`build_forensic_bundle(text)` orchestrates the full pipeline:
1. Discover detectors (or use provided list)
2. Execute each detector → collect `DetectorPrediction` or `DetectorFailure`
3. Run benign-variant robustness probes for each successful detector
4. Build consensus via `family_balanced_consensus`
5. Build Trust Map via `build_trust_map`
6. Compute legacy `VerdictIntegrity` (deprecated heuristic)
7. Assemble `ForensicBundle` with hash, metadata, limitations

---

## 2. Data Flow

### 2.1 Primary Analysis Flow

```
User Input (text)
       │
       ▼
┌──────────────────┐
│  Emergency Stop  │── stopped? ──▶ abort
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│  extract_features│ → word_count, sentence_count, punctuation_ratio, ...
└──────┬───────────┘
       │
       ▼
┌──────────────────┐     ┌───────────────────┐
│ run_builtin_     │     │  BuiltinHeuristic │
│ analyzers()      │────▶│  Detector         │
│ (feature vector) │     │  .detect(text)    │
└──────┬───────────┘     └────────┬──────────┘
       │                          │
       ▼                          ▼
┌─────────────────────────────────────────────┐
│         Detector Registry                   │
│  (builtins + plugins via entry points)      │
│                                             │
│  For each detector: execute_detector()      │
│    ├── validate_prediction()                │
│    ├── _validate_no_source_echo()          │
│    └── wrap failures as DetectorFailure     │
└──────┬──────────────────────────────────────┘
       │
       ▼
┌──────────────────┐  ┌──────────────────┐
│ Benign Stability │  │  Robustness       │
│ Probes           │  │  (per detector)   │
│ (whitespace,     │  │  verdict_stability│
│  punctuation,    │  │  native_score_    │
│  markup)         │  │  range            │
└──────┬───────────┘  └────────┬─────────┘
       │                       │
       ▼                       ▼
┌─────────────────────────────────────────────┐
│          Report Assembly                    │
│                                             │
│  1. family_balanced_consensus(predictions)  │
│  2. build_trust_map(predictions,            │
│       word_count, robustness, failures)     │
│  3. _integrity(predictions, word_count,     │
│       robustness) ← legacy heuristic        │
│  4. ForensicBundle assembled                │
└────────────────────────┬────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────┐
│              Output Layer                   │
│                                             │
│  • CLI (JSON/JSONL/rich text)               │
│  • API (FastAPI JSON response)              │
│  • MCP (structured tool response)           │
│  • Browser UI (HTML report)                 │
│  • Case file (sealed, portable JSON)        │
└─────────────────────────────────────────────┘
```

### 2.2 Calibration Flow

```
┌──────────────┐     ┌────────────────┐     ┌──────────────┐
│ Calibration  │     │   Held-out     │     │  Production  │
│   Dataset    │     │   Test Set     │     │   Text       │
│ (labeled,    │     │  (disjoint,    │     │              │
│  not used    │     │   labeled)     │     │              │
│  for eval)   │     │                │     │              │
└──────┬───────┘     └───────┬────────┘     └──────┬───────┘
       │                     │                      │
       ▼                     │                      │
  select_threshold()         │                      │
  → returns threshold        │                      │
  → writes artifact          │                      │
       │                     │                      │
       │              evaluate_threshold()          │
       │              → contamination check         │
       │              → metrics (FPR, TPR,         │
       │                AUPRC, Brier, etc.)        │
       │                     │                      │
       │                     ▼                      │
       │              Threshold applied             │
       │              to prediction                 │
       │                     │                      │
       │                     ▼                      │
       │              calibrated_ai_probability     │
       │              + calibration_id              │
       │                     │                      │
       │                     ▼                      │
       │              DetectorPrediction            │
       │                     │                      │
       └─────────────────────┼──────────────────────┘
                             │
                             ▼
                    Trust Map + Consensus
```

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  LOCAL-FIRST TRUST BOUNDARY                                     │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  TRUSTED ZONE: Local execution                             │  │
│  │  • Feature extraction (zero network)                       │  │
│  │  • Builtin heuristic detector (zero network)               │  │
│  │  • Trust Map evaluation (local data only)                  │  │
│  │  • Consensus computation (local data only)                 │  │
│  │  • Provenance ledger (local filesystem)                    │  │
│  │  • Case file creation (local filesystem)                   │  │
│  │  • Drift observatory (local probe corpus)                  │  │
│  │  • Calibration artifacts (local filesystem)                │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  OPT-IN ZONE: Remote execution                             │  │
│  │  • Remote detector adapters (requires explicit config)     │  │
│  │  • Provider API calls (official/authorized only)           │  │
│  │  • Results treated as observations, not ground truth       │  │
│  │  • No network telemetry                                    │  │
│  │  • Server binds to loopback by default                     │  │
│  │  • --allow-remote or TEXTFORENSICS_ALLOW_REMOTE=1 required │  │
│  │    for non-loopback bind                                   │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  EXCLUDED: Never done                                      │  │
│  │  • No raw text in logs                                     │  │
│  │  • No raw text in case files (unless explicitly opted in)  │  │
│  │  • No silent telemetry                                     │  │
│  │  • No scraping or reverse-engineering providers            │  │
│  │  • No text leakage in error messages                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.1 Network Safety

- **Default:** Zero network activity. The CLI and all local tools work offline.
- **Server:** Binds to `127.0.0.1` by default. Non-loopback requires explicit `--allow-remote` flag.
- **Remote detectors:** Only activated when explicitly configured. Must use official/authorized APIs.
- **Error handling:** Provider errors that might echo submitted text are redacted.
- **Input limits:** Default 2,000,000 UTF-8 bytes via `TEXTFORENSICS_MAX_INPUT_BYTES`.

---

## 4. State Machines

### 4.1 Detector Lifecycle

```
                    ┌───────────────────┐
                    │   Registered      │
                    │   (in manifest)   │
                    └────────┬──────────┘
                             │
                    ┌────────▼──────────┐
                    │   Discovery       │
                    │   (entry point    │
                    │    / builtin)     │
                    └────────┬──────────┘
                             │
                  ┌──────────▼──────────┐
                  │   Health Check      │
                  │   PluginHealth      │
                  └──┬───────────────┬──┘
                     │ ok            │ error
              ┌──────▼──────┐  ┌────▼────────────┐
              │   Ready     │  │   Failed        │
              │   (loaded)  │  │   (PluginHealth │
              │             │  │    status=error)│
              └──────┬──────┘  └─────────────────┘
                     │
              ┌──────▼──────┐
              │   Executed  │
              │   .detect() │
              └──────┬──────┘
                     │
           ┌─────────▼──────────┐
           │   Validated?       │
           │   validate_        │
           │   prediction()     │
           └──┬────────────┬────┘
              │ valid      │ invalid
      ┌───────▼──────┐  ┌─▼────────────────┐
      │ Prediction   │  │ DetectorFailure   │
      │ recorded     │  │ (message stripped)│
      └──────────────┘  └───────────────────┘
```

### 4.2 Calibration Flow

```
  ┌──────────────────┐
  │ Calibration Data │
  │ (labeled set)    │
  └────────┬─────────┘
           │
  ┌────────▼───────────────────────┐
  │  select_threshold()            │
  │  → finds threshold at target   │
  │    FPR on calibration data     │
  │  → returns ThresholdSelection  │
  │    Result with hash provenance │
  └────────┬───────────────────────┘
           │
  ┌────────▼───────────────────────┐
  │  write artifact                │
  │  create_threshold_selection_artifact() │
  │  → JSON with schema, hash,     │
  │    dataset hash, method        │
  └────────┬───────────────────────┘
           │
  ┌────────▼───────────────────────┐
  │  validate_no_contamination()   │
  │  → calibration vs test hash    │
  │  → sample-level overlap check  │
  └────────┬───────────────────────┘
           │
  ┌────────▼───────────────────────┐
  │  evaluate_threshold()          │
  │  → held-out metrics            │
  │  → contamination flag          │
  └────────┬───────────────────────┘
           │
  ┌────────▼───────────────────────┐
  │  Applied to predictions        │
  │  → calibrated_ai_probability   │
  │  → calibration_id              │
  └────────────────────────────────┘
```

### 4.3 Case File Creation

```
  ┌──────────────────┐
  │ Forensic Bundle  │
  │ (full report)    │
  └────────┬─────────┘
           │
  ┌────────▼───────────────────────┐
  │  _validate_portable_bundle()   │
  │  • schema = forensic-bundle/v1 or v2 │
  │  • content_sha256 valid        │
  │  • raw_text_included = false   │
  │  • no forbidden raw-text keys  │
  └────────┬───────────────────────┘
           │
  ┌────────▼───────────────────────┐
  │  seal_case_file()              │
  │  • wrap with schema, tool ver  │
  │  • compute case_sha256 seal    │
  │  • deterministic mode: strip   │
  │    runtime_ms, fix timestamp   │
  └────────┬───────────────────────┘
           │
  ┌────────▼───────────────────────┐
  │  write_case_file()             │
  │  • atomic write (temp + fsync │
  │    + os.replace)               │
  └────────┬───────────────────────┘
           │
  ┌────────▼───────────────────────┐
  │  Portable Case File            │
  │  (JSON, sealed, no raw text)   │
  └────────────────────────────────┘
```

---

## 5. Integration Points

### 5.1 CLI (`src/textforensics/cli.py`)

Primary command-line interface. Key capabilities:
- `textforensics analyze` — run analysis on text (stdin, file, or argument)
- `textforensics detectors --health` — check all detector health
- `textforensics bundle` — create forensic bundle
- `textforensics case` — create/export sealed case files
- `textforensics drift` — manage drift observatory snapshots
- `textforensics benchmark` — run benchmark evaluation
- `textforensics serve` — start local HTTP server

Output formats: JSON, JSONL, and rich terminal output (when `rich` is available).

### 5.2 CLI (`src/textforensics/cli.py`)

Single CLI implementation (argparse, zero extra dependencies). It owns the
`scan`, `report`, `case`, `bundle` (including `check`), `capability`
(including `policy`), `drift`, `verify`, `detectors`, `schema`, `serve`,
`web`, `web-fastapi`, `emergency`, `build-info`, and audit-anchor commands.
The former second CLI (`typer_cli.py`, Typer-based) was deleted in Phase 2;
its only unique commands (`capability policy`, `bundle check`) and its
`--text` input flag were ported into `cli.py`, and the `--typer` delegation
flag and `TEXTFORENSICS_CLI` environment switch were removed.

### 5.3 API / HTTP Server (`src/textforensics/api.py`)

FastAPI-based HTTP server:
- `POST /analyze` — analyze text, returns forensic bundle
- `POST /bundle` — create forensic bundle
- `POST /case` — create sealed case file
- `GET /healthz` — liveness probe
- `GET /readyz` — readiness probe
- `GET /detectors` — list available detectors

**Network safety:** Binds to loopback by default. Remote binding requires `--allow-remote`.

### 5.4 MCP Server (`src/textforensics/mcp_server.py`, `mcp_tools.py`)

Model Context Protocol integration for AI tooling:
- Exposes analysis as MCP tools for LLM agents
- Structured tool responses match detector protocol
- Same privacy guarantees as other interfaces

### 5.5 Browser UI (`src/textforensics/web_ui/`)

Local browser-based interface (FastAPI + WebSocket), started with
`textforensics web` (or `textforensics web-fastapi`, or the
`textforensics-web` console script):
- Runs on same loopback server as API (binds to `127.0.0.1` by
  default; `--allow-remote` for a network-visible bind)
- Renders forensic bundles as structured reports, with Trust Map
  evidence coverage leading instead of a giant certainty percentage
- Sessions/collaboration, analysis history, JSON/CSV/HTML export,
  side-by-side bundle comparison, and streamed per-detector results
  over WebSocket
- `POST /api/report` returns the raw forensic bundle (compatibility
  alias for the former stdlib UI); `POST /api/analyze` returns the
  `{success, data}` wrapper and stores the result in history
- Emergency-stop gate on every request; Content-Security-Policy and
  Permissions-Policy headers on every response
- Requires the `[api]` extra (`pip install "textforensics[api]"`);
  without it the command fails with an install hint
- No telemetry, no external fetches: Chart.js is vendored at
  `web_ui/static/chart.umd.min.js` (v4.4.1)

### 5.6 Python Library API

```python
from textforensics import analyze_text, build_forensic_bundle, verify_case_file

# Direct analysis
result = analyze_text("The text to analyze...")

# Full forensic bundle
bundle = build_forensic_bundle("The text to analyze...")

# Case file verification
report = verify_case_file(case_payload)
```

---

## 6. Schema Versions

| Schema | File | Purpose |
|---|---|---|
| `textforensics.detector-result/v1` | `schemas/detector-result.schema.json` | Detector prediction output |
| `textforensics.forensic-bundle/v1` | `schemas/forensic-bundle.schema.json` | Full analysis report |
| `textforensics.case-file/v1` | `schemas/case-file.schema.json` | Portable sealed artifact |
| `textforensics.trust-map/v1` | `schemas/trust-map.schema.json` | Trust Map assessment |
| `textforensics.drift-corpus/v1` | (inline) | Probe corpus for drift tracking |
| `textforensics.drift-snapshot/v1` | (inline) | Single drift observation |
| `textforensics.drift-snapshot-store/v1` | (inline) | Multiple drift snapshots |
| `textforensics.drift-report/v1` | (inline) | Drift comparison report |
| `textforensics.threshold-selection/v1` | (inline) | Calibration threshold artifact |
| `textforensics.capability-ledger/v1` | (inline) | Capability claims registry |
| `textforensics-ledger/v1` | (inline) | Provenance ledger record |

All schemas are versioned with `/vN` suffixes. Changes to field meaning require version bump.
