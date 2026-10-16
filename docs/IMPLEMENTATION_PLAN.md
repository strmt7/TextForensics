# Implementation plan

This is the staged engineering plan. Do not jump directly to a flashy UI or many detector adapters; build the evidence substrate first.

## P0 — semantics and contracts

### A. Stabilize detector protocol
- Finalize TFDP/1 fields and schema tests.
- Add explicit detector capabilities: language/domain/length support, network behavior, model/checkpoint identity, calibration reference.
- Validate adapter results at runtime.
- Surface broken plugin health instead of silently hiding all failures.
- Keep raw/native score semantics intact.

### B. Remove ambiguous confidence semantics
The v0.1 heuristic engine currently exposes a development `confidence` value. It must remain clearly labeled as a heuristic diagnostic and must not be interpreted as calibrated confidence in authorship.

### C. Split calibration and evaluation
Replace exploratory in-sample threshold tuning with a split-aware pipeline:
- threshold/training split,
- calibration split,
- final held-out test split.
Persist dataset fingerprints and prevent accidental reuse where possible.

## P1 — benchmark substrate

### D. Common example/run schema
Define:
- immutable sample ID,
- label/provenance metadata,
- domain/genre,
- language,
- generator/model when known,
- decoding metadata when known,
- editing/attack regime,
- text length,
- source dataset/version/fingerprint.

Prediction rows should include detector/version/config and run ID.

### E. Benchmark adapters
Implement dataset adapters rather than copying datasets into the repository:
1. RAID
2. DetectRL
3. M4

Add a tiny synthetic/smoke fixture only for CI mechanics; never use it for public accuracy claims.

### F. Metrics
At minimum:
- AUROC,
- AUPRC,
- confusion matrix at declared operating points,
- human FPR,
- TPR/recall,
- TPR at low-FPR operating points,
- Brier/ECE for calibrated probabilities,
- abstention/coverage,
- latency and memory,
- bootstrap confidence intervals.

### G. Slicing
Produce metrics by:
- generator/model,
- domain/genre,
- language,
- length bucket,
- decoding regime,
- edit/paraphrase/attack regime,
- relevant human-writing cohort/style when ethically and legally supportable.

## P2 — detector families

Add independent families one at a time and benchmark each before fusion.

Candidate order:
1. supervised open classifier,
2. likelihood/curvature or cross-model method,
3. structural/stylometric baseline,
4. provenance/watermark evidence when verifiable,
5. optional authorized commercial observations.

Do not add three classifiers merely to increase detector count.

For each adapter:
- pin model/version,
- record license,
- declare local/remote behavior,
- benchmark,
- calibrate separately,
- document failure modes.

## P3 — calibration registry

Create versioned calibration artifacts containing:
- detector/version/config,
- calibration method,
- dataset fingerprint and slice,
- sample counts,
- created-at/git SHA,
- metrics,
- thresholds,
- validity scope.

No top-level ensemble probability until there is:
- an exact ensemble specification,
- a missing-detector policy,
- an independently fitted ensemble calibration,
- a held-out evaluation.

## P4 — Trust Map

### Inputs
- document metadata,
- detector observations,
- benchmark slice registry,
- calibration registry,
- benign-stability results,
- detector disagreement/family structure,
- observatory drift snapshots.

### Initial dimensions
- language,
- length,
- domain,
- editing robustness,
- nearest-slice human FPR,
- detector diversity/disagreement,
- benign stability,
- temporal/version stability.

### Output
Each dimension:
- state: `supported | partial | unknown | out_of_scope`
- reason,
- evidence reference,
- detector/version scope,
- timestamp where applicable.

Overall composition is conservative and qualitative for v1.

## P5 — detector observatory

### Probe corpus
Create a manifest for a small, stable, license-compatible probe set:
- human controls,
- machine controls from multiple model families where licensing permits,
- edited controls,
- short/long texts,
- multiple domains/languages over time.

Store immutable hashes and provenance.

### Snapshots
For local/versioned detectors and opt-in official provider APIs, record:
- timestamp,
- provider/model/version metadata,
- native score/verdict,
- config,
- latency,
- errors.

### Drift reports
Measure:
- paired score deltas,
- distribution shift,
- verdict flips,
- human-slice FPR change,
- calibration change,
- changed/unknown provider version.

Require multiple probes before declaring drift.

## P6 — forensic case files

Define a stable JSON schema for:
- TextForensics version/git SHA,
- input hash and non-sensitive metadata,
- detector observations,
- calibration references,
- Trust Map,
- benign-stability evidence,
- drift evidence,
- optional external detector observation,
- optional process provenance,
- limitations,
- canonical bundle hash.

Raw text: excluded by default.

Later:
- human-readable HTML/PDF renderer,
- optional signature/trusted timestamp only with sound key/timestamp design.

## P7 — interfaces

Build all interfaces over the same core:
- Python API,
- CLI,
- MCP,
- optional localhost HTTP API,
- later local desktop/web UI.

Target commands:
- `analyze`
- `audit-flag`
- `compare`
- `benchmark`
- `calibrate`
- `trust-map`
- `observatory run|diff`
- `case export|verify`
- `provenance ...`

MCP tools should return structured evidence and limitations, not only prose.

## P8 — authorized external providers

Provider adapter contract:
- explicit opt-in,
- official/authorized API only,
- user-supplied credentials,
- visible network boundary,
- timeout/retry/rate/cost controls,
- timestamp and provider version metadata where exposed,
- no treatment of provider consensus as ground truth.

## P9 — provenance importers

Add:
- Git history importer,
- DOCX revision-history importer where the format actually contains useful history,
- optional trusted timestamp integration,
- portable provenance report.

Do not imply that a local hash chain alone proves when content existed.

## P10 — writing review

Only after the forensic core is strong.

Allowed goals:
- clarity,
- specificity,
- author voice,
- sentence/paragraph quality,
- semantic preservation,
- diagnosis of false-positive-correlated features.

Do not build an objective function whose only target is "make every detector say human".

## Release sequence

### v0.2
Contracts, split-aware benchmark harness, run manifests.

### v0.3
Three genuinely different detector families + reproducible benchmark reports.

### v0.4
Calibration registry + Trust Map alpha.

### v0.5
Observatory + drift reports + case-file v2.

### v0.6
Authorized provider adapters + richer provenance.

### v1.0
Stable schemas/interfaces, reproducible benchmark suite, documented operating envelope, conservative release claims.

## Definition of done for any public performance claim

A claim is publishable only when:
- code is committed,
- detector/model/data versions are pinned,
- final evaluation is held out,
- run manifest is archived,
- uncertainty/CI is reported,
- human FPR is visible,
- relevant slices are visible,
- known limitations are adjacent to the claim,
- another contributor can reproduce it from documentation.
