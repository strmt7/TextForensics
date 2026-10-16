# Threat model

TextForensics handles sensitive text and produces evidence that can be overinterpreted. Security therefore includes both software threats and inference/communication threats.

## Assets
- private document text,
- provider/API credentials,
- detector/model artifacts,
- calibration and benchmark artifacts,
- provenance ledgers,
- forensic case files,
- integrity of reported detector/version metadata.

## Threats and controls

### 1. Unintended text exfiltration
Risk: an optional adapter, log, error handler or UI sends/stores source text unexpectedly.

Controls:
- local core by default,
- explicit remote opt-in,
- no raw-text logs by default,
- sanitize provider errors,
- raw-text-free portable case files.

### 2. Misleading score semantics
Risk: a raw classifier score is presented as a probability.

Controls:
- TFDP score-semantics field,
- separate calibrated-probability field,
- calibration ID requirement,
- schema/contract tests.

### 3. Correlated-detector confidence inflation
Risk: many related classifiers create a false impression of independent agreement.

Controls:
- detector-family metadata,
- family-aware diagnostics,
- empirical correlation analysis,
- separate ensemble validation.

### 4. Benchmark leakage
Risk: benchmark samples influence training, threshold selection, prompts or calibration and inflate evaluation.

Controls:
- split fingerprints,
- source/near-duplicate grouping,
- separate development/calibration/final evaluation,
- run manifests.

### 5. Provider drift
Risk: a remote provider silently changes behavior while old calibration assumptions remain.

Controls:
- timestamps/version metadata,
- stable probe corpus,
- observatory snapshots,
- invalidate/downgrade applicability after material drift.

### 6. Model supply chain
Risk: model weights/dependencies change or are replaced.

Controls:
- immutable revisions/checksums where practical,
- explicit download manifests,
- dependency review,
- record model identity in reports.

### 7. Input canonicalization confusion
Risk: visually similar Unicode/formatting produces different hashes or detector behavior.

Controls:
- define hashing/canonicalization semantics,
- preserve original-content hash,
- test benign variants separately,
- never silently normalize evidence without recording it.

### 8. Case-file tampering
Risk: report contents change after generation.

Controls:
- deterministic canonicalization,
- bundle hash,
- optional signatures/trusted timestamp only after a clear trust model.

A hash proves integrity relative to the hash, not who authored the document.

### 9. False-certainty UX
Risk: users treat a polished grade/percentage as proof.

Controls:
- visible limitations,
- abstention,
- Trust Map,
- nearest-slice FPR,
- no giant unsupported certainty number,
- high-stakes-use warning.

### 10. Plugin failures or malicious plugins
Risk: third-party detector packages execute arbitrary Python or return malformed/misleading results.

Controls:
- plugins are trusted code and must be described as such,
- runtime result validation,
- plugin health reporting,
- optional isolation/sandboxing as a future enhancement,
- do not auto-install plugins from untrusted sources.

## Out of scope for current alpha
- hardened sandbox for arbitrary third-party detector code,
- remote multi-user tenancy,
- enterprise secret management,
- formal cryptographic identity infrastructure.

These can be added if deployment scope expands.
