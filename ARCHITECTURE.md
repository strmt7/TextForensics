# Architecture

TextForensics treats AI-text detectors as **fallible, versioned measurement instruments**.

## North-star rule

**A score is not a probability, agreement is not independence, and text-only detection is not proof of authorship.**

The long-term architecture therefore separates:
1. detector observations,
2. validation/calibration evidence,
3. applicability (Trust Map),
4. optional ensemble inference,
5. stability and temporal drift,
6. process provenance,
7. portable case files.

See [AGENTS.md](AGENTS.md) for the non-negotiable development contract.

## Current alpha architecture

The repository already provides useful scaffolding:

1. **TFDP/1 detector protocol** — explicit detector identity, family, native score semantics, verdict and calibration fields.
2. **Detector registry** — built-ins plus third-party Python entry points.
3. **Built-in heuristic baseline** — zero-dependency stylometric/structural signals for exercising interfaces and tests.
4. **Forensic orchestrator** — runs detectors without converting every raw score into a probability.
5. **Benign-stability probes** — rescore harmless text-normalization variants.
6. **Forensic bundle** — content hash, detector observations, robustness and optional provenance evidence.
7. **Provenance ledger** — local chained draft hashes kept separate from linguistic inference.
8. **Interfaces** — Python, CLI, local browser UI, MCP and optional HTTP API.

## Important alpha limitation: Verdict Integrity

The current code has a `Verdict Integrity` grade based on hand-designed factors such as text length, detector-family count, calibration availability, agreement and benign stability.

That grade is **an engineering heuristic, not a validated probability, reliability estimate, or scientifically calibrated trust score**.

Rules:
- do not market the grade as evidence that a verdict is correct;
- do not optimize product decisions around raising the grade;
- do not publish A/B/C/D boundaries as scientifically validated;
- keep its factors inspectable;
- replace it with the benchmark-backed Trust Map described below.

The long-term project should prefer a qualitative applicability statement backed by concrete evidence over a polished but arbitrary numeric score.

## Target evidence architecture

### Layer A — detector observation

A detector adapter returns what the instrument actually observed:
- detector ID/version/family,
- local or remote execution,
- raw/native score,
- score direction/semantics,
- detector verdict or abstention,
- threshold if defined,
- optional calibrated probability + calibration ID,
- runtime/errors/warnings,
- declared operating constraints.

Raw scores stay raw.

### Layer B — validation registry

Validation artifacts describe where a detector has demonstrated performance:
- detector/model/config version,
- dataset and split fingerprint,
- language/domain/length/revision slice,
- human false-positive rate,
- TPR/recall at declared thresholds,
- AUROC/AUPRC,
- calibration metrics where probabilities exist,
- confidence intervals,
- evaluation date and git SHA.

This is evidence about the instrument, not about one document.

### Layer C — Trust Map

The Trust Map joins a current input with applicable validation evidence.

Initial dimensions:
- language coverage,
- text-length coverage,
- domain/genre coverage,
- editing/revision robustness,
- nearest-slice human FPR evidence,
- detector-family diversity and disagreement,
- benign-transformation stability,
- detector/provider temporal stability.

Initial states:
- `supported`
- `partial`
- `unknown`
- `out_of_scope`

Do **not** turn these into a 0–100 trust percentage before such an aggregation is empirically validated.

### Layer D — optional ensemble inference

Fusion is optional, not mandatory.

If TextForensics ever emits a top-level calibrated probability, it requires:
- a fixed/versioned detector set,
- explicit missing-detector behavior,
- a separately fitted ensemble calibration artifact,
- held-out evaluation for that ensemble,
- an abstention policy.

**Detector-local calibrated probabilities do not make their arithmetic mean a calibrated ensemble probability.**

Family-balanced categorical consensus may be useful as a diagnostic, but consensus remains separate from calibrated inference.

### Layer E — stability and observatory

Two mechanisms:

**Per-document benign stability**
- whitespace normalization,
- punctuation normalization,
- markup/list normalization,
- similarly harmless presentation changes.

**Longitudinal observatory**
Run a stable probe corpus against versioned local detectors and explicitly configured official provider APIs over time.

Track:
- paired score movement,
- verdict flips,
- score-distribution shift,
- calibration/FPR regression,
- detector/provider version changes.

Never infer provider drift from one document.

### Layer F — process provenance

Examples:
- local draft hash ledger,
- Git history,
- document revision history where genuinely available,
- optional external trusted timestamps/signatures.

Process provenance answers a different question from linguistic inference and stays separately typed.

### Layer G — case file

The long-term portable artifact should contain:
- TextForensics version/git SHA,
- input hash and non-sensitive metadata,
- detector observations,
- calibration/benchmark references,
- Trust Map,
- stability/drift evidence,
- optional process provenance,
- limitations.

Raw input text is omitted by default.

## TFDP/1

See [SPEC.md](SPEC.md) and the detector JSON schema.

A third-party adapter should depend on public protocol objects rather than internal implementation details.

Before an adapter becomes eligible for any calibrated fusion, it must satisfy the benchmark/calibration gates in:
- [docs/BENCHMARKING.md](docs/BENCHMARKING.md)
- [docs/QUALITY_GATES.md](docs/QUALITY_GATES.md)

## Why detector families matter

Multiple models can share training data, architecture, objective and failure modes. Counting them as independent votes can create artificial confidence.

TextForensics should therefore track methodological families and, when enough data exists, empirical error correlation. Detector count alone is not evidence diversity.

## Why provenance remains separate

A detector infers patterns from final text. Provenance records aspects of the creation process. Combining them into one opaque number would destroy interpretability and require a separately validated probabilistic model.

Keep the evidence channels distinct.

## Architecture priority

Build in this order:
1. stable contracts,
2. reproducible benchmark/run artifacts,
3. genuinely different detector families,
4. calibration registry,
5. Trust Map,
6. observatory/drift,
7. case-file evolution,
8. remote provider adapters,
9. presentation/UI refinement.

Do not reverse this order just to produce a visually impressive demo.
