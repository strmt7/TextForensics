# Product north star

## One sentence

**TextForensics is the open, local-first audit layer for AI-text detection: it measures detector evidence and tells you when that evidence is — or is not — trustworthy for the exact text, detector version, and operating conditions.**

## The problem

Most AI-text products collapse a complex inference into one visually precise number. That number can hide:
- an unsupported language or genre,
- too little text,
- model/domain shift,
- human editing,
- correlated detectors,
- uncalibrated score semantics,
- changed provider models,
- and human false-positive risk.

The useful product is therefore not another percentage. It is an **audit of the percentage**.

## Primary users

1. **Writers and students** who need to understand or challenge a detector flag.
2. **Educators, editors, publishers and compliance teams** who need evidence without overclaiming.
3. **Researchers and detector developers** who need reproducible cross-detector validation.
4. **Developers/agents** who need a local CLI/API/MCP surface with explicit uncertainty.
5. **Organizations evaluating detector vendors** who need drift and false-positive monitoring.

## Four product surfaces

### 1. Analyze
Run one or more detector families and expose their native evidence without pretending the scores are directly comparable.

### 2. Audit
Given a text and optionally an external detector result, answer:
- Is the input inside validated language/domain/length ranges?
- What is the nearest benchmark slice?
- What was the human false-positive rate there?
- Do methodologically different detectors agree?
- Is the conclusion stable under harmless normalization?
- Is the detector/model/provider version still the one that was validated?

Output: a **Trust Map**, not a magic certainty number.

### 3. Observatory
Run a stable probe corpus repeatedly against versioned local detectors and authorized provider APIs.

Detect:
- score drift,
- threshold/verdict flips,
- calibration drift,
- changes in human-slice false-positive rates,
- provider/model/version changes.

This makes TextForensics useful even when no end-user document is being scanned.

### 4. Case file
Export a portable forensic bundle containing:
- SHA-256 of the input,
- detector/model/provider versions,
- configuration and calibration IDs,
- detector observations,
- Trust Map,
- benchmark slice references,
- stability/drift evidence,
- optional provenance evidence,
- limitations.

Raw document text is excluded by default.

## Flagship workflow

**"Audit this AI flag."**

Input:
- the document,
- optionally the detector/provider and reported score,
- optionally draft/Git/document-history evidence.

TextForensics:
1. fingerprints the input;
2. determines language/length/domain metadata conservatively;
3. collects detector observations;
4. retrieves applicable validation evidence;
5. evaluates benign stability;
6. checks longitudinal drift data if available;
7. builds the Trust Map;
8. incorporates process provenance separately;
9. emits a reproducible case file.

The final result should be capable of saying:

> Detector signals are elevated, but this document is outside the validated domain and the nearest human slice has weak false-positive evidence. Two detector families disagree. Overall evidence coverage is insufficient; do not make an authorship conclusion from the detector output alone.

That is more useful than "73% AI".

## Product principles

- **Evidence before verdict.**
- **Abstention is a feature.**
- **False positives are first-class.**
- **Calibration is versioned evidence, not a checkbox.**
- **Local-first privacy.**
- **Raw score semantics remain visible.**
- **Provenance and detection stay distinct.**
- **Reproducibility beats marketing.**
- **Drift matters because detectors and generators change.**
- **No claim of proof from prose alone.**

## Non-goals

TextForensics is not:
- a plagiarism detector,
- a guaranteed AI-authorship oracle,
- an automatic disciplinary decision-maker,
- a universal "humanizer",
- a tool promising detector bypass,
- or a clone of commercial detector dashboards.

## Success metrics

Technical:
- low and well-characterized human FPR at declared operating points,
- robust held-out performance across multiple benchmark families,
- calibration quality where probabilities are emitted,
- high abstention precision for unsupported regimes,
- reproducible runs,
- detector/plugin contract stability.

Product:
- users can understand *why* a result is weak or strong,
- case files can be independently re-run,
- provider/local-detector drift is surfaced,
- integrations can consume structured evidence without losing caveats.

## Naming

Use **Trust Map** for applicability/reliability coverage.

Avoid:
- "truth score",
- "authorship certainty",
- "proof",
- "100% AI",
- "100% human",
- "undetectable".

