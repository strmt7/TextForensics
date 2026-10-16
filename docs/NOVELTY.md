# Landscape and differentiation

This document prevents future contributors from accidentally rebuilding an existing product category.

## What already exists

### Multi-detector workbenches
AITextJury already runs stylometry, perplexity, Fast-DetectGPT, Binoculars, classifiers and plugins side-by-side with local execution and calibration:
https://github.com/YiCQi/AITextJury

**Implication:** "many detectors + local UI + calibration + heatmaps" is not sufficient differentiation.

### Local/MCP detector wrappers
Projects already expose local AI-text classification through CLI/API/MCP surfaces. Examples include:
- https://github.com/houtini-ai/ai-detect

**Implication:** local execution or MCP support is an interface, not the product thesis.

### Detector + rewrite/humanizer loops
Multiple products/repositories already combine detection with rewriting/humanization and MCP-like agent workflows.

**Implication:** do not position TextForensics as "detect, rewrite, repeat until zero".

### Public benchmarks
Strong public evaluation resources already exist:
- RAID: https://github.com/liamdugan/raid
- DetectRL: https://github.com/NLP2CT/DetectRL
- M4: https://github.com/mbzuai-nlp/M4

**Implication:** TextForensics should consume/standardize evidence from these benchmarks, not invent a toy dataset and call it validation.

## The open space TextForensics should own

### 1. Applicability-conditioned reliability
For the current input, determine whether detector performance has actually been validated for its language, length, domain, editing regime and other material conditions.

### 2. Detector drift observatory
Track behavior over time on an immutable probe corpus. Treat detector/provider versions as changing instruments, not timeless truths.

### 3. False-positive-first auditing
Make nearest-slice human FPR, uncertainty and unsupported regimes central to the report.

### 4. Strict calibration semantics
Separate:
- native detector score,
- detector-local calibrated probability,
- threshold/verdict,
- ensemble calibration.

A calibrated component score does not magically calibrate a derived ensemble.

### 5. Reliability-aware disagreement
Measure detector-family diversity and correlation. Five variations of the same classifier family must not create five independent votes.

### 6. Benign stability tests
Test whether punctuation normalization, whitespace/markup changes and other meaning-preserving presentation changes cause material score/verdict movement.

### 7. Longitudinal provider evidence
Where official APIs permit it, preserve timestamped provider observations and detect behavioral/version drift.

### 8. Reproducible forensic case files
Export portable evidence with content hashes, versioned detector observations, Trust Map, benchmark references, drift/stability data and explicit limitations.

### 9. Process provenance
Treat draft/Git/document-history evidence as a separate channel that can corroborate a writing process without pretending it is inferred from prose.

## Positioning sentence

> **TextForensics audits AI-text detectors as instruments.**

That sentence should guide roadmap decisions.

## Novelty test for future features

Before implementing a major feature, search the current ecosystem and answer:

1. Does a maintained open-source project already do this exact workflow?
2. If yes, what reliability/audit capability does TextForensics add?
3. Is the feature part of the north star or merely table stakes?
4. Will it improve validation, reproducibility, false-positive handling, drift monitoring or provenance?
5. Does it reduce scientific ambiguity or merely add another score?

If there is no defensible answer to questions 2 and 4, deprioritize the feature.
