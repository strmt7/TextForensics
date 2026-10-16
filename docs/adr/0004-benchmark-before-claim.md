# ADR 0004 — Benchmark before claim

**Status:** accepted

## Decision

Public performance/comparison claims require a reproducible held-out benchmark artifact for the exact committed system.

## Why

Detector performance changes across domains, languages, generators, revisions and versions. Quoting a paper or evaluating on development data is not evidence for the released product.

## Consequences

- maintain run manifests and dataset fingerprints;
- keep calibration/test data separate;
- show human FPR and relevant slices;
- remove or qualify claims that cannot be reproduced.
