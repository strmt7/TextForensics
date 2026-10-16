# Roadmap

## v0.1 — foundation
- [x] zero-dependency local heuristic ensemble
- [x] disagreement and confidence
- [x] benign-transformation robustness check
- [x] version comparison
- [x] naturalness audit
- [x] chained local draft ledger
- [x] CLI
- [x] MCP server (optional extra)
- [x] HTTP API (optional extra)
- [x] baseline JSONL benchmark and calibration commands

## v0.2 — detector interoperability and forensic bundles
- [x] TFDP/1 detector protocol
- [x] explicit raw-score vs calibrated-probability semantics
- [x] detector-family metadata
- [x] Python entry-point discovery
- [x] portable forensic bundle with content hash
- [x] per-document Verdict Integrity grade
- [x] detector stability probes
- [x] JSON schemas
- [ ] plugin health/error reporting
- [ ] cryptographic signing of forensic bundles

## v0.3 — serious detector adapters
- [ ] supervised open-model adapter
- [ ] likelihood/curvature detector adapter
- [ ] alignment-imprint / representation detector adapter
- [ ] optional user-configured commercial API adapters
- [ ] model/download manifests with immutable revisions
- [ ] CPU/GPU capability detection
- [ ] sentence/chunk localization normalized across adapters

## v0.4 — evidence-grade validation
- [ ] RAID-compatible evaluation runner
- [ ] NIST-style calibration metrics (Brier, reliability curves)
- [ ] genre/language/length stratification
- [ ] false-positive-first operating points
- [ ] confidence intervals via bootstrap
- [ ] cross-model and unseen-generator evaluation
- [ ] benign-perturbation sensitivity matrix
- [ ] empirical mapping from evidence conditions to Verdict Integrity grades

## v0.5 — provenance and reproducibility
- [ ] Git history importer
- [ ] DOCX revision-history importer where available
- [ ] optional trusted timestamp anchoring
- [ ] signed portable forensic report
- [ ] reproducibility verifier that re-runs a bundle against pinned local detector versions

## v1.0 target

A user should be able to install several detector adapters, run **one command**, and receive a report that tells them not only what each detector said but whether the overall detector evidence deserves trust.

## Non-goals
- Claiming a detector score proves authorship.
- Averaging incompatible vendor percentages.
- Automatic punishment or high-stakes decisions from detector output alone.
- Promising "100% undetectable" writing.
