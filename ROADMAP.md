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
- [x] baseline JSONL benchmark command

## v0.2 — real detector plugins
- [ ] detector plugin protocol and entry-point discovery
- [ ] supervised open-model adapter
- [ ] likelihood-based detector adapter
- [ ] per-detector calibration curves
- [ ] sentence/chunk localization
- [ ] CPU/GPU capability detection
- [ ] reproducible model manifests

## v0.3 — benchmarking and calibration
- [ ] RAID-compatible evaluation runner
- [ ] genre and length stratification
- [ ] false-positive-first calibration mode
- [ ] confidence intervals via bootstrap
- [ ] cross-model / unseen-generator evaluation
- [ ] adversarial robustness suite for research evaluation

## v0.4 — provenance
- [ ] Git history importer
- [ ] DOCX revision-history importer where available
- [ ] optional RFC 3161 / OpenTimestamps anchoring
- [ ] portable signed provenance report

## Non-goals
- Claiming a detector score proves authorship.
- Automatic punishment or high-stakes decisions from detector output.
- Promising "100% undetectable" writing.
