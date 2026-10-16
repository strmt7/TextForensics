# Roadmap

The roadmap is organized around TextForensics' differentiator: **auditing the reliability of AI-text detector evidence**, not merely aggregating detectors.

## v0.1 — foundation
- [x] zero-dependency local heuristic baseline
- [x] basic disagreement/confidence diagnostics
- [x] benign-transformation robustness check
- [x] version comparison
- [x] naturalness audit
- [x] chained local draft ledger
- [x] CLI
- [x] optional MCP server
- [x] optional HTTP API
- [x] local browser UI
- [x] exploratory JSONL benchmark/calibration commands

## v0.2 — interoperability and alpha forensic bundles
- [x] TFDP/1 detector protocol
- [x] explicit raw-score versus calibrated-probability fields
- [x] detector-family metadata
- [x] Python entry-point discovery
- [x] portable bundle with content hash
- [x] detector stability probes
- [x] JSON schemas
- [x] family-aware consensus diagnostics
- [ ] structured plugin-health/error reporting
- [ ] runtime schema/contract validation
- [ ] make alpha heuristic `confidence` semantics unmistakably diagnostic
- [ ] mark the current hand-weighted Verdict Integrity grade as legacy/alpha in all interfaces

## v0.3 — benchmark substrate and detector families

### Evaluation substrate
- [ ] common dataset/example schema
- [ ] run-manifest schema with git/model/data fingerprints
- [ ] split-aware threshold/calibration/test pipeline
- [ ] RAID adapter
- [ ] DetectRL adapter
- [ ] M4 adapter
- [ ] AUROC/AUPRC + operating-point FPR/TPR
- [ ] probability-calibration metrics
- [ ] bootstrap confidence intervals
- [ ] genre/language/length/revision slices

### Detector families
- [ ] supervised open-model adapter
- [ ] likelihood/cross-model detector adapter
- [ ] keep transparent structural/stylometric family as baseline
- [ ] immutable model/download manifests
- [ ] CPU/GPU capability detection

Public accuracy claims start only after reproducible held-out runs exist.

## v0.4 — calibration registry and Trust Map
- [ ] versioned per-detector calibration artifacts
- [ ] explicit calibration validity scope
- [ ] nearest benchmark-slice lookup
- [ ] Trust Map: language
- [ ] Trust Map: length
- [ ] Trust Map: domain/genre
- [ ] Trust Map: editing/revision robustness
- [ ] Trust Map: nearest-slice human FPR
- [ ] Trust Map: detector-family diversity/disagreement
- [ ] Trust Map: benign stability
- [ ] conservative qualitative overall evidence coverage
- [ ] deprecate/replace the hand-weighted Verdict Integrity grade

No numeric Trust Map percentage unless later validated.

## v0.5 — detector observatory and case files
- [ ] stable, license-compatible probe-corpus manifest
- [ ] versioned detector/provider snapshots
- [ ] paired score-drift reports
- [ ] verdict-flip reports
- [ ] human-slice FPR regression checks
- [ ] provider/model-version change tracking
- [ ] case-file v2 schema
- [ ] raw-text-free case export by default
- [ ] deterministic bundle canonicalization/hash
- [ ] case verification command

## v0.6 — authorized provider evidence and richer provenance
- [ ] external-provider adapter contract
- [ ] explicit opt-in network boundary
- [ ] official/authorized APIs only
- [ ] rate/cost/timeout controls
- [ ] Git history importer
- [ ] DOCX revision-history importer where useful history actually exists
- [ ] optional trusted timestamp/signature design with explicit trust model
- [ ] longitudinal validation after provider changes

## v0.7 — local product experience
- [ ] Trust Map UI
- [ ] benchmark-slice explorer
- [ ] detector drift dashboard
- [ ] case-file viewer
- [ ] clear comparison of detector observations versus validation evidence
- [ ] accessibility and offline packaging work

## v1.0 target

A user should be able to run one audit and receive:
- what each detector said,
- what each score means,
- whether the input is inside validated operating conditions,
- nearest-slice false-positive evidence,
- whether independent families agree,
- whether results are stable,
- whether detector/provider behavior has drifted,
- what process-provenance evidence exists,
- and a reproducible case file.

The system must be able to conclude **insufficient evidence** without treating that as failure.

## Non-goals
- claiming a detector score proves authorship;
- treating a clean detector score as proof of human authorship;
- averaging incompatible vendor percentages;
- automatic high-stakes decisions from detector output alone;
- presenting the alpha heuristic grade as a validated trust metric;
- promising guaranteed detector outcomes after rewriting.

See [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) for the detailed engineering sequence.
