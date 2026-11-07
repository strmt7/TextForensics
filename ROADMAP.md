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
- [x] structured plugin-health/error reporting (Phase 1)
- [x] runtime schema/contract validation (Phase 1)
- [x] make alpha heuristic `confidence` semantics unmistakably diagnostic (Phase 1)
- [x] mark the current hand-weighted Verdict Integrity grade as legacy/alpha in all interfaces (Phase 1)

## v0.3 — benchmark substrate and detector families

### Evaluation substrate
- [x] common dataset/example schema (Phase 3, datasets waves 1–2: `datasets.py`, `NormalizedRow`)
- [x] run-manifest schema with git/model/data fingerprints (Phase 3, U7: run-artifact schema)
- [x] split-aware threshold/calibration/test pipeline (`calibrate`/`benchmark`/`select-threshold` + disjointness checks)
- [x] RAID adapter (Phase 3, datasets wave 1: loader + preliminary measurement)
- [ ] DetectRL adapter — blocked: no licence anywhere (refusing loader shipped, Phase 3 wave 2; no live rows)
- [ ] M4 adapter — blocked: no licence anywhere (refusing loader shipped, Phase 3 wave 2; no live rows)
- [x] AUROC/AUPRC + operating-point FPR/TPR (Phase 3, U1 records)
- [x] probability-calibration metrics (Brier / ECE / log-loss in `calibration.py`)
- [x] bootstrap confidence intervals (1000 resamples, seed 20261106)
- [x] genre/language/length/revision slices (Phase 3, U1 records)

### Detector families
- [ ] supervised open-model adapter
- [ ] likelihood/cross-model detector adapter
- [x] keep transparent structural/stylometric family as baseline (builtin heuristic detector)
- [ ] immutable model/download manifests
- [ ] CPU/GPU capability detection

Public accuracy claims start only after reproducible held-out runs exist.

## v0.4 — calibration registry and Trust Map
- [x] versioned per-detector calibration artifacts (`CalibrationArtifact` with fit/evaluation provenance)
- [ ] explicit calibration validity scope
- [x] nearest benchmark-slice lookup (Phase 3, U1: `validation.py` registry matching / `derive_trust_map`)
- [x] Trust Map: language
- [x] Trust Map: length
- [x] Trust Map: domain/genre
- [x] Trust Map: editing/revision robustness
- [x] Trust Map: nearest-slice human FPR
- [x] Trust Map: detector-family diversity/disagreement
- [x] Trust Map: benign stability
- [x] conservative qualitative overall evidence coverage
- [x] deprecate/replace the hand-weighted Verdict Integrity grade (Phase 1: legacy, `include_legacy=True` only)

No numeric Trust Map percentage unless later validated.

## v0.5 — detector observatory and case files
- [x] stable, license-compatible probe-corpus manifest (Phase 3, U3: frozen probe corpus v1.0.0, 400 items, licences resolved first)
- [x] versioned detector/provider snapshots (Phase 3, U3: `textforensics.probe-run/v1` run manifests)
- [x] paired score-drift reports (Phase 3, U3: per-slice KS/PSI)
- [x] verdict-flip reports (Phase 3, U3: directional flips with Wilson CI)
- [x] human-slice FPR regression checks (Phase 3, U3: verdict-based human FPR, 0.05 cap, Tier-1 demotion on breach)
- [x] provider/model-version change tracking (Phase 3, U3: provider metadata diff; version change goes stale after 7 days without a probe run)
- [x] case-file v2 schema (v3 is now the default seal, Phase 3 U2; v2/v1 still verify)
- [x] raw-text-free case export by default
- [x] deterministic bundle canonicalization/hash (MPL sealed bundle, Phase 3 U2)
- [x] case verification command (`case verify`)

## v0.6 — authorized provider evidence and richer provenance
- [ ] external-provider adapter contract
- [ ] explicit opt-in network boundary
- [ ] official/authorized APIs only
- [ ] rate/cost/timeout controls
- [ ] Git history importer
- [ ] DOCX revision-history importer where useful history actually exists
- [x] optional trusted timestamp/signature design with explicit trust model (Phase 3, U2: T1 hash seal, T2 Ed25519/DSSE signature, T3 RFC 3161 timestamp, honestly labelled non-qualified for free TSAs)
- [x] longitudinal validation after provider changes (Phase 3, U3 drift observatory: scheduled probe runs, version-change staleness)

## v0.7 — local product experience
- [x] Trust Map UI (web UI Trust Map section)
- [ ] benchmark-slice explorer (no such view in `web_ui/`)
- [ ] detector drift dashboard (no such view in `web_ui/`)
- [ ] case-file viewer (no such view in `web_ui/`)
- [ ] clear comparison of detector observations versus validation evidence
- [ ] accessibility and offline packaging work

## Revamp track

How the v0.x items above map to the revamp phases (2026-11-06–07).
Detail lives in `~/workspace/goals/textforensics-complete-revamp/hidden_files/`
(the goal working notes, not in this repo) and in
`docs/VERIFICATION.md`.

- **Phase 1 — Make it true: done** (2026-11-06, pushed `42d70e4`).
  The four v0.2 items above; CI-greening fixes.
- **Phase 2 — Consolidation: done** (2026-11-06, pushed `e99c474`).
  One CLI, one web UI, one verifier + one bundle format, telemetry
  deleted outright. Outcome 46 modules / 28,150 src LOC — the
  ~35 modules / ~18k LOC target was NOT reached; remaining merges
  would have cost features.
- **Phase 3, U7 — claim-to-evidence CI gate: done** (pushed
  `2bc6e03`). 33 claims, evidence registry, report card, claims-gate
  CI job.
- **Phase 3, datasets waves 1–2: done** (wave 1 head `2e2d81a`,
  wave 2 head `5ab3c45`). Measured preliminarily: RAID, MAGE,
  Beemo, OpAI-Bench, GhostWriter, DetectRL-X. Licence-blocked with
  refusing loaders: MixSet, DetectRL, M4, M4GT-Bench. PAN 2025
  pending Greg's TIRA registration.
- **Phase 3, U1 — validation-evidence registry: done** (head
  `596d10a`). 7 records, all `partial` (6 dataset seeds + 1 U4
  segment record); Trust Map v3 with the `stale` state.
- **Phase 3, U2 — sealed case file: done** (pushed `5bf4ce3`;
  Python 3.15 base64 fix `ca3af3d`). Case-file v3, T1/T2/T3 seal,
  D1–D10 checklist, custody chain, standalone verifier.
- **Phase 3, U3 — drift observatory: done** (pushed `87dde38`).
  Probe corpus v1.0.0 (400 items), probe-run engine, `tf drift run`
  / `tf drift status`, monthly/quarterly cadence. First live probe
  run: 0 alerts, pooled human FPR 0.0 [0.0, 0.0298].
- **Phase 3, U4 — mixed-origin report: done** (pushed `f1f391c`).
  Honest negative result: the builtin heuristic cannot separate AI
  from human sentences (pooled segment AUROC 0.4772).
- **Phase 4 — Dependabot recovery: done** (pushed `ca56440`). All
  10 original PRs (#25–#34) recovered on main, plus the Node 24
  sweep (#40–#46) and the twine bump.
- **Phase 5, wave 1: done** (pushed `76fc8b1`). Atheris 3.x,
  Mutation cosmic-ray 8.x wiring, CodeQL per-PR concurrency.
  Pinned-install green on main.
- **Phase 5, wave 2: done** (pushed `02929ce`). Equivalent-mutant
  baseline (73 entries) + 26 kill tests; Mutation run on main:
  200 total, 127 killed / 73 surviving, 0 unexplained.
- **Phase 5, wave 3: done** (pushed `1e0fb2b`). Downloader urllib
  tuning + curl fallback; full 879 MB DetectRL-X download via the
  shipped loader, SHA-256 match. Curl fallback firing on a real
  stall is NOT proven live.
- **Phase 5, wave 4: done** (HEAD `264344e`). All 13 latent
  defects fixed (policy floor fail-open, disable action, adversarial
  fabrications, and the rest).
- **Docs wave: in progress.** This file, README / CHANGELOG /
  SECURITY / RELEASE / SPEC / CLAIMS / VERIFICATION consistency
  against current main.
- **Remaining release-gate items:** human-FPR evidence (worst-slice
  human FPR still unknown — see `docs/evidence/report-card.md`),
  live-host verification (Docker + API + web UI on a live host),
  `pip-audit` as a failing gate for runtime extras, SBOM in the
  release workflow, live-TSA interop (never achieved from the
  sandbox VM), the seal-time `not_reproducible` declaration for
  non-deterministic detectors, and the coverage gate (still
  `--fail-under=70` in CI, not yet raised to the measured ~83%).
  No release is created without Greg's explicit say-so.

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
