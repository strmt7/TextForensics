# Changelog

All notable user-visible changes are documented here.

The project is pre-1.0. Public schemas and detector/calibration semantics are treated as contracts and should still be versioned deliberately.

## [Unreleased]

### Added
- strict TFDP/1 runtime result validation;
- detector plugin-health reporting with redacted failure messages;
- qualitative `textforensics.trust-map/v2` (v3, which adds a `stale`
  state for registry-derived maps, added in U1 — see below);
- sealed, raw-text-free `textforensics.case-file/v3` artifacts
  (v2/v1 still verify; v3 is the default seal since U2 — see below);
- case export/verification CLI;
- split-aware calibration artifacts and held-out evaluation guard;
- unified environment configuration and UTF-8 input-size limits;
- API health/readiness/version/detector-health endpoints;
- current MCP v2 server support;
- host-safe ASGI/API runner;
- packaged JSON schemas;
- multi-stage non-root OCI image and Compose example;
- Linux/macOS/Windows smoke CI;
- Python 3.11–3.15 test matrix;
- wheel build/install validation;
- CodeQL, dependency-review, dependency-audit, Dependabot and release-build workflows;
- installation, operations, support and commercial-readiness documentation.

### Changed
- Python 3.10 is no longer supported after its upstream end-of-life; CI now covers Python 3.11–3.15.
- the legacy `confidence` value is explicitly labeled an **uncalibrated diagnostic reliability heuristic**;
- the legacy Verdict Integrity grade is explicitly marked an unvalidated alpha compatibility diagnostic;
- the browser UI now leads with Trust Map evidence coverage rather than the legacy grade;
- consensus no longer averages detector-local probabilities into an ensemble probability;
- non-loopback network binding requires explicit opt-in;
- corrupted provenance ledgers cannot be appended to silently.

### Security
- detector/plugin exceptions are redacted before inclusion in reports;
- raw submitted text remains absent from portable case artifacts by default;
- default API access logging is disabled;
- browser UI sends no-store, CSP, no-sniff, no-referrer, and permissions-policy headers;
- container runtime uses a non-root numeric UID.

### Phase 2 — Consolidation (2026-11-06)

- One CLI: the Typer-only CLI was ported into `cli.py` and deleted
  (1,251 lines); one web UI: `webapp.py` was deleted and its surface
  ported into the FastAPI `web_ui/`; one verifier entry point and one
  bundle format.
- Consensus, calibration, benchmark and observatory modules merged;
  tiny modules folded. Outcome: 68 → 46 modules, 28,804 → 28,150
  source lines (the ~35-module / ~18k-line target was not reached;
  the remaining merges would have cost features — see
  `docs/VERIFICATION.md` Phase 2).
- Real bug fix in the merge: `validate_no_contamination` never
  detected partial overlap; both sides now hash samples the same way.
- Telemetry deleted outright: `telemetry.py` (375 lines) removed,
  with the `--metrics` flag and the `[telemetry]` extra; no
  OpenTelemetry import remains in `src/`, guarded by
  `tests/test_no_telemetry.py`.
- Determinism fix: `TRUST_STATES` is an ordered tuple, so Trust Map
  coverage keys serialize in declared order across processes.
- Adversarial bright-line test proving `adversarial.py` never emits
  rewrite suggestions.
- Model-card / compliance outputs renamed to transparency notes; the
  builder no longer asserts a risk class, conformity assessment, or
  CE marking, and the licence default is the project's actual
  `AGPL-3.0-or-later`.

### Phase 3 — Uniqueness (2026-11-06 – 2026-11-07)

- U7 claim-to-evidence gate: `scripts/check_claims.py` verifies every
  claim in `docs/CLAIMS.yaml` against a measured run artifact in
  `docs/evidence/runs/` (registry `docs/evidence/registry.json`,
  deterministic `docs/evidence/report-card.md`); a claims-gate CI job
  runs it on every push. 33 claims, all evidence-linked. Packaged
  schemas grew from 5 to 7 with the run-artifact and
  evidence-registry schemas.
- Datasets wave 1: preliminary builtin-heuristic measurements for
  RAID (strided n=3000, AUROC 0.5937), MAGE (n=400, AUROC 0.5567),
  Beemo (AUROC 0.3976) and OpAI-Bench (AUROC 0.3961); MixSet is
  licence-blocked. All measurements are preliminary and no new
  performance claims were made from them.
- U1 validation-evidence registry: `textforensics.evidence-record/v1`
  + `textforensics.validation-registry/v1` with a validator-enforced
  partial cap, licence/contamination hard rejections, SHA-256
  hash-seal signatures and computed staleness; Trust Map v3
  (`textforensics.trust-map/v3`) adds the `stale` state for
  registry-derived maps. Seeded with preliminary records, all
  `partial`.
- Datasets wave 2: GhostWriter measured (474,904 rows, strided n=500,
  AUROC 0.436) and DetectRL-X measured (124,800 rows, strided
  n=400→800 rows, AUROC 0.5972, exactly 100 rows per language);
  DetectRL, M4 and M4GT-Bench are licence-blocked with refusing
  loaders (no live rows, no artifacts). A shared resumable
  stdlib-only downloader was added.
- U2 sealed replayable text-free case file: case-file v3 is the
  default seal — T1 hash seal always, T2 Ed25519/DSSE detached
  signature, T3 RFC 3161 timestamp (opt-in; free-TSA tokens are
  honestly labelled non-qualified), custody hash chain, and the
  D1–D10 process checklist. A dependency-free standalone verifier
  and sealed-bundle packing (`sealed_bundle.py`) were added; v2/v1
  case files still verify. Known gap: live-TSA interop was not
  achieved from the development VM, and no seal-time
  `not_reproducible` declaration exists yet for non-deterministic
  detectors.
- U3 drift observatory: probe-run engine with three-tier
  persistence-gated alerts and a demotion hook into the validation
  registry, `tf drift run` / `tf drift status` CLI, and a frozen
  probe corpus v1.0.0 (400 items, 8 slices × 50, disjoint from U1 by
  content hash). First live probe run (baseline): 0 alerts.
- U4 mixed-origin / co-authorship report: `tf mixed-origin` and the
  `textforensics.mixed-origin-report/v1` schema, validated at
  segment level on OpAI-Bench. Honest negative result: the builtin
  heuristic cannot separate AI from human sentences (pooled segment
  AUROC 0.4772, below chance); every segment claim stays
  `partial`/`unknown` and no cell meets the `supported` bar.
- Packaged schemas grew to 12; worst-slice human false-positive rate
  remains **unknown** (see `docs/evidence/report-card.md`).

### Phase 4 — Dependabot recovery (2026-11-07)

- All 10 Dependabot PRs #25–#34 closed unmerged by the 2026-11-06
  history rewrite were recovered onto main: #34 pytest-cov `<8`,
  #25 attest-build-provenance v1→v4, #29 build-push-action v6→v7,
  #27 cryptography `<43`→`<51`, #32 rich `<16`, #33 pytest `<10`,
  #26 codeql-action v4.39.3, #28 setup-buildx v4, #31
  metadata-action v6; #30 pytest-timeout was already satisfied
  (no-op).
- Two pre-existing PR-only CI defects found by the first recovered
  PR and fixed: a typo'd action SHA in the dependency-review
  workflow and a dead SARIF-conversion step (`sarif-tool` does not
  exist on PyPI) in the dependency-audit workflow.
- Node 24 sweep (PRs #40–#46) and a twine `<8` follow-up landed;
  0 open PRs and 0 surviving Dependabot branches remain.

### Phase 5 — Release gate (2026-11-07)

- Wave 1: atheris 1.0.11 → 3.x (`atheris>=3.0,<4`), so the pinned
  requirements install is green; Mutation wiring rewritten for
  cosmic-ray 8.x and proven live (proof push: 200 work items, 77
  killed, 123 survived, job failing by design on survivors);
  CodeQL concurrency made per-PR. Fuzz follow-ups: a latent
  `instrument_func` bug fixed, `-runs=0` honoured, and the fuzz
  timeout design fixed (Regression 60 min, Extended 120 min).
- Wave 2: equivalent-mutant baseline (73 entries) and 26
  Trust-mutation kill tests; proof run 200 total, 127 killed / 73
  surviving, 0 unexplained survivors (69 annotation `BitOr`
  mutants, never evaluated at runtime, plus 4 proven-equivalent).
  The gate still fails on unexplained survivors and on stale
  baselines.
- Wave 3: downloader urllib tuning (split connect/stall timeouts,
  jittered capped back-off, Content-Length truncation check) plus a
  curl fallback for stalled downloads; stall-server tests and a
  weekly prefix-probe workflow. Live evidence: the full 879 MB
  DetectRL-X download via the shipped loader verified
  (878,631,989 bytes, SHA-256 match).
- Wave 4: all 13 latent defects from the release-gate register
  fixed, including the High-severity pair #1+#8 — the policy floor
  is now fail-closed (a corrupt policy state file or a wrong-length
  key file is an error, not a silent reset to 0) — plus the
  `disable` flag being ignored and ledger streaming fixes. 70 new
  kill tests, 82 baseline entries, and a new `unobservable-value`
  baseline kind; mutation proof runs exit 0 at budget 200.

## [0.1.0]

Initial alpha foundation:
- dependency-free heuristic baseline;
- local CLI/browser UI;
- TFDP detector protocol;
- forensic bundle;
- MCP/API scaffolding;
- provenance ledger;
- benchmark/calibration scaffolding.
