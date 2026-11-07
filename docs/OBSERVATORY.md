# Drift observatory — operator guide (U3)

The observatory is TextForensics' longitudinal reliability layer: it
re-scores a frozen probe corpus on a schedule and reports whether a
detector still behaves the way its validation evidence says it
should. It is not a detector, and it does not change verdicts on
user text. It changes what the project claims about a detector.

## Concepts

**Frozen probe corpus v1.0.0.** 8 slices × 50 items (400 items),
each with a stable item ID and a content hash, built by
`scripts/build_probe_corpus.py` (corpus half, branch `u3-corpus`)
from licence-cleared datasets. The slices are: `human-native`,
`human-short`, `ai-current-generator`, `ai-legacy-generator`,
`ai-paraphrased`, `ai-humanized`, `mixed-origin`,
`benign-transformed`. The 9th slice prescribed by the research
(`human-non-native` / ESL) is cut in v1.0.0 — no licensed source
was found; see the corpus manifest's notes. The corpus lives in the
cache (`~/.cache/textforensics/probe-corpus/1.0.0/`:
`manifest.json`, `corpus.jsonl`, `holdback.jsonl`), never in the
repo. The manifest is copied into the repo at
`docs/probe-corpus/v1.0.0/manifest.json` by hand after verification.

**Probe run.** One scoring pass over the corpus (or a scoped subset)
plus the §7.6 metrics, the three-tier evaluation, and a run manifest
(schema `textforensics.probe-run/v1`). Run manifests live in
`~/.cache/textforensics/probe-runs/<corpus version>/run-<id>.json`
and cite probe items by ID and hash only — they never contain raw
probe text.

**Baseline.** The first full run for a detector version + corpus
fingerprint. A detector/provider version change re-baselines
explicitly (`is_baseline: true`, `rebaselined_from` records the old
baseline); the old baseline stays in the history. A monthly
partial-scope run can never be a baseline.

**Score series.** Each manifest stores the per-item score series
(score, verdict, calibrated probability, calibration ID) so the
next run can recompute KS/PSI/flips against the baseline without
re-scoring. Numbers and IDs only, never raw text.

**Labels.** Holdback labels (0 human / 1 machine / None for
mixed-origin, which has no binary label) are read only *after*
scoring completes. They cannot influence which items are scored or
how they are scored.

## The seven per-run metrics (§7.6)

Computed per slice and overall by `textforensics.probe_runs`:

| # | Metric | Notes |
|---|--------|-------|
| 1 | Score shift (KS statistic + Holm-adjusted p, PSI) | KS needs effect size ≥ 0.10 *and* Holm-adjusted p < 0.05. PSI < 0.1 stable, > 0.2 action. |
| 2 | Verdict flips (rate + Wilson CI + direction) | `human_to_ai` / `ai_to_human` / `to_abstain` / `from_abstain`. A human→AI flip is an FPR event. |
| 3 | Calibration drift (ECE, Brier, calibration-ID change) | Only when the detector emits calibrated probabilities; native scores are never treated as probabilities. |
| 4 | Human-slice FPR (verdict-based, Wilson CI) | Claimable only at n_human ≥ 100. Cap 0.05, same as the Trust Map ceiling. |
| 5 | Attacked-slice TPR@1% FPR | The negative class is the human slices' scores (attacked slices contain no human items). |
| 6 | Conformal coverage / shortfall | **Unavailable in v1.0** — no conformal machinery exists in the repo (U5 is v1.1). Coverage-dependent tier rules are inactive; every manifest declares this as a gap. |
| 7 | Provider metadata diff | Missing/changed provider versions are reported, never silently ignored. |

MMD is unavailable in v1.0 (needs ~500+ samples per set; per-slice
n=50 is far below that). Tier 3 fires on PSI/KS instead; every
manifest declares this as a gap.

## Pre-registered thresholds

These are design choices recorded in every run manifest (`thresholds`
field). Changing one is a deliberate, documented act, not a silent
tweak. Values live in `src/textforensics/probe_runs.py`.

| Threshold | Value | Meaning |
|---|---|---|
| `ALPHA_PER_RUN` | 0.05 | Per-run alpha; Holm-corrected across the per-slice KS family. |
| `PSI_STABLE` / `PSI_ACTION` | 0.1 / 0.2 | PSI < 0.1 stable; > 0.2 investigate/act. |
| `KS_EFFECT_SIZE` / `KS_P_THRESHOLD` | 0.10 / 0.05 | KS Tier-3 rule needs both. |
| `FLIP_RATE_TIER2` / `FLIP_RATE_TIER1` | 0.01 / 0.05 | >1% flips (CI excluding 0) investigate; >5% human→AI flips on a human slice demote. |
| `ECE_INCREASE_TIER2` | 0.05 | ECE increase > 0.05 investigate. |
| `COVERAGE_SHORTFALL_TIER2_PP` / `TIER1_PP` | 5 / 10 | Inactive in v1.0 (no conformal machinery). |
| `VERSION_CHANGE_STALE_DAYS` | 7 | Version change with no probe run within 7 days demote. |
| `MIN_SLICE_N` / `MIN_SLICE_N_FOR_FPR_CLAIM` | 50 / 100 | Drift-signal floor / FPR-claim floor. |
| `FPR_CAP_DEFAULT` | 0.05 | Declared human-FPR cap. |
| `MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT` | 2 | Consecutive clean full runs before `temporal_version_stability` may exceed `partial`. |

## The three tiers and the iron rules

| Tier | Trigger | Action |
|---|---|---|
| 3 — record | A drift statistic breaches on one run (PSI > 0.2, or KS effect ≥ 0.10 with Holm-adjusted p < 0.05). | Recorded in the manifest's `breaches` for the next run. Nothing else happens. |
| 2 — investigate | The same drift breach on 2 consecutive runs, *or* a flip rate > 1% with Wilson CI excluding 0, *or* an ECE increase > 0.05. | Trust Map watch (`u3_watch` in the dimension's `observed` + a limitations line). Human review required. A watch never changes a Trust Map state by itself. |
| 1 — demote | A measured performance breach: human-slice FPR with Wilson CI lower bound above the 0.05 cap on a claimable slice; > 5% human→AI flips on a human slice; attacked-slice TPR@1% FPR collapse; or a version change with no probe run within 7 days. | The detector's U1 validation records are demoted to `stale` (`limits.demoted_by = "U3 probe run <id>: …"`). Withhold binary verdicts on affected slices until a full re-run passes. |

Iron rules, enforced in code:

- **Never demote on a drift statistic alone.** Drift statistics
  (PSI/KS) can only ever produce Tier 3 (one run) or Tier 2 (two
  consecutive runs). Tier 1 requires a measured performance breach.
- **Never claim drift from one sample or one run.** A single run
  never demotes; Tier 2 needs two consecutive runs. A drift
  statistic from a single sample is not a claim.
- **No alert silently changes a verdict.** Demotion marks U1
  records `stale`; the operator withholds binary verdicts on
  affected slices until a full re-run passes. Nothing in a run
  rewrites a verdict on a user's text.
- **Recovery flips never demote.** A flip toward human (the clean
  re-run recovering from a demotion) is Tier 2 at most. The Tier-1
  flip rule is human→AI on a human slice only, and overall flips
  are Tier 2 only — otherwise the recovery run would re-demote the
  detector and the demotion could never clear.
- **Demotion is per-detector in v1.0, not per-slice.** U1 records
  are regime-coarse; a probe-corpus performance breach indicts the
  detector's measured performance generally. Per-slice demotion is a
  v1.1 refinement once records are slice-granular.

**Clearing.** A clean full run (no Tier-1 alert) clears U3
demotions for the detector — but only records whose `demoted_by`
starts with `U3 probe run `; demotions from any other source are
left alone. Clearing re-signs the record.

## Trust Map threading

`derive_trust_map(..., longitudinal=...)` accepts the longitudinal
summary from `probe_runs.summarize_longitudinal`. The
`temporal_version_stability` dimension may exceed `partial` only
when at least 2 consecutive clean full-corpus runs exist at the same
detector version; the dimension's `observed` cites the run IDs and
the corpus fingerprint, and the reason names the runs. An active
watch is surfaced in `observed["u3_watch"]` and in the map
limitations. Demotion still wins: a demoted record stays `stale`
even with longitudinal support. Longitudinal evidence for another
detector/version, a malformed corpus fingerprint, or a run-ID count
mismatch raises instead of silently applying (fail-closed).

## Cadence

| Cadence | Scope | Where |
|---|---|---|
| Monthly (1st, 03:00 UTC, non-quarterly months) | `monthly-attacked` + `monthly-current-generator` | `.github/workflows/observatory.yml` |
| Quarterly (1st of Jan/Apr/Jul/Oct, 03:00 UTC) | `full` | Same workflow |
| Event-driven | `event-driven` (full) after a detector/provider version change | Same workflow via `workflow_dispatch`, or the version-change Tier-1 rule + re-baselining in code |
| Annual | The January quarterly full run doubles as the annual review run | Operator re-validates thresholds then (see below) |

GitHub-hosted CI cannot hold the NC-licensed corpus text, so the
scheduled job in CI only runs the machinery smoke (U3 tests + CLI
smoke on synthetic fixtures) and exits cleanly with a notice when
the corpus cache is absent. Real probe runs execute on the corpus
host, where the cache lives — the host runs this same workflow file
(or the equivalent operator cron/systemd timer) with
`PROBE_CORPUS_DIR` / `PROBE_RUNS_DIR` set. Run manifests are
uploaded as CI artifacts (90-day retention) when a run happens.

**Annual review checklist (January full run):** re-validate the
pre-registered thresholds against the year's runs (any threshold
change is a deliberate, documented act); confirm the corpus is still
frozen at v1.0.0 or plan a versioned corpus update (a new corpus
version re-baselines explicitly); review every Tier-2 watch that
never cleared; confirm the worst-slice human FPR evidence is still
current in the U1 registry.

## CLI reference

```sh
# One probe run (full corpus, builtin detector)
textforensics drift run \
  --manifest ~/.cache/textforensics/probe-corpus/1.0.0/manifest.json \
  --texts ~/.cache/textforensics/probe-corpus/1.0.0/corpus.jsonl \
  --holdback ~/.cache/textforensics/probe-corpus/1.0.0/holdback.jsonl \
  --scope full

# Monthly scopes
textforensics drift run --manifest ... --texts ... --holdback ... --scope monthly-attacked
textforensics drift run --manifest ... --texts ... --holdback ... --scope monthly-current-generator

# Compute only (no save, no demotion); fail the job on Tier 1 (for CI)
textforensics drift run --manifest ... --texts ... --holdback ... --dry-run
textforensics drift run --manifest ... --texts ... --holdback ... --fail-on-tier1

# Longitudinal status for a detector (JSON on stdout, human summary on stderr)
textforensics drift status --detector-id textforensics/builtin-heuristic
textforensics drift status --detector-id textforensics/builtin-heuristic \
  --detector-version 0.1.0 --runs-dir ~/.cache/textforensics/probe-runs/1.0.0
```

Exit codes for `drift run`: 0 the run completed (a Tier-1
demotion is an expected outcome, not a failure); 1 with
`--fail-on-tier1` when a Tier-1 alert fired; 2 when the
probe-corpus module is not available yet (it merges separately from
branch `u3-corpus`); 3 on input errors (unknown detector, version
mismatch, corpus verification failure).

Options: `--detector-id` (default `textforensics/builtin-heuristic`),
`--detector-version` (must match the detector), `--runs-dir`,
`--registry` (default `docs/validation/registry.json`),
`--output` (also write the run manifest to a file),
`--allow-remote` (off by default; core is local-first),
`--dry-run`.

## Run manifest fields (`textforensics.probe-run/v1`)

`run_id`, `run_at_utc`, `scope`, `corpus_version`,
`corpus_fingerprint`, `corpus_manifest_sha256`, `detector_id`,
`detector_version`, `provider_metadata`, `code_sha`,
`baseline_run_id`, `is_baseline`, `rebaselined_from`,
`previous_run_id`, `alpha_per_run`, `thresholds`, `metrics`
(per-slice + overall §7.6), `alerts`, `breaches`,
`demotions_applied`, `demotions_cleared`, `watches`,
`score_series`, `gaps`, `scope_statement`, `limitations`.

## Honest limits

- A run manifest records what was measured, not that the detector
  was run honestly: a hash seal cannot prove the analysis was run.
  The manifest's value is reproducibility (same corpus +
  detector + code SHA reproduces the same scores), not attestation.
- The observatory detects drift; it does not prevent bad verdicts.
  Between runs, a drifted detector keeps answering. The cadence
  (monthly attacked slices, quarterly full) bounds that window; it
  does not close it.
- Per-slice n=50 is small: drift signals below the pre-registered
  thresholds are not "no drift", they are "no detected drift at
  this power". FPR claims need n_human ≥ 100.
- The ESL (`human-non-native`) slice is cut in v1.0.0; human-population
  coverage is thinner than the research prescribed.
- MMD and conformal coverage are unavailable in v1.0 (declared as
  gaps in every manifest, not silently skipped).
- Demotion is per-detector in v1.0, not per-slice.
- The corpus half (frozen corpus v1.0.0, `probe_corpus.py`,
  `probe_metrics.py`, `scripts/build_probe_corpus.py`) lives on
  branch `u3-corpus` and merges separately through the parent; until
  then `tf drift run` exits 2 with a clear message and the U3 tests
  drive the machinery through injected test doubles.
