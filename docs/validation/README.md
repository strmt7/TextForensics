# Validation-evidence registry (U1)

`registry.json` is the versioned store of validation-evidence records
(`textforensics.evidence-record/v1`) for the built-in heuristic
detector. Each record binds one detector version to one declared
input regime (language x length x domain x editing x
generator-vintage x human-population), the dataset sample and run
that measured it, per-slice metrics with bootstrap 95% confidence
intervals, and its limits. The Trust Map derivation engine
(`textforensics.validation.derive_trust_map`) reads this registry —
never the v1 evidence registry — to decide, per input, whether the
detector's output is inside validated operating conditions.

No raw text anywhere in the registry: records carry counts, hashes
and metrics only. Per-sample scores live in the U7 run artifacts
(`docs/evidence/runs/EV-*-dataset-*.json`) by hash, not here.

## Seeded records (2026-11-06, U1 Package C)

All four seeds are stored as `partial` — no reviewer has assessed
any of them, the samples are preliminary strided subsets, and RAID's
human slice (92) is below the 100-row minimum for a `supported`
slice. Their effective status is therefore also `partial` (fresh,
in-date, same detector version 0.1.0). `next_revalidation_due` is
2027-02-04 for all four (run date + 90 days).

Detector: `textforensics/builtin-heuristic` 0.1.0
(stylometric-heuristic). CI method for every metric: bootstrap, 1000
resamples, seed 20261106. Native FPR/TPR are at the detector's native
categorical operating point — "builtin-heuristic native verdict
(analyze_text); no score threshold". No threshold was fitted anywhere.

| record | n_human / n_ai | AUROC [95% CI] | TPR@1% FPR [95% CI] | TPR@5% FPR [95% CI] | native FPR [95% CI] | native TPR [95% CI] | abstention [95% CI] |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `evr-20261106-raid-builtin-heuristic` | 92 / 2908 | 0.5937 [0.5468, 0.6442] | 0.0454 [0.0380, 0.1329] | 0.1348 [0.0461, 0.2042] | 0.0000 [0.0000, 0.0000] | 0.0189 [0.0141, 0.0241] | 0.4967 [0.4777, 0.5160] |
| `evr-20261106-mage-builtin-heuristic` | 117 / 283 | 0.5567 [0.4969, 0.6136] | 0.1060 [0.0605, 0.1875] | 0.1661 [0.1170, 0.2983] | 0.0000 [0.0000, 0.0000] | 0.0071 [0.0000, 0.0177] | 0.5425 [0.4925, 0.5900] |
| `evr-20261106-beemo-builtin-heuristic` | 200 / 700 | 0.3976 [0.3560, 0.4405] | 0.0129 [0.0000, 0.0330] | 0.0586 [0.0196, 0.0780] | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.5411 [0.5078, 0.5722] |
| `evr-20261106-opai-bench-builtin-heuristic` | 56 / 55 | 0.3961 [0.3003, 0.4984] | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0426] | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.4955 [0.4054, 0.5856] |

Length (whitespace word count, labelled rows): RAID min 1 / median 229
/ max 4844; MAGE 8 / 112 / 2622; Beemo 6 / 86 / 731; OpAI-Bench
174 / 395 / 1064. OpAI-Bench's binary slice is the v0/v8 endpoint
rows only (56 human, 55 machine); its 389 partial rows are excluded
— they are the U4 spine, not U1 evidence.

## GhostWriter seed (2026-11-07, datasets wave 2)

Appended by `python scripts/seed_validation.py --only ghostwriter
--append` (registry 4 → 5 records; the four U1 seeds are untouched,
byte-identical). Stored as `partial`, effective `partial`;
`next_revalidation_due` is 2027-02-05 (run date + 90 days). Same
detector (`textforensics/builtin-heuristic` 0.1.0) and CI method
(bootstrap, 1000 resamples, seed 20261106) as the U1 seeds.

| record | n_human / n_ai | AUROC [95% CI] | TPR@1% FPR [95% CI] | TPR@5% FPR [95% CI] | native FPR [95% CI] | native TPR [95% CI] | abstention [95% CI] |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `evr-20261107-ghostwriter-builtin-heuristic` | 137 / 210 | 0.4360 [0.3647, 0.5036] | 0.0000 [0.0000, 0.0044] | 0.0048 [0.0000, 0.0332] | 0.0000 [0.0000, 0.0000] | 0.0000 [0.0000, 0.0000] | 0.4669 [0.4121, 0.5187] |

Length (whitespace word count, labelled rows): min 8 / median 447 /
max 20084. The binary slice is the human/ai fulltext endpoints only;
its 153 fusion rows are excluded — they are the U4 spine, not U1
evidence. The record's regime language is `mul` (BCP 47): the sample
mixes English (288 labelled rows) and German (59 labelled rows);
per-language metrics are not reported separately. All 8 domains are
in scope; generators are the `agent` values (gemma2:9b, gpt-4o-mini,
phi3:3.8b, nemotron, deepseek-r1:32b, deepseek-r1:1.5b). Fusion rows
are all chunks and labelled rows are all fulltext, so chunk behaviour
is unmeasured. Licence is the full per-domain table (two domains
CC-BY-NC-SA 4.0, blog corpus non-commercial-research-only); use is
non-commercial research evaluation only.

### Reading the native-verdict zeros honestly

Native FPR is 0.0000 on all five slices, and native TPR is 0.0000–
0.0189. That is NOT evidence that the detector never false-positives
in general. The detector emits `ai_like` only when its score reaches
0.68 (`engine._verdict`); the highest human score in any seed sample
is 0.674 (GhostWriter), so no human row crosses the bar, and only a handful of
machine rows do. The score-based metrics tell the other half of the
story: AUROC is below chance on Beemo (0.3976), OpAI-Bench (0.3961)
and GhostWriter (0.4360) — the heuristic scores expert human text
and pure human text HIGHER than machine text there — and near chance
on MAGE (0.5567). A zero native FPR with a below-chance AUROC means the
categorical verdict is quiet, not that the detector separates the
classes. The degenerate [0.0000, 0.0000] CIs are the percentile
bootstrap of a zero count (every resample is also zero); they are
reported as measured, not widened into a claim. (Highest human score
in any seed sample: 0.674 on GhostWriter; highest machine scores:
RAID 0.784, MAGE 0.724 — only those two slices ever cross 0.68.)

Native TPR is carried in the records as the optional `tpr_native`
metric (evidence-record/v1), paired with `fpr_native` at the same
operating point; the table above also reports it.

### Why every seed is `partial`

- RAID: 92 human rows (< 100 minimum); attack variants pooled, not
  reported separately; no reviewer.
- MAGE: near-chance AUROC; bare size generator labels (7B/13B/30B/
  65B) do not name the model family in the cached sample; no
  per-testbed reporting; no reviewer.
- Beemo: AUROC below chance (expert-edited regime inverts the
  baseline); single split, so no disjointness check; per-kind
  metrics not reported separately; no reviewer.
- OpAI-Bench: AUROC below chance on the endpoint slice; only 111
  binary-labelled rows; partial rows excluded; no reviewer.
- GhostWriter: AUROC below chance (0.4360); bilingual sample
  (English/German) with no per-language reporting; fusion rows are
  all chunks and labelled rows all fulltext, so chunk behaviour is
  unmeasured; per-domain metrics not reported separately; no reviewer.

## How to re-seed

```bash
python scripts/seed_validation.py --check    # build + dual-validate, write nothing
python scripts/seed_validation.py            # rebuild docs/validation/registry.json
python scripts/seed_validation.py --only ghostwriter --append   # append one record, keep the rest
```

New datasets are seeded with `--append`: the script loads the
existing registry, appends the newly built records (duplicate record
ids are refused) and saves the merged registry — the existing records
are carried over untouched and the registry id is recomputed from
the merged record set. The U7 artifact a record seeds from is found
by run date: `--run-date YYYYMMDD` selects the artifact, defaulting
to the latest `EV-*-dataset-<key>.json` in `docs/evidence/runs` (no
date is hardcoded in the script).

The script loads the cached JSONL only (no network, no re-fetch),
re-runs the deterministic detector, and verifies every record's
`run_artifact_sha256` against the actual U7 artifact file and the
U7 registry entry before writing. Re-seeding is deterministic: same
cache + same code = same records (bootstrap seed 20261106). If a
cache is missing, fetch it first with
`python scripts/measure_datasets.py --only <dataset>` — the seed
script never downloads.

## Staleness policy

Staleness is computed, never stored. A record becomes effectively
`stale` when the detector version changes, when
`next_revalidation_due` passes (run date + 90 days by default), or
when the drift observatory (U3) demotes its slice. The stored record
does not change when it goes stale, so its signature stays valid.
Revalidate by re-measuring (a new run artifact) and seeding a new
record that supersedes the old one.

## Contamination policy

Every record states `contamination_flag`: `yes` (the detector was
trained on the evaluation dataset), `no`, or `unknown`. Licence and
contamination flag are registration-blocking — a record missing
either is rejected, it cannot be registered at any tier. A `yes`
record is labelled `contaminated — do not report as generalisation`
and can never support an out-of-distribution claim. All five seeds
are `no`: the builtin detector is a hand-written stylometric
heuristic with no training, so it was not trained on any of these
datasets (or any other text corpus).

## MixSet: no record

MixSet has no licence on any source checked (HF card, GitHub repo,
READMEs; the paper's CC BY 4.0 covers the paper, not the dataset),
and the record schema forbids a record without a licence. The gate
is closed: no MixSet rows were fetched, and no record exists for it
here. Revisit only after the authors provide a licence statement.

## Report-card lead: UNCHANGED by U1

The U1 records ARE the first human-FPR evidence, but the report
card (`docs/evidence/report-card.md`) still leads with worst-slice
human FPR = unknown. Whether these records promote that lead is a
claims decision for the Phase 5 release gate, not for U1 — and the
native-verdict zeros above must not be read as release-gate FPR
evidence on their own (see "Reading the native-verdict zeros
honestly"). U1 deliberately makes no change to `docs/CLAIMS.yaml`.
