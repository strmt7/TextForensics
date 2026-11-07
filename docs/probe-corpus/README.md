# Probe corpus v1.0.0

The frozen probe corpus for the U3 drift observatory: the labelled,
frozen anchor set the observatory re-runs on its cadence. Built
2026-11-07 by `scripts/build_probe_corpus.py` (see
`~/workspace/goals/textforensics-complete-revamp/hidden_files/phase3-u3-corpus.md`
for the full build report).

## What is committed here

Only the manifest (`v1.0.0/manifest.json`): item ids, slices, content
hashes, counts, sources, licences, the sampling plan, and the dated
current-generator list. **No corpus text is committed** — the corpus
file (`corpus.jsonl`, item id + text + source) and the holdback label
file (`holdback.jsonl`, item id → label) live only in the local cache
at `~/.cache/textforensics/probe-corpus/1.0.0/`. The corpus contains
real text from licensed datasets; it is not a portable output and must
not leak into case files, bundles, or docs. No raw corpus text appears
in any report — item ids + hashes only.

## Fingerprint

- Version: `1.0.0`, built 2026-11-07T08:38:38Z
- Items: 400 (8 slices × 50)
- `items_sha256`:
  `d451830fb30e1cd2c93dc3107b72daef44405015e1ddd5c0815792878c7b6ac4`
- `holdback_sha256`:
  `6aae27854613d6c5e0afd6001e90a15e33a54dc385f8c132a6e87ee20d45f992`
- `corpus_file_sha256`:
  `54396495892959791d3f858a1e50e72f16f53b8fddfc2587cc606d30f6f7bf70`

## Slices (n=50 each)

| Slice | Source | Filter |
|---|---|---|
| human-native | MAGE validation | human rows, ≥80 words, ≥20 letter-tokens |
| human-short | Beemo train | human rows, 5–99 words, ≥5 letter-tokens |
| ai-current-generator | DetectRL-X test (English) | machine rows, current models (see below) |
| ai-legacy-generator | MAGE validation | machine rows (all MAGE generators 2022-or-earlier) |
| ai-paraphrased | RAID train | machine rows, attack=paraphrase |
| ai-humanized | RAID train | machine rows, attack=synonym (lexical-evasion attack) |
| mixed-origin | OpAI-Bench dev | partial rows, version=v4 (AI sentence ratio 0.5–0.55) |
| benign-transformed | MAGE validation bases | 25 human + 25 machine bases, one deterministic benign transform each (transform + base hash recorded per item) |

Word counts per slice (min/median/max): human-native 82/171/2040;
human-short 8/34/97; ai-current-generator 135/231/862;
ai-legacy-generator 82/203/872; ai-paraphrased 83/211/437;
ai-humanized 80/256/425; mixed-origin 115/270/979;
benign-transformed 80/329/1466. Holdback labels: 225 machine, 125
human, 50 unlabelled (mixed-origin — no binary label exists).

The 80-word floor is the builtin detector's own minimum (it warns
below 80 words); the letter-token floor rejects degenerate rows (a
RAID row whose whole text is one Markdown image link was found and
excluded during the build). The human-short slice is the designated
short-text regime.

## What is NOT in v1.0.0

- **human-non-native/ESL slice — cut.** No licensed source in the
  resolved set labels ESL ground truth, and inventing ESL labels from
  unlabelled text would be a lie. Resolving an ESL-labelled dataset
  (licence first) is a defined follow-up for the full U3 coordinator.
- **No human-FPR claim on any slice.** Per-slice n=50 meets the
  drift-signal minimum; n≥100 per slice is required before any
  human-FPR claim (Wilson CI arithmetic).
- **No 2026 source prescribes this size.** n=400 is judgement from
  statistical constraints (Wilson CI, n≥100 for 1% FPR), not a
  literature prescription.

## Current-generator list (dated)

Current as of **2026-11-07**: deepseek-v3, gemini-2.5-flash, gpt-4o,
qwen-max (DetectRL-X Binary file models, verified live 2026-11-07).
Re-checked monthly via the U3 cadence; a fixed list is a staleness
bug by construction.

## Licences

RAID MIT; MAGE Apache-2.0; Beemo MIT card + CC-BY-NC-4.0 carve-out on
prompts + `human_output`; OpAI-Bench Apache-2.0; DetectRL-X
non-commercial academic research only (strictest reading of the
three-way Apache-2.0 / MIT / paper conflict governs). Beemo and
DetectRL-X items make this corpus **non-redistributable** — local
cache only, never in the repo. MixSet, DetectRL, M4, M4GT-Bench have
no licence anywhere and were not sourced.

## Disjointness

Corpus items are disjoint by content hash from every row measured
for a U1 validation record (verified overlap: zero, re-checked
independently from the corpus files). The observatory is an
independent check on the validation evidence, not a re-measurement
of the same rows.

## Verify / rebuild

```sh
# Freeze check (no network): re-hash every corpus text + holdback
# file and compare against the manifest.
python scripts/build_probe_corpus.py --verify-only

# Full rebuild from the manifest (network): re-fetches the strided
# samples from the recorded plan and must reproduce identical item
# hashes (created_at_utc is the only field that changes).
python scripts/build_probe_corpus.py
```

The manifest is append-only versioned: any change produces a new
version (`v1.1.0`, …), never an in-place edit of this file. The
module `src/textforensics/probe_corpus.py` implements the manifest,
holdback, transforms and verification; `src/textforensics/probe_metrics.py`
holds the pure per-run metric functions (§7.6 metrics 1–7) used by
the observatory runs. Alerting, demotion and cadence are the full U3
coordinator's work (after U2 lands) and are not in this corpus half.
