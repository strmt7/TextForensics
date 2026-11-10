# GhostWriter near-threshold investigation — threshold-robustness evidence

- Evidence note: `EV-20261110-ghostwriter-threshold-robustness`
- Run date: 2026-11-10
- Code version: `8c8a1cfc7588eaa56a8fdd090b3cf18acb43971d` (repo HEAD at run time)
- Detector: `textforensics/builtin-heuristic` version `0.1.0`
  (stylometric-heuristic)
- Record: `evr-20261107-ghostwriter-builtin-heuristic` (GhostWriter document
  slice)
- Cache: `~/.cache/textforensics/datasets/ghostwriter/default/train.jsonl`,
  SHA-256
  `12d2ab690b8952d34cb8814231b332f96dbc565de6f2daf4af50d3a60df184c8`
  (verified against the registry record before measuring)
- Command:
  `python scripts/measure_ghostwriter_threshold_robustness.py`
- Method: the repo's own `BuiltinHeuristicDetector.detect` (i.e.
  `analyze_text`) re-run over the cached labelled rows, exactly as
  `scripts/measure_human_fpr.py` does. The re-run reproduces the registry
  and the FPR artifact exactly: n_human=137, n_ai=210, abstentions=162.
  No raw text is recorded anywhere: rows are identified by `source_id`
  and a truncated SHA-256 of the text.

## Non-conclusion (read first)

The native `ai_like` threshold **0.68 is UNCHANGED** by this work. This
note is threshold-robustness evidence only (AGENTS.md rule 17: never
lower a threshold to make a demo look better). The sensitivity rows below
report what the human FPR *would be* at perturbed thresholds; they do
not propose moving the threshold, and no claim is restated and no record
status changes.

## Headline finding: fragile downward by exactly one row

The zero-FPR result at 0.68 **does NOT survive a −0.02 perturbation**:
at 0.66 one human row flips to a false positive (FPR 1/137 = 0.0073,
Wilson 95% [0.0013, 0.0402]). It survives a +0.02 perturbation (still
0/137 at 0.70). The margin between the highest human score and the
threshold is a single row, 0.006 wide.

| threshold | human FPR (verdict-equivalent) | Wilson 95% CI |
| --- | --- | --- |
| 0.66 | 1/137 = 0.0073 | [0.0013, 0.0402] |
| 0.68 (native) | 0/137 = 0.0000 | [0.0000, 0.0273] |
| 0.70 | 0/137 = 0.0000 | [0.0000, 0.0273] |

"Verdict-equivalent" means a row counts at threshold T when its score is
≥ T *and* its diagnostic reliability clears the same 0.28 floor the
native verdict applies (`engine._verdict`). The flipping row has
reliability 0.7746, so at 0.66 it would be a genuine `ai_like` verdict,
not an abstention. At the native 0.68 its verdict is `abstain`
(indeterminate → abstain).

## Human score distribution (n=137)

- Max human score: **0.6740** — 0.006 below the 0.68 threshold.
- Mean 0.3199, median 0.3079.
- Quantiles: p50 0.3079, p90 0.4808, p95 0.5516, p99 0.6334, max 0.6740.
- Rows within 0.01 below 0.68: **1**. Within 0.02: **1**. Within 0.05: **2**.
- Rows at or above 0.68: **0**.

Top 10 human scores (all `student_essays`, all `en-EN`, all verdict
`abstain`; word counts are the engine's own counts):

| rank | score | words | reliability | uniformity | formulaic | lexical |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 0.6740 | 330 | 0.7746 | 0.8641 | 0.2500 | 0.9857 |
| 2 | 0.6513 | 503 | 0.8227 | 0.7213 | 0.3474 | 0.9630 |
| 3 | 0.6016 | 447 | 0.7764 | 0.8012 | 0.1782 | 0.8999 |
| 4 | 0.5944 | 613 | 0.8128 | 0.7264 | 0.2500 | 0.8777 |
| 5 | 0.5771 | 584 | 0.8458 | 0.7028 | 0.2883 | 0.7945 |
| 6 | 0.5695 | 354 | 0.7726 | 0.8660 | 0.1301 | 0.7601 |
| 7 | 0.5665 | 474 | 0.7704 | 0.6128 | 0.1959 | 0.9989 |
| 8 | 0.5479 | 590 | 0.7761 | 0.5959 | 0.1848 | 0.9680 |
| 9 | 0.5339 | 726 | 0.7452 | 0.8949 | 0.0451 | 0.7041 |
| 10 | 0.5338 | 462 | 0.7502 | 0.7486 | 0.0628 | 0.8752 |

The two near-threshold rows (score ≥ 0.63):

- 0.6740, `student_essays`, `en-EN`, 330 words,
  `source_id 693f5cc1-14ed-4201-9077-2e5d521066ed`,
  text SHA-256 prefix `1201d96cfa47c270`.
- 0.6513, `student_essays`, `en-EN`, 503 words,
  `source_id 174c05fd-5aac-4d8f-acf8-849c0fff6284`,
  text SHA-256 prefix `a074998aacd2f2a3`.

## What drives the top scores

The aggregate score is the reliability-weighted mean of three analyzers
(`engine._weighted_score`; weights are `max(0.05, reliability)`). For
texts of ≥ 300 words the weights are uniformity 1.0, formulaic 1.0,
lexical 0.75 (lexical reliability is `min(1, words/300) × 0.75`). Mean
analyzer scores:

| analyzer | all human (n=137) | top 10 | near-threshold (n=2) |
| --- | --- | --- | --- |
| structural_uniformity | 0.4450 | 0.7534 | 0.7927 |
| formulaic_language | 0.1088 | 0.1933 | 0.2987 |
| lexical_profile | 0.4438 | 0.8827 | 0.9744 |

The near-threshold scores are driven first by **lexical_profile** and
second by **structural_uniformity**; formulaic_language is a minor
contributor. Feature means (near-threshold vs all human):

| feature | near-threshold | all human | what it means in the analyzer |
| --- | --- | --- | --- |
| type_token_ratio | 0.3001 | 0.4619 | at the floor of the low-TTR ramp (0.34–0.58) |
| hapax_ratio | 0.4457 | 0.6452 | near the floor of the low-hapax ramp (0.42–0.72) |
| punctuation_variety | 1.5 | 4.05 | at/below the floor of the low-variety ramp (2–6) |
| sentence_length_cv | 0.3229 | 0.6160 | low variation → high uniformity sub-score |
| repeated_sentence_start_ratio | 0.3100 | 0.1058 | at the ceiling of its ramp (0.05–0.30) |
| repeated_trigram_ratio | 0.1226 | 0.0590 | above the ceiling of its ramp (0.01–0.10) |
| transition_density | 0.3976 | 0.1411 | modest formulaic contribution |
| cliche_density | 0.0000 | 0.0001 | no contribution |
| paragraph_length_cv | 0.0000 | 0.0000 | see below |

Top row in full (0.6740): type_token_ratio 0.3000, hapax_ratio 0.4343,
punctuation_variety 1.0 — all three lexical features at or near their
ramps' floors, giving lexical_profile 0.9857 — plus sentence_length_cv
0.3323, repeated_sentence_start_ratio 0.5 (ramp ceiling), and
repeated_trigram_ratio 0.1494 (above its ramp ceiling), giving
formulaic_language 0.2500 from the trigram term alone
(transition/cliché densities are 0). Second row (0.6513): same pattern —
type_token_ratio 0.3002, hapax_ratio 0.4570, punctuation_variety 2.0,
sentence_length_cv 0.3135.

Structural caveat, measured: **every** GhostWriter train row is
single-paragraph — paragraph_length_cv is 0.0 for all 137 human rows,
all 210 AI rows, and all 153 unlabelled rows. The uniformity analyzer's
paragraph term (`0.25 × 1.0` for CV 0) is therefore a constant +0.25 to
the uniformity sub-score on this entire slice; paragraph-length
variation carries zero information here. The uniformity signal on this
slice is sentence-length uniformity plus repeated sentence starts only.

## Do the near-threshold texts share characteristics?

Yes, narrowly — but n=2, so this is a description, not a pattern claim:

- Domain: both near-threshold rows are `student_essays`. All 10 top
  rows are `student_essays`. Human rows by domain: student_essays 39,
  bundestag 29, blog_authorship_corpus 18, house_of_commons 16, cnn_news
  15, euro_court_cases 12, arxiv_papers 6, gutenberg 2.
- Language: both are `en-EN`. Human rows by language: en-EN 108, de-DE
  29. The highest-scoring German human row is 0.4607 (`bundestag`,
  17 words — below the detector's 80-word minimum), vs the English max
  0.6740: the near-threshold tail is English-only on this slice.
- Length: near-threshold median 416.5 words vs 561 for all humans — the
  two rows are shorter than the typical human row, but both are well
  above the detector's 80-word minimum and the 300-word full-reliability
  point, so length is not the mechanism.
- Editing regime (record): `raw`. Genre (record): mixed-origin benchmark
  sample, binary slice only (human/AI fulltext endpoints). Vintage:
  2024–2025. Populations: general human authors (human texts from CNN
  news, arXiv papers, blogs, Bundestag proceedings, House of Commons
  debates, EU court cases, student essays, Project Gutenberg; no
  per-author demographics recorded).

## AI-side context: the slice is inverted

AI rows (n=210): max score 0.5744, mean 0.2880, median 0.2847, 0 rows
at or above 0.68. The human mean (0.3199) is *above* the AI mean — the
detector scores human text higher than machine text on this slice,
consistent with the record's AUROC 0.436 (below chance) and its known
failure mode ("heuristic scores human text higher than machine text").
The near-threshold human rows are therefore not outliers in the AI
direction; they are the upper tail of a human distribution the detector
already ranks above the AI distribution.

## Comparison with the other slices' max human scores

| slice | max human score | n_human | source |
| --- | --- | --- | --- |
| GhostWriter | 0.6740 | 137 | this note (re-run 2026-11-10) |
| OpAI-Bench segments | 0.6630 | 4785 | re-run this wave (see below) |
| OpAI-Bench documents | 0.6250 | 56 | re-run this wave (see below) |
| RAID (20261108 record) | 0.6159 | 171 | `EV-20261108-dataset-raid.json` |
| Beemo | 0.5899 | 200 | `EV-20261108-human-fpr.json` |
| MAGE | 0.5260 | 117 | `EV-20261108-human-fpr.json` |
| DetectRL-X | 0.4964 | 400 | `EV-20261108-human-fpr.json` |

OpAI-Bench re-runs this wave (same detector, same caches as the FPR
artifact): document slice max human score 0.6250 (n=56 human / 55 AI,
reproduces the artifact); segment slice max human score 0.6630
(4785 human / 5268 AI segments, `analyze_text(include_robustness=False)`
+ `mixed_origin.segment_verdict`, k_fp=0, reproduces the artifact).
Beemo, MAGE and DetectRL-X maxima are quoted from
`EV-20261108-human-fpr.json` (coordinator-verified 2026-11-08) and were
not re-run here; the RAID 0.6159 is the 20261108 record's value on n=171
humans. GhostWriter is the closest any document slice has come to the
threshold — and the OpAI-Bench segment max (0.6630, 0.017 below 0.68)
is the closest on any unit.

## What this does and does not conclude

- It does NOT conclude the threshold should move. It is 0.006 away from
  a false positive on one row, and one row is not a basis for retuning.
- It does NOT conclude the detector is safe at 0.68: the margin is one
  row, and a larger GhostWriter sample (or a new student-essay sample)
  could produce the first false positive. The Wilson upper bound at the
  native point (0.0273 on n=137) already prices that in.
- It DOES conclude the zero-FPR result on this slice is threshold-fragile
  in the downward direction and must be reported with its margin, not as
  a comfortable zero.
- It DOES identify the mechanism to watch: low lexical variety
  (TTR ≈ 0.30, hapax ≈ 0.45, punctuation variety 1–2) combined with
  uniform sentence lengths in English student essays — plus the
  single-paragraph constant in the uniformity term. Any future
  student-essay or low-variety human sample is the population most
  likely to produce the first false positive on this detector.
