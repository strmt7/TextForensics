# W8 Predeclared Claims — TextForensics audit wave W8

**Status:** PREDECLARATION. Written and committed BEFORE any W8 corpus
result was produced or interpreted. Any W8 run artifact evaluated against
this document must be dated after it; a result known before this file was
committed would invalidate the predeclaration for that claim.

- **Written:** 2026-11-16 ~11:15 CET (10:15 UTC)
- **Author role:** W8 Worker D (predeclared claims / registry / report-card)
- **Base:** staging branch `audit-w7` @ `17b8951` (W7 verified and held;
  main at `7d2112c`, untouched by this wave)
- **Branch:** `audit-w8-d`, worktree `~/workspace/TextForensics-w8-d`
- **Detector under qualification:** `textforensics/builtin-heuristic`
  0.1.0 (stylometric heuristic). No inference or provenance code is
  changed by this wave; W8 is a QUALIFICATION wave (0 findings by design).
- **State of the world at writing:** corpus workers A (RAID+MAGE),
  B (Beemo+DetectRL-X), C (GhostWriter+OpAI-Bench) and reproduction
  worker E are all still at base `17b8951` with no commits and no new
  run artifacts under `docs/evidence/runs/`; no W8 part-reports exist
  yet in `hidden_files/`. The only human-FPR numbers in existence are
  the pre-W8 ones frozen in §1 below. Nothing in this document was
  written after seeing a W8 measurement.

This file exists in two identical copies, which must match byte for
byte (compare SHA-256): the working original at
`~/workspace/goals/textforensics-complete-revamp/hidden_files/audit-w8-predeclared-claims.md`
and the committed copy at `docs/evidence/w8-predeclared-claims.md`
(branch `audit-w8-d`).

## 1. Frozen pre-W8 baseline (the numbers this wave starts from)

Registry `docs/validation/registry.json`: 9 records — 7 `partial`,
2 `supported`.

| record | dataset | n_human / n_ai | Wilson 95% FPR upper | status |
| --- | --- | --- | --- | --- |
| evr-20261106-beemo-builtin-heuristic | Beemo | 200 / 700 | 0.018846 | partial |
| evr-20261106-mage-builtin-heuristic | MAGE | 117 / 283 | 0.031790 | partial |
| evr-20261106-opai-bench-builtin-heuristic | OpAI-Bench (doc) | 56 / 55 | 0.064196 | partial |
| evr-20261106-raid-builtin-heuristic | RAID | 92 / 2908 | 0.040083 | partial |
| evr-20261107-detectrl-x-builtin-heuristic | DetectRL-X | 400 / 400 | 0.009513 | partial |
| evr-20261107-ghostwriter-builtin-heuristic | GhostWriter | 137 / 210 | 0.027276 | partial |
| evr-20261107-opai-bench-builtin-heuristic | OpAI-Bench (segment) | 4785 / 5268 | 0.000802 | partial |
| evr-20261108-raid-builtin-heuristic | RAID | 171 / 5829 | 0.021972 | supported (supersedes evr-20261106-raid) |
| evr-20261110-opai-bench-builtin-heuristic | OpAI-Bench (doc) | 218 / 223 | 0.017317 | supported (supersedes evr-20261106-opai-bench) |

Worst-slice aggregation `EV-20261110-human-fpr`
(`results.worst_slice_wilson_ci_upper` =
`results.worst_document_slice_wilson_ci_upper` = **0.064196**):
worst document slice is OpAI-Bench 20261106 (n_human=56, n_ai=55).
Pooled documents-only Wilson upper 0.003819 (0/1002) is reported for
completeness only and is NEVER a gate statistic.

Report-card lead (`docs/evidence/report-card.md`): **unknown**.
Best single-slice value (OpAI-Bench 20261110, Wilson upper 0.0173,
n_human=218) is a single-slice value, NOT a worst-slice aggregation,
and cannot fill the lead.

All native FPR point values are 0.0 (0 false positives observed on
every slice). A zero is a bound on zero events, not a measured
positive rate, and not evidence the detector never false-positives.
The score-based metrics are negative results where they are negative
and stay negative results: AUROC is below chance on Beemo (0.3976),
OpAI-Bench 20261106 (0.3961) and GhostWriter (0.4360), near chance on
MAGE (0.5567), weakly separating on DetectRL-X (0.5972) and RAID
(~0.595). No below-chance result may be re-interpreted, re-thresholded
or dropped. A score is not a probability.

## 2. Claims being made (and not made)

### 2.1 Claims in scope for W8

- **C1 — Per-slice native human FPR (document slices only).** For each
  of the 6 corpora (RAID, MAGE, Beemo, DetectRL-X, GhostWriter,
  OpAI-Bench document level), the native human false-positive rate
  FPR = P(verdict=`ai_like` | human) at the fixed native operating
  point (§3), reported per slice with its Wilson 95% interval, k/n,
  abstention count and max human score.
- **C2 — Worst-slice human FPR (report-card lead).** The worst
  per-slice Wilson 95% upper bound across the required document
  slices (§5), as a single lead number, ONLY if the gate in §7 is met.
- **C3 — Paired native TPR.** Native TPR = P(verdict=`ai_like` | AI)
  at the same operating point, per slice, with Wilson 95% intervals.
  Reported alongside FPR; a thin paired TPR (n_ai < 100) blocks a
  slice from supporting an FPR claim (§7).
- **C4 — Coverage / abstention.** Abstention counts and rates per
  slice, reported separately, never folded into FPR or TPR.

### 2.2 Claims NOT being made

- No zero-FPR promise. No detector-parity claim. No claim that the
  detector separates human from machine text in general (AUROC says
  otherwise on three slices).
- No claim about any text, population, generator, language, domain,
  length bucket or regime not in the measured slices (§5, gaps).
- No pooled FPR claim. Pooling hides slice heterogeneity and is never
  a worst-slice statistic; the segment slice (sentences, not
  documents) must never be pooled with document slices at all.
- No calibration claim (calibration only where supported by disjoint
  fit and evaluation artifacts; none is in scope for W8).
- No temporal / repeated-run claim beyond the runs actually executed
  at one immutable identity.

## 3. Operating points (fixed, not tuned)

- **Document slices:** the builtin-heuristic native verdict
  (`analyze_text`); no score threshold. The detector emits `ai_like`
  only when its score reaches 0.68 (`engine._verdict`). This point is
  FIXED. It was not selected on W8 data, and it must not be moved,
  re-tuned or re-fit on any W8 final holdout. Any proposal to move it
  is a new claim requiring a new predeclaration.
- **Segment slice (OpAI-Bench segment-level, pre-existing):** segment
  verdict (`analyze_text` with `include_robustness=False` +
  `mixed_origin.segment_verdict`, 0.68/0.32); segments under 20 words
  abstain. Assessed separately; never a candidate for a
  document-level worst slice.
- S17 thresholds are audit contracts, not tuned values. No threshold
  is lowered, no baseline grown, no failing test dropped, no
  `unknown` relabelled `supported` to meet a gate.

## 4. Minimum samples and uncertainty methods

- **Minimum samples per supported slice:** n_human ≥ 100 AND
  n_ai ≥ 100. Both bounds are required: the pre-W8 record shows why —
  RAID 20261106 fails on n_human=92 alone, OpAI-Bench 20261106 fails
  on both (n_human=56, n_ai=55). A slice below either minimum cannot
  support an FPR claim, even if its Wilson upper is ≤ 0.05.
- **Uncertainty method:** Wilson score interval, 95% (z=1.96),
  computed by `textforensics.probe_metrics.wilson_ci`, from the
  re-run (k, n) counts. The degenerate bootstrap [0.0, 0.0] (a
  percentile bootstrap over an all-zero sample cannot resample a
  positive) is NOT an honest interval for a zero count and must not
  be cited as the FPR interval. Wilson is the interval for every
  native FPR/TPR reported in W8.
- **Rare-event bounds:** every native FPR here is a bound on zero
  observed events (k=0). Report k and n alongside the bound, always.
  A larger human sample may produce the first false positive and move
  the bound; that is a finding, not a reason to re-sample or
  re-threshold.
- **Cluster-aware uncertainty where applicable:** rows are not
  independent where they share a source document, author or
  near-duplicate group. Where a W8 run can identify clusters
  (same document under different versions/generators, near-duplicate
  groups, same author), the run artifact must record the cluster
  structure and the number of independent clusters; if a
  cluster-aware interval cannot be computed, the artifact must say
  so explicitly and the Wilson interval must be labelled as treating
  rows as independent. Cluster structure never silently inflates n.
- **Partitioning:** partition by source document / author / generator
  / near-duplicate group BEFORE selecting thresholds or calibration.
  Train / development / selection / fit / validation / final-test
  manifests are frozen; the final evaluation is inaccessible to
  tuning. A new W8 record must be disjoint by content hash from ALL
  prior samples of the same dataset (the OpAI-Bench precedent:
  byte-identical rows excluded by identity, never by detector score).

## 5. Slice list — covered vs explicit gaps

### 5.1 Document slices in scope (6 corpora)

RAID, MAGE, Beemo, DetectRL-X, GhostWriter, OpAI-Bench (document
level). Plus the pre-existing OpAI-Bench segment-level slice, which
is a different unit and is excluded from every document-level
aggregation.

### 5.2 Required slice dimensions (W8 plan) and their W8 status

| dimension | covered by W8 design | explicit gap |
| --- | --- | --- |
| language | DetectRL-X: 8 languages balanced (100 rows each: ar, zh, en, fr, de, pt, ru, es); GhostWriter: en+de; others en | Per-language FPR is NOT reported separately anywhere (registry reports one pooled slice per dataset). No per-language claim may be made. Non-English document text outside DetectRL-X / GhostWriter is unmeasured. |
| domain | Domains are declared per record (RAID abstracts/books/news/poetry in the measured sample; Beemo Closed QA / Generation / Open QA / Rewrite / Summarize; DetectRL-X 6 domains; GhostWriter 8 domains) | Per-domain FPR is NOT reported separately. Domains outside each measured sample are unmeasured. |
| length | Length buckets are declared per record (measured min/median/max words) | Texts below 80 words are NOT validated (the detector's minimum). Short-text behaviour is worker E's OOD scope and does not feed the FPR gate. |
| human population / style | Declared populations only (expert human editors + general human authors for Beemo; per-record declarations otherwise) | No per-author demographics; no ESL human text; no human population outside the declared ones. Human-edited text: Beemo mixes plain, human-edited and LLM-edited rows under one regime label (documented, not separated); GhostWriter fusion rows and OpAI-Bench partial (mixed-origin) rows are excluded from binary evidence (they are the U4 spine, not U1 evidence). |
| generator / version | Declared generator families + vintage per record only | Generators newer than each record's declared vintage are unmeasured. Per-generator FPR is NOT reported separately. |
| edited / paraphrased / mixed text | Human-edited regime is present in Beemo (mixed, not separated); GhostWriter fusion and OpAI-Bench partial rows exist as data but are excluded from binary FPR evidence | No supported claim covers edited, paraphrased or mixed-origin text as a slice. Any such claim would need a new predeclaration and a labelled slice. |
| benign transformations | — | NOT measured at all in W8 scope. Explicit gap; no claim. |

### 5.3 PAN 2025 — explicit gap

**PAN 2025 is an explicit gap.** It was not attempted to be obtained
in W8, no PAN 2025 data was fetched, measured or cited, and no claim
in this wave depends on it. The gap is recorded here (predeclared),
in the W8-D part-report, and in `docs/validation/README.md`
(W8 qualification note). It remains open for a later wave with
licence-cleared access.

### 5.4 Other standing gaps (carried, not newly discovered)

- Per-kind metrics (plain human vs human-edited vs LLM-edited) are
  not reported per record.
- Near-duplicate rates were not measured for the seed samples (except
  where a W8 run measures them).
- No reviewer has assessed any registry record; records are
  preliminary seeds / patches, not reviewed validations.
- Python 3.11, 3.13, 3.14, 3.15: measured on the local interpreter
  only; CI covers the matrix.
- Full-corpus evaluation: all samples are strided subsets, not
  full-corpus evaluations; inclusion/drop counts must be recorded
  per run.

## 6. Failure / abstention handling

- **Abstentions** are counted separately from FPR/TPR and reported
  per slice (count and rate). An abstained row is never counted as a
  correct negative (or positive). Abstained rows still contribute
  their score to AUROC/TPR@FPR where the metric definition says so,
  per the existing `reporting_rules` in each record.
- **Detector failure** (exception, timeout, malformed row): the run
  fails closed. A failed row is not silently dropped; it is recorded
  in the run artifact's drops manifest with its reason, or the run
  is invalid. Failure counts are not hidden inside abstention counts.
- **Out-of-domain / short-text / refusal tests** are worker E's scope
  (independent reproduction + OOD/short-text/refusal). Their results
  do not feed the FPR gate and do not upgrade registry records.
- **A no-utility or below-chance result stays a negative result**,
  not a threshold-change invitation.

## 7. Gates (predeclared — no exceptions, no post-hoc changes)

### 7.1 Per-record upgrade gate (stored status `partial` → `supported`)

A registry record may be upgraded ONLY if ALL of the following hold:

1. A W8 run artifact exists under `docs/evidence/runs/` with a full
   manifest (run_id, run_date, runner, code_version, dependency lock
   or lock SHA, hardware/runtime, seeds, exact command, drops
   manifest with inclusion/drop counts, per-row hashes, abstention
   counts) — committed on a W8 corpus branch and integrated by the
   coordinator. No artifact, no upgrade. No interpretation of a
   result without its artifact.
2. The measured slice meets n_human ≥ 100 AND n_ai ≥ 100.
3. The slice's native FPR Wilson 95% upper bound is ≤ 0.05 at the
   fixed native operating point (§3).
4. The slice was measured on a **disjoint final holdout**: frozen
   manifests, final evaluation inaccessible to tuning, disjoint by
   content hash from ALL prior samples of the same dataset
   (document-level overlap excluded by identity, never by score).
   Pre-W8 artifacts do NOT retroactively upgrade records: the
   already-measured values in §1 (e.g. Beemo 200/0.0188, MAGE
   117/0.0318, DetectRL-X 400/0.0095, GhostWriter 137/0.0273) meet
   the numeric bar but were measured on preliminary strided subsets
   with no disjoint final holdout and no reviewer assessment, so
   they stay `partial` unless a W8 final-holdout run re-measures
   them under this gate.
5. All mandatory-for-supported fields are present
   (`textforensics.validation.missing_mandatory_fields` returns []),
   so the effective status is not capped to `partial`; detector
   version is 0.1.0; `limits.next_revalidation_due` is in the future;
   `limits.demoted_by` is unset; contamination flag is `no` with its
   stated justification (hand-written heuristic, no training).
6. Worker E's independent reproduction agrees with the artifact's
   numbers. An unreproduced artifact cannot upgrade a record; it
   stays `partial` and the coordinator records it as pending
   reproduction.
7. The registry edit recomputes the record's `signature` via
   `textforensics.validation.compute_signature` (SHA-256 of the
   canonical JSON excluding `signature`) and recomputes the
   registry `registry_id`; the registry validates against
   `src/textforensics/schemas/validation-registry.schema.json`
   (`additionalProperties: false` — no new fields, no new top-level
   keys); `scripts/check_claims.py` still reads 33/33; schema
   validation (13 OK) and pre-commit (13/13) still pass.
8. A new record that supersedes an old one sets `supersedes` to the
   old record_id (precedent: evr-20261108-raid supersedes
   evr-20261106-raid; evr-20261110-opai-bench supersedes
   evr-20261106-opai-bench). The superseded record stays in the
   registry as `partial` history; it is never deleted or rewritten.

A slice that does not meet n ≥ 100 AND Wilson upper ≤ 0.05 stays
`partial` (or is recorded as a gap). No upgrade without a predeclared
gate and a disjoint final holdout.

### 7.2 Report-card lead gate (unknown → supported)

The report-card lead flips from `unknown` to `supported` ONLY if a
W8 worst-slice aggregation run artifact (same shape as
`EV-20261110-human-fpr`: per-slice detail with `slice_kind`,
`n_human`, `fpr_native_wilson`, `assessment.can_support_fpr_claim`
and `blockers`, plus top-level `worst_slice_wilson_ci_upper` /
`worst_document_slice_wilson_ci_upper`) recomputed over the W8
final-holdout document slices shows that the WORST document slice
meets n_human ≥ 100 AND Wilson upper ≤ 0.05 AND
`assessment.can_support_fpr_claim` is true — i.e. the gate logic in
`scripts/check_claims.py` (`FPR_BAR_N_HUMAN_MINIMUM = 100`,
`FPR_BAR_WILSON_UPPER_CEILING = 0.05`, worst-document-slice
qualification) reads the new artifact as qualified. The lead value
is the worst-slice Wilson upper bound from that artifact.

Otherwise the lead stays `unknown`, and the D part-report must
document exactly why: which slice blocks it, with its n and upper
bound. In particular: if the n=56 OpAI-Bench 20261106 slice cannot
be expanded to n ≥ 100 (or is superseded only by a slice that still
fails the bar), the lead stays `unknown` and that is the honest
outcome. The lead is NEVER filled from a best slice, a single slice,
or a pooled value.

### 7.3 What D will not do

- No re-tuning of operating points, thresholds or S17 values.
- No pooling away of harms; no suppression of findings.
- No registry change without a run artifact and a recomputed
  signature / registry_id.
- No hand-edit of `docs/evidence/report-card.md`: it is generated
  by `scripts/check_claims.py` and CI diffs it. The lead changes
  only through the gate reading a qualifying artifact.
- No change to inference or provenance code. No change to
  `pyproject.toml` (none is needed for this work).
- No use of PAN 2025, no attempt to obtain it.

## 8. Evaluation procedure (decided now, executed later)

1. Collect each corpus worker's run artifacts (A: RAID+MAGE,
   B: Beemo+DetectRL-X, C: GhostWriter+OpAI-Bench) from their
   branches/worktrees, plus their part-reports in
   `hidden_files/audit-w8-{a,b,c}-report.md`, and worker E's
   reproduction report.
2. For each artifact, verify: file SHA-256 matches the citing
   record, manifest complete (§7.1.1), slice disjoint by content
   hash from prior samples, operating point unchanged, Wilson
   intervals recomputed from (k, n) with `wilson_ci`.
3. Apply §7.1 per record; apply §7.2 to the recomputed worst-slice
   aggregation. Record every non-upgrade with its blocking reason.
4. Record PAN 2025 as an explicit gap (§5.3) in the registry
   documentation and the D part-report.
5. Verify on the exact merged tree: registry schema validation,
   `check_claims.py` 33/33 (run alone, never concurrently with the
   full suite; clean `/tmp/pytest-of-root` first if needed),
   pre-commit 13/13. Hand back branch `audit-w8-d` + head hash +
   part-report. Do NOT merge — the coordinator integrates.

## 9. Amendments

This predeclaration is frozen at commit time. Any change to a claim,
operating point, minimum, method, slice or gate after a W8 result
exists must be recorded as a dated amendment below, stating what
changed, why, and which results were already known — and any claim
touched by an amendment is re-evaluated from scratch under the
amended text.

- (none)
