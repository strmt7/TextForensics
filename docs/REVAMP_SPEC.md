# TextForensics v1.0 Design Specification

**Status:** implementation contract
**Supersedes:** alpha behavior in `SPEC.md`, `ARCHITECTURE.md`, and the README's alpha claims
**Research input:** [`REVAMP_RESEARCH_2026.md`](REVAMP_RESEARCH_2026.md)

---

## 1. Product definition

TextForensics is an **independent audit layer for AI-text detectors**.

Given a text and a set of detectors, it reports:

1. what each detector observed, in that detector's native semantics;
2. which input conditions were observed or declared;
3. which validation evidence covers those conditions, with evidence references;
4. a qualitative **Trust Map** whose dimensions are `supported`, `partial`, `unknown`, or `out_of_scope` (`stale` is added by Trust Map v3, §6.4);
5. explicit limitations and abstention reasons;
6. a portable, machine-verifiable case file that excludes raw text by default.

It does **not**:

- claim to prove authorship;
- emit an authorship probability unless a documented, held-out calibration artifact supports that exact output;
- average detector probabilities into an ensemble probability without a separate ensemble calibration;
- optimize text for detector evasion;
- certify regulatory compliance.

---

## 2. Non-negotiable invariants

These are derived from `AGENTS.md` and are enforced in code and tests.

| ID | Invariant | Enforcement |
|---|---|---|
| I1 | A score is not a probability. | `DetectorPrediction.calibrated_ai_probability` requires `calibration_id`; `CalibrationArtifact` must be evaluated and disjoint; Trust Map is never numeric. |
| I2 | Detector-local calibration is not ensemble calibration. | `consensus.family_balanced_consensus` emits a top-level probability only when the caller supplies a separate `ensemble_calibration_id`. |
| I3 | Preserve abstention. | `unknown`/`out_of_scope`/`partial` are first-class; `insufficient` overall is a valid result. |
| I4 | Do not hide disagreement. | Per-detector observations and failures remain in the bundle; family votes are visible. |
| I5 | Provenance is first-class. | Detector/version, calibration ID, registry ID, git SHA, run artifact hash, environment hash, and dataset fingerprint are recorded. |
| I6 | Core is local-first. | Core dependencies are stdlib-only; remote adapters require explicit configuration. |
| I7 | No telemetry. | The package contains no telemetry/metrics code; nothing is recorded or transmitted. |
| I8 | Raw text is excluded from portable case files by default. | Deterministic seal rejects forbidden raw-text keys; `raw_text_included=false`. |
| I9 | A claim must trace to a reproducible artifact. | `docs/CLAIMS.yaml` + `scripts/check_claims.py`; CI gate. |
| I10 | Sentence/chunk scores are not sentence-level probabilities. | Segment outputs carry `uncalibrated_diagnostic` semantics. |
| I11 | Cryptographic provenance/watermarks are a separate evidence class. | Separate schemas and report sections; never fused into stylometric scores. |
| I12 | Heavy dependencies are optional. | `pyproject.toml` core has no ML/GPU deps. |

---

## 3. Architecture

```
                    ┌──────────────────────────┐
                    │  Input text + metadata   │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ conditions.extract        │
                    │ language/length/domain/   │
                    │ editing/generator/pop.    │
                    └────────────┬─────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌─────────▼─────────┐
│ detectors         │  │ evidence registries │  │ provenance         │
│ TFDP/2            │  │ U7 claims registry  │  │ ledger/C2PA/process│
│ native scores     │  │ + U1 validation     │  │ separate classes   │
│                   │  │ registry (§5.5)     │  │                    │
└─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ trust.assess             │
                    │ evidence-conditioned     │
                    │ Trust Map v2 (v3 for    │
                    │ U1 registry-derived     │
                    │ maps, §6.4)             │
                    └────────────┬─────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌─────────▼─────────┐
│ report bundle v2  │  │ case file v3      │  │ drift observatory │
│ JSON/CLI/API/MCP  │  │ seal + replay     │  │ snapshots + alerts│
└───────────────────┘  └───────────────────┘  └───────────────────┘
```

### 3.1 Module responsibilities

| Module | Responsibility |
|---|---|
| `conditions.py` | Deterministic extraction of input conditions and confidence; no authorship inference. |
| `evidence.py` | Validation evidence registry, slice matching, artifact verification, per-detector coverage. |
| `trust.py` | Aggregation of per-detector coverage and live observations into Trust Map v2. |
| `calibration.py` | Fit/apply/validate detector-local calibration; fail-closed semantics. |
| `detectors.py` | TFDP/2 protocol, prediction validation, plugin discovery, execution isolation. |
| `policy.py` | Claim records tied to verified evidence artifacts and expiry. |
| `report.py` | Forensic Bundle v2 orchestration and deterministic serialization. |
| `casefile.py` | Sealed case file v3 (default seal), portable manifest, replay. |
| `verify.py` | Independent re-derivation and verification paths. Accepts case-file v1/v2/v3, Trust Map v1/v2/v3, bundle v1/v2. |
| `observatory.py` | Longitudinal probe snapshots and drift reports. |
| `probe_runs.py` | U3 drift observatory probe runs: per-run metrics, persistence-gated alerts, demotion into the validation registry, Trust Map threading. |
| `probe_corpus.py` + `probe_metrics.py` | Frozen probe corpus (v1.0.0) and probe-run metric computation (U3). |
| `benchmark.py` | Dataset scoring, threshold selection, evidence-record generation. |
| `datasets.py` | Benchmark dataset loaders, Phase 3 waves 1–2 (RAID, MAGE, Beemo, OpAI-Bench, GhostWriter, DetectRL-X measured; DetectRL, M4, M4GT-Bench, MixSet licence-blocked with refusing loaders); shared resumable downloader. |
| `validation.py` | U1 validation-evidence records and registry: partial cap, hard rejections, SHA-256 hash-seal signatures, computed staleness, v3 Trust Map derivation (§5.5, §6.4). |
| `mixed_origin.py` | U4 mixed-origin / co-authorship report builder and schema. |
| `sealing.py` | Sealing-key files (Ed25519, mode 0600) and case-body signing helpers (U2, T2). |
| `timestamp.py` | RFC 3161 time-stamping for sealed case files (U2, T3); free-TSA tokens labelled non-qualified. |
| `ed25519.py` | Pure-stdlib Ed25519 (RFC 8032) for sealed case files (U2). |
| `dsse.py` | DSSE (Dead Simple Signing Envelope) for sealed case files (U2, T2). |
| `_standalone_verify.py` | Standalone stdlib-only verifier shipped inside sealed bundles (U2); replays nothing, reports replay as `unavailable`. |
| `sealed_bundle.py` | Deterministic MPL sealed-bundle packing/verification (`case export --seal`, `case verify`). |
| `bundle.py` | Canonical bundle format (pack/verify/list/check); not legacy — it is the one bundle format kept by Phase 2. |
| `cli.py` | Canonical CLI. |
| `api.py` | Canonical HTTP API. |
| `mcp_server.py` | MCP server: registers the tools listed in §11.3. |
| `mcp_tools.py` | MCP tool implementations (capability ledger, drift, fingerprint, contamination, result codec, policy evaluation). |

`trust_map_from_capability_ledger` (in `trust.py`) exists as a legacy v1 compatibility view: it builds a Trust Map on schema `textforensics.trust-map/v1` from capability-ledger claims, is explicitly *not* evidence-conditioned, and must not be presented as a Trust Map v2 result. There is no `trust_map_v1_to_v2` adapter anywhere in the tree (see §13). The former second CLI, `typer_cli.py`, was deleted in Phase 2; its only unique commands, `capability policy` and `bundle check`, plus the `--text` input flag, were ported into the canonical `cli.py`. The former stdlib browser UI, `webapp.py`, was deleted in Phase 2; `textforensics web` now serves the FastAPI `web_ui/`, which kept the `POST /api/report` raw-bundle endpoint, the `GET /index.html` alias, the browser auto-open and URL print, and the CSP/Permissions-Policy headers, and vendors Chart.js locally instead of loading it from a CDN.

---

## 4. Input conditions

### 4.1 Model

```json
{
  "schema": "textforensics.input-conditions/v1",
  "language": "en",
  "language_confidence": "high",
  "script": "latin",
  "word_count": 312,
  "char_count": 1874,
  "length_band": "medium",
  "domain_genre": "news",
  "domain_confidence": "medium",
  "editing_regime": "unknown",
  "generator": null,
  "human_population": "unknown",
  "declared": {"source": "caller", "fields": ["editing_regime"]},
  "cues": {"stopword_hits": {"en": 41}, "domain_hits": {"news": 7}},
  "extraction_version": "1"
}
```

### 4.2 Rules

- Language detection is conservative. If the margin between the top two languages is insufficient, return `language="und"` with `language_confidence="low"`.
- Script is detected independently (Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari, Han, Kana, Hangul, Thai, other).
- Domains are heuristic (`news`, `academic`, `social_media`, `email`, `fiction`, `legal`, `business`, `technical`, `student_essay`, `general`, `unknown`). Low-confidence domains are treated as `unknown` by coverage assessment.
- Editing regime is **never inferred from text**. It is `unknown` unless declared by the caller. Valid values: `human_only`, `machine_only`, `machine_then_human_edited`, `machine_then_machine_paraphrased`, `mixed`, `unknown`.
- Generator and human population are `null`/`unknown` unless declared. They are not guessed.
- Length bands: `very_short` (<50 words), `short` (50–149), `medium` (150–499), `long` (500–999), `very_long` (>=1000).

---

## 5. Validation evidence registry

### 5.1 Schema

`textforensics.evidence-registry/v1`:

```json
{
  "schema": "textforensics.evidence-registry/v1",
  "registry_id": "<sha256 of canonical records>",
  "created_at_utc": "2026-11-05T00:00:00+00:00",
  "records": [<EvidenceRecord>...]
}
```

`EvidenceRecord`:

> **Illustrative schema example — the values below are fictional and no such detector has been measured.** The detector `roberta-raid` does not exist in this repository; the only detector measured to date is the builtin heuristic (`textforensics/builtin-heuristic`). Real preliminary measurements are recorded separately as committed run artifacts in `docs/evidence/runs/` (see the note at the end of this section); no claim in `docs/CLAIMS.yaml` is made from them.

```json
{
  "evidence_id": "raid-en-news-roberta-2026-10",
  "schema": "textforensics.validation-evidence/v1",
  "detector_id": "roberta-raid",
  "detector_version": "1.0.0",
  "detector_family": "supervised-encoder",
  "evaluated_at_utc": "2026-10-15T00:00:00+00:00",
  "status": "active",
  "benchmark": {
    "name": "RAID",
    "version": "2024-08",
    "fingerprint_sha256": "<64 hex>",
    "split": "test",
    "license": "MIT",
    "citation": "...",
    "artifact_path": "benchmarks/raid/run.json",
    "artifact_sha256": "<64 hex>",
    "contamination_controls": ["train/test disjoint", "generator held out"]
  },
  "slices": [
    {
      "slice_id": "raid-en-news-150-499",
      "conditions": {
        "languages": ["en"],
        "length_words": {"min": 150, "max": 499},
        "domains": ["news"],
        "editing_regimes": ["machine_only"],
        "generators": ["gpt-4o", "claude-3-7", "llama-3-70b"],
        "generator_scope": "multi",
        "human_populations": ["news-writers"]
      },
      "n_human": 500,
      "n_ai": 500,
      "threshold": 0.5,
      "metrics": {
        "auroc": {"value": 0.91, "ci_lower": 0.89, "ci_upper": 0.93, "n": 1000},
        "auprc": {"value": 0.90, "ci_lower": 0.88, "ci_upper": 0.92, "n": 1000},
        "fpr": {"value": 0.03, "ci_lower": 0.02, "ci_upper": 0.05, "n": 500},
        "tpr": {"value": 0.82, "ci_lower": 0.79, "ci_upper": 0.85, "n": 500}
      },
      "calibration_id": "cal-raid-roberta-2026-10",
      "limitations": ["English only", "news domain only"]
    }
  ],
  "calibration_ids": ["cal-raid-roberta-2026-10"],
  "provenance": {
    "git_sha": "<40 hex>",
    "command": "python scripts/run_benchmark.py ...",
    "environment_sha256": "<64 hex>",
    "executed_at_utc": "2026-10-15T00:00:00+00:00",
    "hardware": "...",
    "runtime_seconds": 1234,
    "run_artifact_path": "benchmarks/raid/run.json",
    "run_artifact_sha256": "<64 hex>"
  },
  "limitations": ["..."],
  "supersedes": null
}
```

### 5.2 Validation rules

A record is structurally valid only when:

- `schema` is exact; IDs are non-empty; detector version is non-empty.
- `evaluated_at_utc` parses as ISO-8601.
- benchmark fingerprint is 64 lowercase hex; artifact hash is 64 lowercase hex.
- `split` is explicit; `contamination_controls` is non-empty.
- at least one slice; every slice has at least one language and one domain.
- `n_human`, `n_ai` are non-negative integers; at least one is positive.
- metrics are in `[0,1]`; CIs bracket the value; `n` is positive.
- if `fpr` or `tpr` is present, `threshold` is present.
- `calibration_ids` refer to records that declare fit/evaluation disjointness (checked when the calibration registry is available).
- `status` is `active` or `retracted`.
- `supersedes` either points to an existing record or is null.

A record is **evidence-grade** ("eligible for `supported`") only when:

- status is `active`;
- at least one matched slice has `n_human >= 100` and `n_ai >= 100`;
- metrics required for the dimension are present with CIs;
- evaluated within `max_age_days` (default 365);
- the record's benchmark fingerprint and artifact hash are present;
- the caller has not requested strict artifact verification, or the artifact hash verifies.

### 5.3 Matching

For an input condition `C` and slice `S`:

| Field | Match | Mismatch | Unknown |
|---|---|---|---|
| language | `C.language ∈ S.languages` or `*` | otherwise | `C.language == "und"` or low confidence |
| length | `S.min <= C.word_count <= S.max` | otherwise | never |
| domain | `C.domain ∈ S.domains` or `*` | otherwise | `C.domain_confidence` low or `C.domain == "unknown"` |
| editing | `C.editing_regime ∈ S.editing_regimes` or `*` | otherwise | `C.editing_regime == "unknown"` |
| generator | not required for matching; assessed via `generator_scope` | — | — |
| human population | not required for matching; reported as coverage limitation | — | — |

If language or length is a mismatch, the slice is not applicable. If domain or editing is a mismatch, the slice is not applicable for that dimension but may still inform language/length. If domain/editing is unknown, the dimension state is `unknown`, not `supported`.

### 5.4 Coverage state derivation

For each detector and dimension:

- `supported`: a matching, evidence-grade slice covers the dimension, and every required condition for that dimension is known and matched.
- `partial`: a matching slice exists but at least one of: sample size below threshold, CI missing/wide, evidence stale, input condition unknown, artifact unverified, generator/population scope not representative.
- `unknown`: no matching evidence, or the relevant input condition is unknown and no slice establishes coverage.
- `out_of_scope`: the detector's declared capability excludes the input (e.g., detected language not in `supported_languages`, or word count below `min_words`) and no evidence establishes otherwise.

Aggregation across detectors uses the best state per detector, then:

- all `supported` → `supported`;
- any `supported` and any `partial`/`unknown` → `partial`;
- all `unknown` → `unknown`;
- all `out_of_scope` → `out_of_scope`;
- `out_of_scope` mixed with `supported`/`partial` → `partial` (the evidence set covers some detectors, not all), with the excluded detectors recorded in `observed`.

### 5.5 U1 validation-evidence registry (the registry that is actually populated)

§5.1–§5.4 describe the U7 claims registry's evidence-record shape (`textforensics.evidence-registry/v1`, `docs/evidence/registry.json`). The validation evidence that Trust Map v3 is derived from lives in a second registry, added by U1:

- Schemas: `textforensics.evidence-record/v1` (one record) + `textforensics.validation-registry/v1` (the registry, `docs/validation/registry.json`). The registry carries `schema`, `registry_id` (SHA-256 of canonical records), `created_at_utc`, and `records`.
- A `ValidationRecord` binds one detector version to one measured input regime (`regime`: language/script, length bucket, domain, editing regime, generator info, human population), the dataset and licence/consent data, the run (command, git SHA, environment, artifact hash), per-slice metrics with confidence intervals, and `limits` (`next_revalidation_due`, `demoted_by`).
- **Partial cap (validator-enforced):** a record whose stored `status` is `supported` but which is missing any mandatory-for-supported field (licence reference, contamination data, sample counts, metric CIs, and the other fields listed in `validation.py:missing_mandatory_fields`) has its *effective* status capped at `partial`. The stored record does not change; only the effective status is capped.
- **Hard rejections (registration-blocking):** records missing licence/consent data or contamination data, or failing structural or signature checks, are refused outright — they are not loaded at capped status.
- **Hash-seal signatures:** `signature` is the SHA-256 of the canonical JSON of the record excluding `signature` itself (`validation.compute_signature` / `verify_signature`). A record whose signature does not match its contents is refused.
- **Computed staleness:** a record's effective status becomes `stale` when the caller's detector version differs from the record's `detector_version`, when `now` is past `limits.next_revalidation_due` (default: run date + 90 days, matching the U7 90-day rule), or when `limits.demoted_by` is set (U3 demotion). The stored record does not change when it goes stale, so its signature stays valid.
- **Current contents (2026-11-07):** 7 records, all `partial` — RAID, MAGE, Beemo, OpAI-Bench (×2, waves 1 and 2/U4 segments), GhostWriter, DetectRL-X, all for the builtin heuristic `textforensics/builtin-heuristic` v0.1.0. No record is `supported`: every measurement to date is preliminary (strided samples, see the `drops` manifest in each run artifact). DetectRL, M4, M4GT-Bench and MixSet have no records: their loaders refuse to fetch without a licence statement. PAN 2025 is pending registration.
- **Real preliminary figures (builtin heuristic only, preliminary, no claims made):** RAID AUROC 0.5937 (`docs/evidence/runs/EV-20261106-dataset-raid.json`, strided n=3000); MAGE 0.5567, Beemo 0.3976, OpAI-Bench 0.3961 (wave 1, `EV-20261106-dataset-*.json`); GhostWriter 0.436 and DetectRL-X 0.5972 (wave 2, `EV-20261107-dataset-*.json`). Worst-slice human FPR is **unknown** (`docs/evidence/report-card.md`); no FPR is claimed anywhere in the repository.

---

## 6. Trust Map v2

### 6.1 Dimensions

| Dimension | Source | Supported requires |
|---|---|---|
| `language` | detector metadata + registry | matching language slice with evidence-grade sample; input language known |
| `text_length` | detector `min_words` + registry | input length within an evidence-grade slice; detector minimum met |
| `domain_genre` | registry | input domain known and matching evidence-grade slice |
| `editing_revision` | registry + declared input | input editing regime declared and matching evidence-grade slice |
| `generator_scope` | registry | `generator_scope == "representative"` or a multi-generator slice with >=3 generators and explicit coverage |
| `human_population` | registry | at least two human populations covered, or a declared representative population; otherwise `partial` |
| `human_false_positive_evidence` | registry | matching slice has `fpr` with CI, `n_human >= 100`, and `fpr.ci_upper <= 0.05` |
| `detector_diversity` | live observations | >=2 independent families and no detector failures |
| `benign_stability` | live robustness probes | all usable detectors keep categorical verdicts and native-score drift is bounded |
| `temporal_version_stability` | registry age + probe runs | current record is fresh and >=2 consecutive clean full-corpus probe runs at the same detector version exist (see docs/OBSERVATORY.md) |

The FPR ceiling (`0.05`) is a product policy, not a universal truth. It is recorded in the Trust Map `observed` block and can be configured. A detector with FPR evidence above the ceiling is `partial`, never `supported` for consequential use.

### 6.2 Overall state

```
if language or text_length is out_of_scope for every usable detector:
    overall = insufficient
elif all dimensions supported:
    overall = strong
elif supported_count == 0 and partial_count == 0:
    overall = insufficient
elif supported_count == 0 and unknown_count >= 4:
    overall = insufficient
else:
    overall = mixed
```

`insufficient` is not an error. It is the correct result when the evidence does not cover the input.

### 6.3 Serialization

```json
{
  "schema": "textforensics.trust-map/v2",
  "overall": "mixed",
  "input_conditions": {...},
  "evidence_registry": {"registry_id": "...", "record_count": 3, "verified": true},
  "coverage": {"supported": 3, "partial": 2, "unknown": 4, "out_of_scope": 0},
  "dimensions": [
    {
      "dimension": "language",
      "state": "supported",
      "reason": "...",
      "evidence_refs": ["raid-en-news-roberta-2026-10"],
      "observed": {...},
      "limitations": ["..."]
    }
  ],
  "limitations": ["Trust Map states describe evidence coverage, not probability of authorship."],
  "generated_at_utc": "..."
}
```

No numeric trust score, percentage, grade, or probability is permitted in a Trust Map.

### 6.4 Trust Map v3 (U1 registry-derived maps)

v2 behaviour and the v2 schema contract are unchanged. v3 (`textforensics.trust-map/v3`, the default schema for maps derived from the U1 validation registry via `validation.derive_trust_map`) adds a fifth dimension state:

- `stale`: a matching U1 record exists but its effective status is stale — the detector version changed since the record was made, `limits.next_revalidation_due` has passed, or the record was demoted (U3). See §5.5.
- In the v3 overall-state formula, `stale` counts as neither `supported` nor `partial`: `strong` requires every dimension `supported`; `insufficient` when language or `text_length` is `out_of_scope`, or when no dimension is `supported` or `partial`; otherwise `mixed`. (The v2 formula in §6.2 is the same shape with four states; a v2/v1 map carrying `stale` is rejected by `verify.py`.)
- **`mixed` cap:** a v3 map derived from U1 records alone is at most `mixed` until U3 supplies longitudinal evidence. `temporal_version_stability` caps at `partial` from a single snapshot; it may exceed `partial` only when `MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT` (2) consecutive clean full-corpus probe runs exist at the same detector version, supplied via `derive_trust_map(longitudinal=...)`. Because one dimension can never be `supported` from U1 records alone, `strong` is unreachable.
- A v3 map's `evidence_registry` block identifies the U1 validation registry (`registry_id`, `record_count`); every dimension cites its matching record IDs in `evidence_refs`. The v1 `EvidenceRegistry` is never consulted for a v3 map.
- `supported` additionally requires a matching U1 record with effective status `supported`, at least 100 human and 100 AI samples, and no contamination. `human_false_positive_evidence` additionally requires an `fpr_native` metric with CI and `ci_upper <= fpr_ceiling` (default 0.05).

---

## 7. Calibration contract

### 7.1 Supported methods

| Method | Formula | Parameters |
|---|---|---|
| `platt` | `sigmoid(A*x + B)` | `A`, `B` |
| `temperature` | `sigmoid(x / T)` | `T > 0` |
| `isotonic` | piecewise-linear monotone interpolation | `x[]`, `y[]` |
| `beta` | `sigmoid(a*ln(x) - b*ln(1-x) + c)` | `a`, `b`, `c` |
| `identity` | `x` (diagnostic only, never probability-eligible) | none |

- `x` is the detector's native score on a documented `[0,1]` scale with documented direction.
- `beta` implements the Kull et al. (2017) beta-calibration map, not an ad-hoc beta CDF.
- Unknown methods raise `CalibrationError`; they never silently return the raw score.

### 7.2 Artifact requirements

A probability-eligible artifact requires:

- `detector_id`, `detector_version`, `calibration_id`;
- `method`, `parameters`;
- `fit_dataset` with fingerprint and split;
- `evaluation_dataset` with a different fingerprint and an explicit held-out split;
- `disjointness` declaration with evidence (e.g., fingerprint inequality, split manifest hash);
- `sample_count` for fit and evaluation;
- `metrics` (`brier`, `ece`, `log_loss`) on the evaluation set;
- `code_version`, `created_at_utc`, `run_artifact` hash;
- no `fit_dataset`/`evaluation_dataset` fingerprint collision.

If any requirement is missing, the artifact is `fit_only` and `eligible_for_probability=False`. `calibrate()` on such an artifact raises unless `allow_unvalidated=True` is explicitly passed by a diagnostic caller, and the result carries `calibration_status="unvalidated"`.

### 7.3 Fit/evaluation disjointness

- The fit and evaluation fingerprints must differ.
- If a split manifest is supplied, the manifest must declare disjoint sample IDs and the artifact must hash the manifest.
- A dataset-level hash equality is sufficient to reject, but hash inequality alone is not proof of disjointness; the artifact must state the split strategy and sample counts.

---

## 8. Detector protocol TFDP/2

`DetectorPrediction` adds:

- `native_score_direction`: `higher_means_ai`, `lower_means_ai`, or `not_applicable`;
- `score_range`: `[min, max]` or null;
- `supported_length`: `{min_words, max_words}` or null;
- `supported_domains`: list;
- `supported_editing_regimes`: list;
- `supported_generators`: list or `["*"]`;
- `calibration`: `{calibration_id, method, evaluation_fingerprint}` or null;
- `runtime`: `{mode, provider, provider_version, model_id, device}`;
- `evidence_schema`: `"textforensics.detector-evidence/v1"`.

Backward compatibility: TFDP/1 predictions remain accepted and are normalized to TFDP/2 with `native_score_direction="unknown"` and `score_range=None`; the report records the normalization.

Validation rules remain: finite scores, probability only with calibration ID, no raw-text echo, no forbidden evidence fields.

---

## 9. Case file v3 and replay

### 9.1 Case file

```json
{
  "schema": "textforensics.case-file/v3",
  "tool": {"name": "TextForensics", "version": "1.0.0", "git_sha": "..."},
  "created_at_utc": "...",
  "raw_text_included": false,
  "forensic_bundle": {...},
  "manifest": {
    "content_sha256": "...",
    "registry_id": "...",
    "registry_sha256": "...",
    "calibration_ids": ["..."],
    "schema_versions": {"forensic_bundle": "v2", "trust_map": "v3", "detector_result": "v2"},
    "git_sha": "..."
  },
  "input": {"content_sha256": "...", "word_count": 0, "language": "en"},
  "detector_observations": [...],
  "validation_refs": [...],
  "limitations": {"plain_language": {...}, "counterfactuals": [...]},
  "process": {"checklist": {"template_notice": "Template, not legal advice", "items": {"D1": {...}}}},
  "custody": [{"actor": "sealer", "action": "sealed", "entry_hash": "..."}],
  "seal": {"algorithm": "sha256", "custody_head": "<entry_hash of last custody entry>", "signature": null, "timestamp": null, "digest_publication": null},
  "gaps": [{"field": "input.sentence_count", "reason": "not recorded at seal time"}],
  "case_sha256": "..."
}
```

Three seal tiers (U2):

- **T1 — hash seal (default):** `seal.signature` and `seal.timestamp` are `null`. Integrity rests on `case_sha256` (SHA-256 over canonical JSON excluding `case_sha256`), the per-file manifest hashes, and the v3-only `custody` hash chain (`seal.custody_head` is the last custody entry's hash; each entry chains the previous entry hash). A hash seal proves integrity since sealing only — never authorship, never that the analysis was run.
- **T2 — Ed25519/DSSE signature (opt-in):** `seal.signature` is `{"algorithm": "ed25519", "key_fingerprint": "...", "signer": {"identity": ..., "role": ...}, "dsse": <envelope>}` — a DSSE envelope over the case body, produced by `sealing.sign_case_body` (pure-stdlib Ed25519, `ed25519.py` + `dsse.py`). Keys come from a sealing-key file created by `case keygen` (Ed25519 seed, file mode 0600); `case export --seal --signing-key PATH` supplies it. Verification needs the public key (`case verify --public-key PATH`, or a hex public key); a signature present without a public key yields exit 2 (checks could not run), not a pass.
- **T3 — RFC 3161 timestamp (opt-in):** `seal.timestamp` holds a timestamp-token record (`timestamp.py`) when `--timestamp-url` was supplied to `case export --seal`. A token from a free TSA is labelled non-qualified: only a qualified timestamp (QTSP, EU Trusted List) carries an eIDAS presumption of time/integrity. A token that cannot be obtained fails the seal. A token supplied separately is verified with `case verify --timestamp-token PATH` (bare case files only; a sealed bundle carries its token inside).
- `seal.digest_publication` records an optional public digest publication. Signing (T2) and timestamping (T3) both require `--seal`: they apply to the sealed MPL bundle, not to a bare case file export.

- `case_sha256` is SHA-256 over canonical JSON excluding `case_sha256`.
- Raw text keys are rejected recursively.
- Deterministic mode removes `runtime_ms`, `generated_at_utc` volatility, and other non-reproducible fields.
- v1 and v2 case files still verify; v3 is what the system seals.
  The seal cannot contain its own bundle digest (circularity), so the
  per-file manifest + bundle digest live in the sealed bundle's
  `manifest.json` (MPL pattern) plus a companion seal record.
- `seal.signature` is `null` for a T1 hash-only seal, or an Ed25519 /
  DSSE object (T2, `{"algorithm": "ed25519", "key_fingerprint": ..., "signer": ..., "dsse": ...}`) when a signing key was supplied; `seal.timestamp`
  holds an RFC 3161 token record (T3, free TSAs labelled
  non-qualified) when one was requested. `seal.custody_head` is the
  hash of the last `custody` entry (v3 only).
- The D1–D10 checklist is re-derived at verification time
  (`_checklist_consistency`): an item marked `satisfied` without its
  supporting evidence is reported, never silently accepted. Sealing
  does not enforce it — only verification does.

### 9.2 Replay

`replay_case_file(case, *, text=None, detectors=None, registry=None)`:

1. verify the case seal and schema;
2. if `text` is supplied, verify `sha256(text) == bundle.content_sha256` (normalization is explicit; default exact UTF-8) — **hash-then-reveal: a mismatch aborts with `text_hash_mismatch` before any detector runs**;
3. if detectors are supplied, run them and compare:
   - detector IDs/versions present,
   - native scores within an explicit tolerance (default exact for deterministic local detectors; `atol=1e-9`),
   - categorical verdicts,
   - calibration IDs;
4. re-derive Trust Map dimensions from the sealed conditions and registry (v3 maps via the U1 validation registry when supplied; `stale` is a distinct state);
5. return `{"valid": bool, "errors": [...], "checks": {...}}`.

Replay without text verifies only structural integrity and re-derivation. It cannot re-run detection.

### 9.3 Sealed bundle

`case export --seal` packs a v3 case into a deterministic MPL bundle
(`sealed_bundle.py`): canonical JSON, sorted stored ZIP entries,
normalised ZipInfo, archive comment `mpl-bundle-sha256:<manifest
SHA-256>`, carrying `case.json`, the standalone stdlib-only verifier
(`_standalone_verify.py`), an optional RFC 3161 token, and an MPL
manifest with a companion seal record. `case verify` accepts a bundle
or a bare case file and exits 0 (verified), 1 (seal failed), or 2
(checks could not run). The standalone verifier replays nothing (no
detectors standalone) and reports replay as `unavailable`. Every
verification output carries a one-line scope statement: the seal
proves integrity since sealing only — never authorship, never that
the analysis was run.

---

## 10. Claims gate

`docs/CLAIMS.yaml` + `scripts/check_claims.py` + the CI `claims-gate` job (U7). There are no "tiers" (`readable` / `tool_backed` / `validated` do not exist in the code or the claims file); claims carry a **status**:

```yaml
claims:
  - id: "trustmap.evidence_conditioned"
    statement: "Trust Map v2/v3 is evidence-conditioned: ..."
    category: "trust-map"
    status: "verified"
    evidence_type: "test"
    evidence_path: "tests/test_trust_evidence.py"
    evidence_record_id: "EV-20261106-suite"
    run_artifact_sha256: "<64 hex>"
    values:
      tests_passed: 2585
    last_verified: "2026-11-06"
    owner: "trust-map"
```

Statuses: `verified` / `partially_verified` / `unverified` / `false` / `stale`. At HEAD, 33 claims, 33 passed, 0 failed.

The gate (`python scripts/check_claims.py`, exit 0 on pass) enforces, for every claim:

- **(a) Record linkage:** the claim's `evidence_record_id` must resolve to a record in the U7 evidence registry (`docs/evidence/registry.json`, schema `textforensics.evidence-registry/v1`); the record's artifact must exist under `docs/evidence/runs/`.
- **(b) Artifact re-hash:** every referenced run artifact is re-hashed; a mismatch with the recorded `run_artifact_sha256` fails the claim.
- **(c) `values`-map comparison:** the numbers in the claim's `values` map are compared against the values in the cited run artifact (with tolerance); a mismatch fails the claim. The `values` map is also checked against the claim statement text.
- **(d) Staleness:** a `verified` claim whose evidence record is more than 90 days old (`STALENESS_DAYS = 90`), or whose detector version changed since the run, is reported `stale`, not `verified`.
- **(e) Drops manifest:** a run artifact without a `drops` manifest (explicitly listing what the run did *not* cover) is reported `incomplete`.
- **(f) Deterministic report-card regeneration:** the gate rewrites `docs/evidence/report-card.md`, which leads with the worst-slice human false-positive rate (currently **unknown** — no human-FPR evidence is recorded in the registry yet) and lists every claim with its status and evidence record. CI diffs the regenerated file; a diff fails the job. Do not hand-edit the report card.

Evidence types: `test` (a test file is run), `command` (a command chain is re-executed and its output re-checked), `benchmark` / `code-audit` / `doc` / `external-audit` (artifact hash + values comparison). A claim whose evidence cannot be re-executed or re-hashed is not `verified`.

README numbers must cite a `claims` entry (AGENTS.md rule 1: every number must trace to a committed/reproducible run artifact).

---

## 11. CLI, API, and MCP surfaces

### 11.1 Canonical CLI

The canonical CLI is `textforensics` (`src/textforensics/cli.py`, argparse). Top-level commands (from `textforensics --help`):

```
textforensics scan TEXT|--file PATH [--json]            # local alpha pattern baseline
textforensics mixed-origin TEXT|--file PATH             # U4 mixed-origin / co-authorship report
textforensics audit TEXT|--file PATH                    # formulaic/naturalness patterns (NOT the forensic audit of §1);
                                                        # also: audit export / audit verify (audit anchors)
textforensics localize TEXT|--file PATH                 # diagnostic segment scores
textforensics compare FILE FILE                         # compare two text versions
textforensics snapshot ...                              # append a tamper-evident draft snapshot to the ledger
textforensics verify-ledger ...                         # verify the provenance ledger hash chain
textforensics calibrate ...                             # fit a threshold artifact on calibration-only JSONL
textforensics benchmark ...                             # evaluate the built-in baseline on labeled JSONL
textforensics fingerprint ...                           # dataset fingerprint for contamination tracking
textforensics check ...                                 # benchmark contamination check between datasets
textforensics select-threshold ...                      # operating threshold on calibration-only data
textforensics detectors                                 # list installed detector adapters
textforensics schema ...                                # validate and inspect JSON schemas
textforensics report TEXT|--file PATH                   # build a reproducible detector-evidence bundle
textforensics case export --output PATH [--seal] [--signing-key PATH] [--timestamp-url URL]
textforensics case verify CASE [--text TEXT | --text-file FILE] [--public-key PATH] [--timestamp-token PATH] [--expect-digest HEX]
textforensics case keygen ...                           # generate a sealing-key file (Ed25519, mode 0600)
textforensics bundle pack|verify|list|check ...         # sealed-bundle operations
textforensics verify ...                                # N-version integrity replay (re-derive Trust Map, calibration, metrics)
textforensics web | web-fastapi | serve                # browser UI / FastAPI WebSocket UI / ASGI API server
textforensics drift snapshot|compare|report|run|status  # drift observatory (U3: run/status are the probe-run commands)
textforensics capability list|check|export|register|policy
textforensics build-info                                # embedded build identity (source commit, deps hash, contract info)
textforensics policy ...                                # enterprise policy management, revision-floor enforcement
textforensics emergency ...                             # out-of-band emergency stop sentinel
```

There is no `trust` command, no `evidence` command group, no `calibration verify`, no `case seal`, no `case replay`, and no `claims check`. The equivalents are: Trust Map inspection via `report` (the bundle carries the Trust Map); registry inspection via `python scripts/validate_schemas.py`, the registry JSON files, and `validation.py` directly; case sealing via `case export` (v3 by default, `--seal` for a sealed MPL bundle); replay via `case verify --text ...` and the `verify` command; claims via `python scripts/check_claims.py` (see §10).

Global rules:

- `--json` prints exactly one JSON document to stdout; diagnostics go to stderr.
- Exit codes (implemented contract, `constants.py`): `0` (`EXIT_OK`, analysis complete, Trust Map sufficient), `1` (`EXIT_DOWNGRADED`, analysis complete but coverage partial/insufficient, or a seal failed in `case verify`), `2` (`EXIT_INCOMPLETE`, abstained detectors / missing calibration / checks could not run), `3` (`EXIT_ERROR`, configuration or runtime error on caught exceptions). Argparse usage errors exit `2`. There is no exit 4 or 5. `case verify` follows the MPL contract within this scheme: 0 = seal verified, 1 = seal failed, 2 = checks could not run (e.g. signature present but no public key supplied).
- No raw text in logs.

### 11.2 API

`src/textforensics/api.py` (FastAPI, served by `textforensics serve`). Actual routes — there are no `/v1/health`, `/v1/ready`, `/v1/version`, `/v1/trust`, `/v1/case/replay`, `/v1/evidence`, `/v1/evidence/coverage`, or `/v1/calibration/verify` routes:

- `GET /healthz` — liveness.
- `GET /readyz` — readiness.
- `GET /version` — package version and build identity.
- `GET /v1/detectors` — installed detector adapters and health.
- `POST /v1/analyze` → per-detector observations for a text.
- `POST /v1/report` → forensic bundle (observations + Trust Map + limitations).
- `POST /v1/case` → sealed case file (v3 by default).
- `POST /v1/audit` → audit bundle (formulaic/naturalness patterns).
- `POST /v1/compare` → comparison of two text versions.
- All endpoints validate input size, content type, and raw-text policy. CORS is loopback-only by default.

### 11.3 MCP tools

`src/textforensics/mcp_server.py` registers 16 tools with the MCP server (`mcp.server.MCPServer("TextForensics")`). There are no tools named `audit_text`, `get_trust_map`, `seal_case_file`, `replay_case_file`, `evidence_coverage`, `verify_evidence_registry`, or `claims_audit`:

- `analyze_ai_text(text)` — local alpha baseline analysis.
- `build_forensic_report(text)` — detector observations, Trust Map, stability, limitations.
- `build_case_file(text)` — sealed, raw-text-free case artifact (v3 by default).
- `detector_health()` — detector adapters and plugin-loading health.
- `localize_text_patterns(text, sentences_per_segment=4)` — diagnostic segment patterns.
- `compare_text_versions(before, after)` — compare two versions.
- `audit_writing_naturalness(text)` — formulaic-writing patterns.
- `capability_register(params)` / `capability_check(params)` / `capability_list(params)` — capability ledger.
- `verify_case_file(params)` — N-version integrity replay on a case file.
- `drift_snapshot(params)` / `drift_compare(params)` / `drift_report(params)` — drift observatory.
- `fingerprint_dataset(params)` — dataset fingerprint.
- `check_contamination(params)` — benchmark contamination check.

`src/textforensics/mcp_tools.py` additionally defines `result_encode`, `result_decode`, and `capability_policy_evaluate` as plain helper functions (unit-tested by direct import); they are **not** registered as MCP server tools.

Tool implementations in `mcp_tools.py` return `{success, exit_code, ...}` on success and `{success: False, error, exit_code}` on failure (exit codes are the §11.1 constants), and never echo raw text. The `@mcp.tool()` wrappers in `mcp_server.py` return the payload as a JSON string.

---

## 12. Quality and test strategy

### 12.1 Test layers

| Layer | What it proves |
|---|---|
| Unit | Conditions, matching, state derivation, calibration math, hash canonicalization. |
| Property | Monotonicity of calibration, idempotence of canonical hashing, no raw-text leakage, Trust Map state invariants. |
| Integration | Report + registry + case file + replay; API + CLI + MCP. |
| Golden | Deterministic case file and Trust Map fixtures. |
| Adversarial | Tampered case, forged registry, stale evidence, mismatched calibration, raw-text injection. |
| End-to-end | Analyze → seal → verify → replay with/without text. |
| Claim-to-artifact | Every claim in `docs/CLAIMS.yaml` resolves to a registry record and a re-hashed run artifact; `python scripts/check_claims.py` passes 33/33. |
| Fuzz | JSON parsing, registry fields, detector outputs, calibration parameters. |
| Mutation | Core state-derivation logic must be killed by tests. |

### 12.2 Acceptance criteria

- `pytest` passes with zero failures and zero errors.
- Coverage is reported honestly in the measured metric: line coverage (currently 83% in the extras venv, per committed run artifact `docs/evidence/runs/EV-20261107-suite.json`; see `docs/VERIFICATION.md` for the latest measured numbers). Branch coverage is not recorded per module, so no per-module branch-coverage criterion is enforceable from the recorded numbers; if a branch-coverage criterion is wanted, record branch coverage per module in `docs/VERIFICATION.md` first, then restate the criterion against it. Until then the criterion is: overall line coverage must not regress below the last recorded value without a recorded reason.
- `ruff check` and `ruff format --check` pass on `src` and `tests`.
- `python -c "from textforensics import *"` succeeds and every name in `__all__` resolves.
- `schema.validate_*` passes for all generated artifacts.
- A sealed case file verifies; a tampered file fails with a specific error.
- A registry with no records yields `insufficient`/`unknown`, never `supported`.
- A calibration artifact without held-out evaluation is rejected for probability emission.
- README claims pass `scripts/check_claims.py`.
- No benchmark number appears without a committed run artifact.

### 12.3 Out of scope for v1.0

- Training new detectors.
- GPU inference.
- A hosted service.
- Regulatory certification.
- Human-subject studies.
- A full C2PA signer/verifier implementation (integration hooks only).

---

## 13. Migration and compatibility

- `textforensics.trust-map/v1` readers: v2 is a deliberate schema bump. There is **no** `trust_map_v1_to_v2` adapter in the tree: v1 maps are accepted as legacy (no adapter, no migration) — `verify.py` accepts Trust Map v1/v2/v3, and the legacy v1 view is produced only by `trust_map_from_capability_ledger` (§3.1), which is explicitly not evidence-conditioned and must not be presented as a v2 result. A v2/v1 map carrying the v3-only `stale` state is rejected.
- `textforensics.forensic-bundle/v1` → v2: `verdict_integrity` is removed from the default bundle; a `legacy.verdict_integrity` field is available only with `include_legacy=True` and is marked deprecated.
- `textforensics.detector-result/v1` remains accepted; new fields are optional.
- CLI flags from alpha are retained where they do not conflict; deprecated flags emit a warning.
- Duplicate surfaces (`webapp`, `web_ui`) become shims or are documented as deprecated; they must not introduce new semantics. (The former duplicate CLI `typer_cli` was deleted in Phase 2; its unique commands were ported into `cli.py`. The former stdlib browser UI `webapp` was deleted in Phase 2; `textforensics web` now serves the FastAPI `web_ui/`, which kept the `POST /api/report` raw-bundle endpoint, the `GET /index.html` alias, the browser auto-open and URL print, and the CSP/Permissions-Policy headers, and vendors Chart.js locally instead of loading it from a CDN.) `bundle.py` is not a duplicate surface: it is the canonical bundle format (see §3.1).

---

## 14. Release definition

A release is shippable only when:

1. all acceptance criteria pass on the release commit (§12.2);
2. the claims gate passes: `python scripts/check_claims.py` exits 0 (33/33), and the regenerated `docs/evidence/report-card.md` is committed with no diff;
3. CI is green on the release commit where it matters (Core Python 3.11–3.15, claims gate, build/OS smoke, API/MCP surfaces, Reproducibility, CodeQL, Supply-chain, Scorecard, Semver, Repository Integrity, Container, Fuzz, Drift Observatory) — the pinned-install and Mutation jobs are release-gate jobs and must also pass (see `docs/VERIFICATION.md` for the current gate state);
4. worst-slice human-FPR evidence exists (AGENTS.md rule 10): the report card's worst-slice human FPR is a measured value with a committed run artifact, not `unknown`. While it is `unknown`, the release is blocked;
5. live-host verification has been run on the release commit (the revamp's "fully tested incl. live host" bar);
6. the case-file golden fixture matches;
7. the benchmark/evidence artifacts referenced by the README exist and hash-match;
8. `python scripts/validate_schemas.py` reports 12 OK and `pre-commit run --all-files` passes;
9. no release is created without Greg's explicit permission; report readiness instead (see `docs/RELEASE.md` for the full checklist).

There is no pull-request self-review step: development is only in `main`, with no PRs and no manual code review by Greg (process rule, 2026-11-07).
