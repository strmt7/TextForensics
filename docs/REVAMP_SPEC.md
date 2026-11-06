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
4. a qualitative **Trust Map** whose dimensions are `supported`, `partial`, `unknown`, or `out_of_scope`;
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
| I7 | No silent telemetry. | Telemetry is opt-in and local; no network by default. |
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
│ detectors         │  │ evidence registry │  │ provenance         │
│ TFDP/2            │  │ versioned slices  │  │ ledger/C2PA/process│
│ native scores     │  │ metrics + CIs     │  │ separate classes   │
└─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌────────────▼─────────────┐
                    │ trust.assess             │
                    │ evidence-conditioned     │
                    │ Trust Map v2             │
                    └────────────┬─────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌─────────▼─────────┐
│ report bundle v2  │  │ case file v2      │  │ drift observatory │
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
| `casefile.py` | Sealed case file, portable manifest, replay. |
| `verify.py` | Independent re-derivation and verification paths. |
| `drift.py` | Longitudinal probe snapshots and drift reports. |
| `benchmark.py` | Dataset scoring, threshold selection, evidence-record generation. |
| `cli.py` | Canonical CLI. |
| `api.py` | Canonical HTTP API. |
| `mcp_tools.py` | MCP tools. |

Legacy modules (`typer_cli.py`, `webapp.py`, `web_ui/`, `bundle.py`, `trust_map_from_capability_ledger`) are either thin compatibility shims or explicitly marked experimental. They cannot define new semantics.

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
| `temporal_version_stability` | registry age + drift snapshots | current record is fresh and >=2 drift snapshots over >=30 days show no material change |

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

## 9. Case file v2 and replay

### 9.1 Case file

```json
{
  "schema": "textforensics.case-file/v2",
  "tool": {"name": "TextForensics", "version": "1.0.0", "git_sha": "..."},
  "created_at_utc": "...",
  "raw_text_included": false,
  "forensic_bundle": {...},
  "manifest": {
    "content_sha256": "...",
    "registry_id": "...",
    "registry_sha256": "...",
    "calibration_ids": ["..."],
    "schema_versions": {"forensic_bundle": "v2", "trust_map": "v2", "detector_result": "v2"},
    "git_sha": "..."
  },
  "case_sha256": "..."
}
```

- `case_sha256` is SHA-256 over canonical JSON excluding `case_sha256`.
- Raw text keys are rejected recursively.
- Deterministic mode removes `runtime_ms`, `generated_at_utc` volatility, and other non-reproducible fields.

### 9.2 Replay

`replay_case_file(case, *, text=None, detectors=None, registry=None)`:

1. verify the case seal and schema;
2. if `text` is supplied, verify `sha256(text) == bundle.content_sha256` (normalization is explicit; default exact UTF-8);
3. if detectors are supplied, run them and compare:
   - detector IDs/versions present,
   - native scores within an explicit tolerance (default exact for deterministic local detectors; `atol=1e-9`),
   - categorical verdicts,
   - calibration IDs;
4. re-derive Trust Map dimensions from the sealed conditions and registry;
5. return `{"valid": bool, "errors": [...], "checks": {...}}`.

Replay without text verifies only structural integrity and re-derivation. It cannot re-run detection.

---

## 10. Claims gate

`docs/CLAIMS.yaml`:

```yaml
claims:
  - id: "trust-map-applicability"
    text: "Trust Map states are derived from registered validation evidence and input conditions."
    tier: "validated"
    evidence:
      - path: "tests/test_trust_evidence.py"
        sha256: "..."
      - path: "benchmarks/.../run.json"
        sha256: "..."
    scope: "core"
```

- Tiers: `readable`, `tool_backed`, `validated`.
- `validated` requires at least one `executed` artifact with a matching SHA-256.
- `scripts/check_claims.py` parses the YAML with a stdlib-compatible parser (or JSON fallback), verifies paths/hashes, and exits non-zero on failure.
- README numbers must cite a `claims` entry.

---

## 11. CLI, API, and MCP surfaces

### 11.1 Canonical CLI

```
textforensics audit TEXT|--file PATH [--registry PATH] [--json]
textforensics trust TEXT|--file PATH [--registry PATH] [--json]
textforensics evidence validate --registry PATH [--root PATH]
textforensics evidence list --registry PATH
textforensics evidence coverage --registry PATH --conditions JSON
textforensics calibration verify ARTIFACT
textforensics case seal BUNDLE --out PATH
textforensics case verify CASE
textforensics case replay CASE [--text FILE]
textforensics drift snapshot/compare/report ...
textforensics claims check
```

Global rules:

- `--json` prints exactly one JSON document to stdout; diagnostics go to stderr.
- Exit codes: `0` success, `2` invalid input, `3` insufficient coverage, `4` verification failure, `5` internal error.
- No raw text in logs.

### 11.2 API

- `GET /v1/health`, `/v1/ready`, `/v1/version`.
- `GET /v1/detectors`.
- `POST /v1/audit` → bundle.
- `POST /v1/trust` → Trust Map only.
- `POST /v1/case` → sealed case file.
- `POST /v1/case/replay` → replay result.
- `GET /v1/evidence` → registry summary.
- `GET /v1/evidence/coverage?conditions=...` → coverage.
- `POST /v1/calibration/verify`.
- All endpoints validate input size, content type, and raw-text policy. CORS is loopback-only by default.

### 11.3 MCP tools

- `audit_text`
- `get_trust_map`
- `seal_case_file`
- `replay_case_file`
- `evidence_coverage`
- `verify_evidence_registry`
- `claims_audit`

Tools return `{ok, data, error, exit_code}` and never echo raw text.

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
| Claim-to-artifact | Every `validated` claim resolves to a file with a matching hash. |
| Fuzz | JSON parsing, registry fields, detector outputs, calibration parameters. |
| Mutation | Core state-derivation logic must be killed by tests. |

### 12.2 Acceptance criteria

- `pytest` passes with zero failures and zero errors.
- New core modules have >=90% branch coverage; overall coverage is reported honestly.
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

- `textforensics.trust-map/v1` readers: v2 is a deliberate schema bump. A `trust_map_v1_to_v2` adapter preserves dimensions/states and adds `unknown` for new dimensions with a migration note.
- `textforensics.forensic-bundle/v1` → v2: `verdict_integrity` is removed from the default bundle; a `legacy.verdict_integrity` field is available only with `include_legacy=True` and is marked deprecated.
- `textforensics.detector-result/v1` remains accepted; new fields are optional.
- CLI flags from alpha are retained where they do not conflict; deprecated flags emit a warning.
- Duplicate surfaces (`typer_cli`, `webapp`, `web_ui`, `bundle`) become shims or are documented as deprecated; they must not introduce new semantics.

---

## 14. Release definition

A release is shippable only when:

1. all acceptance criteria pass on the release commit;
2. the claims manifest has no unresolved `validated` claims;
3. the case-file golden fixture matches;
4. the benchmark/evidence artifacts referenced by the README exist and hash-match;
5. the AGENTS.md pull-request self-review is completed and recorded.
