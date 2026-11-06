# Calibration Guide — TextForensics

> Living document. Last major update: 2026-11-02.
> See [AGENTS.md](../AGENTS.md) for the non-negotiable development contract.

---

## 1. Calibration Methodology

### 1.1 Threshold Selection

TextForensics uses **threshold-based operating point selection** rather than full probability calibration. This is the minimal viable calibration: it ensures a detector operates at a declared false positive rate on the calibration set, without claiming the output is a calibrated probability.

**Method** (`threshold_selection.py` → `select_threshold`):

1. Load labeled calibration data (JSONL format with `label` and `score` fields)
2. Separate human and AI samples
3. Enumerate candidate thresholds from the observed score distribution (plus one sentinel above the maximum)
4. For each candidate, compute FPR and TPR
5. Select the threshold with the highest TPR that satisfies `FPR ≤ target_fpr`
6. If no threshold satisfies the target FPR, raise `RuntimeError`

**Target FPR** defaults to 0.01 (1%) but can be configured per-detector:
```python
from textforensics import select_threshold

result = select_threshold(
    "data/calibration/cal_en.jsonl",
    target_fpr=0.01,
    detector_id="textforensics/builtin-heuristic",
    detector_version="0.1.0",
)
# result.threshold → selected operating threshold
# result.observed_fpr → actual FPR at that threshold
# result.observed_tpr → TPR at that threshold
```

### 1.2 Probability Calibration (Future)

Full probability calibration (mapping scores to `calibrated_ai_probability` ∈ [0, 1]) requires:

1. **Isotonic regression** (preferred) — non-parametric, no distributional assumptions. Implemented via `sklearn.isotonic.IsotonicRegression`.
2. **Platt scaling** — parametric logistic regression on scores. Simpler but assumes sigmoid relationship.

The infrastructure supports both via the `calibrated_ai_probability` and `calibration_id` fields in `DetectorPrediction`. A calibration artifact links the artifact to the method, dataset, and version.

**Current state:** Threshold selection is implemented. Full probability calibration infrastructure is in place but no calibrated artifacts are produced by the built-in detector.

### 1.3 Why Threshold, Not Full Calibration, First

Threshold selection:
- Requires fewer assumptions about score distribution
- Is directly interpretable: "≤ X% human false positives on calibration data"
- Does not require the detector output to be in probability space
- Can be validated with a simple FPR check

Full calibration:
- Requires more calibration data for stable estimates
- Needs careful validation of calibration error (Brier score, ECE, reliability curves)
- Must be revalidated after every detector version change

---

## 2. Validation Splits — Disjointness

### 2.1 The Contamination Rule

**AGENTS.md §12:** "Prevent benchmark contamination. Training, threshold selection, calibration, and final evaluation must be disjoint."

Three sets must be disjoint:
```
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  Training     │   │  Calibration  │   │   Evaluation  │
│  (if any)     │   │  (threshold   │   │  (held-out    │
│               │   │   selection)  │   │   metrics)    │
└───────────────┘   └───────────────┘   └───────────────┘
         │                   │                   │
         ▼                   ▼                   ▼
     Model fitting     Threshold fitted      Metrics computed
     (not done         on calibration       against threshold
      in TF core)      data only            from calibration
```

### 2.2 Disjointness Verification

`validate_no_contamination(cal_path, test_path)` performs two checks:

**1. File-level hash comparison:**
```python
cal_hash = dataset_sha256(calibration_path)
test_hash = dataset_sha256(test_path)
if cal_hash == test_hash:
    raise ValueError("Files are identical; all samples overlap")
```

**2. Sample-level overlap detection:**
```python
# Hash each sample's text and check for intersection
cal_samples = {sha256({"text": row.text}) for row in calibration}
test_samples = {sha256({"text": row.text}) for row in test}
shared = cal_samples & test_samples
if shared:
    raise ValueError(f"Contamination: {len(shared)} overlapping samples")
```

### 2.3 Dataset Fingerprinting

`benchmark.py` provides dataset fingerprinting for contamination tracking:

```python
from textforensics import fingerprint_dataset, verify_fingerprint, check_disjointness

# Create fingerprint
fp = fingerprint_dataset("data/raid_en.jsonl")
# fp: DatasetFingerprint with sample hashes, count, file hash

# Verify against committed fingerprint
report = verify_fingerprint(fp, "data/raid_en.jsonl")

# Check two datasets are disjoint
disjoint = check_disjointness(fp1, fp2)
# Returns bool: True if no shared sample hashes
```

### 2.4 Benchmark Fingerprint Schema

```json
{
  "schema": "textforensics.dataset-fingerprint/v1",
  "file_path": "data/raid_en.jsonl",
  "file_sha256": "abc123...",
  "sample_count": 500,
  "sample_hashes": ["sha256:...", ...],
  "generated_at_utc": "2026-11-02T00:00:00+00:00",
  "fingerprint_sha256": "def456..."
}
```

---

## 3. Operating Point Selection

### 3.1 Target FPR

The target false positive rate determines how many human-authored texts are incorrectly flagged as AI-generated. This is the primary operating point parameter.

| Target FPR | Use Case | Risk |
|---|---|---|
| 0.01 (1%) | Default; high-stakes decisions | Conservative; may miss some AI |
| 0.05 (5%) | General screening | Balanced; moderate FP risk |
| 0.10 (10%) | Low-stakes triage | Permissive; higher FP risk |

### 3.2 Threshold Selection Algorithm

The algorithm from `select_threshold`:

```python
# 1. Load and separate
humans = [score for label, score in rows if label == "human"]
ais    = [score for label, score in rows if label == "ai"]

# 2. Generate candidates from observed scores + sentinel
candidates = sorted({score for _, score in rows} ∪ {max(scores) + ε})

# 3. Find best threshold: max TPR with FPR ≤ target
best = None
for threshold in candidates:
    fpr = count(human_scores >= threshold) / len(humans)
    tpr = count(ai_scores >= threshold) / len(ais)
    if fpr <= target_fpr:
        if best is None or candidate.tpr > best.tpr:
            best = candidate

# 4. Return with provenance
return ThresholdSelectionResult(
    threshold=best.threshold,
    observed_fpr=best.fpr,
    observed_tpr=best.tpr,
    calibration_dataset_hash=dataset_sha256(cal_path),
    ...
)
```

### 3.3 Evaluation

`evaluate_threshold(test_path, threshold, calibration_dataset_hash)` computes full classification metrics on held-out data:

| Metric | Formula | Description |
|---|---|---|
| Accuracy | (TP + TN) / total | Overall correctness |
| Precision | TP / (TP + FP) | Of flagged AI, how many were truly AI |
| TPR | TP / (TP + FN) | Of true AI, how many were caught |
| Specificity | TN / (TN + FP) | Of true human, how many were correctly identified |
| FPR | FP / (FP + TN) | Of true human, how many were falsely flagged |
| FNR | FN / (FN + TP) | Of true AI, how many were missed |

### 3.4 Full Pipeline

`run_calibration_evaluation(cal_path, eval_path, target_fpr)` orchestrates the full pipeline:

```python
result = run_calibration_evaluation(
    "data/calibration/en.jsonl",
    "data/evaluation/en.jsonl",
    target_fpr=0.01,
)
# result["calibration_result"] → threshold, FPR, TPR on cal data
# result["evaluation_result"]   → full metrics on held-out data
# result["validation"]          → disjointness report
```

---

## 4. Artifact Format

### 4.1 Calibration Artifact

Threshold selection produces a JSON artifact via `create_calibration_artifact()`:

```json
{
  "schema": "textforensics.threshold-selection/v1",
  "created_at_utc": "2026-11-02T12:00:00+00:00",
  "threshold": 0.68,
  "observed_false_positive_rate": 0.008,
  "observed_true_positive_rate": 0.872,
  "target_false_positive_rate": 0.01,
  "human_samples": 250,
  "ai_samples": 250,
  "detector_id": "textforensics/builtin-heuristic",
  "detector_version": "0.1.0",
  "calibration_dataset_hash": "abc123...",
  "calibration_record_hash": "def456...",
  "selection_method": "threshold_at_target_fpr",
  "mode": "calibration_only",
  "warning": "This artifact is fitted to the calibration corpus only. Do not use for evaluation on the same data."
}
```

**Key fields:**
- `calibration_record_hash`: SHA-256 of all other fields (provenance seal)
- `calibration_dataset_hash`: SHA-256 of the calibration JSONL file (data provenance)
- `mode`: Always `"calibration_only"` to prevent misuse as evaluation result

### 4.2 Evaluation Result

Evaluation produces a structured result via `evaluate_threshold()`:

```json
{
  "schema": "textforensics.evaluation-result/v1",
  "created_at_utc": "2026-11-02T12:05:00+00:00",
  "threshold": 0.68,
  "evaluated": 500,
  "tp": 205,
  "fp": 2,
  "tn": 248,
  "fn": 45,
  "accuracy": 0.926,
  "precision": 0.99,
  "true_positive_rate": 0.82,
  "specificity": 0.992,
  "false_positive_rate": 0.008,
  "false_negative_rate": 0.18,
  "test_dataset_hash": "111222...",
  "calibration_dataset_hash": "abc123...",
  "evaluation_mode": "held_out",
  "contamination_detected": false
}
```

### 4.3 Artifact Loading and Validation

`load_threshold_artifact(path)` validates:
1. JSON object format
2. Schema version (`textforensics.threshold-selection/v1`)
3. Required fields (`threshold`, `calibration_dataset_hash`)
4. Threshold is finite number

---

## 5. Revalidation Triggers

Calibration artifacts are detector-version-bound. The following changes **invalidate** existing calibration and require revalidation:

### 5.1 Mandatory Revalidation

| Trigger | Why |
|---|---|
| **Detector version change** | Model weights, architecture, or logic changed |
| **Detector score semantics change** | Score direction, range, or meaning changed |
| **Detector family change** | Methodological approach changed |
| **Calibration dataset change** | Different data → different threshold |
| **Target FPR change** | Different operating point required |

### 5.2 Recommended Revalidation

| Trigger | Why |
|---|---|
| **Provider version change** (remote detectors) | Remote model may have been updated |
| **Platform dependency update** | Numerical differences from library updates |
| **Benchmark drift detection** | Drift observatory flagged behavioral change |
| **New slice evidence** | Previously unseen domain/language may need re-evaluation |
| **Expiry date passed** | Capability claim `valid_until` date reached |

### 5.3 Revalidation Process

```
1. Identify the detector and its current version
2. Confirm calibration dataset is still appropriate
3. Confirm calibration and evaluation splits are still disjoint
4. Run select_threshold() on calibration data
5. Validate no contamination with test data
6. Run evaluate_threshold() on held-out data
7. Compare new vs. old artifact:
   - Threshold changed? By how much?
   - FPR within target?
   - TPR regression? By how much?
8. Create new artifact; archive old artifact
9. Register new capability claim with evidence
```

### 5.4 Drift Observatory as Revalidation Signal

The drift observatory (`drift.py`) automatically detects calibration-relevant changes:

- `calibration_id_changed` → calibration artifact changed between snapshots
- `calibrated_probability_shift_significant` → probability distribution shifted
- `score_distribution_shift` → raw scores moved significantly
- `human_fpr_increase` → human false positive rate increased

When any of these are flagged, revalidation should be initiated.

---

## 6. Calibration Pipeline Checklist

Before a calibration artifact is considered release-ready:

- [ ] Calibration and evaluation datasets are disjoint (verified by `validate_no_contamination`)
- [ ] Calibration dataset fingerprint is committed
- [ ] Evaluation dataset fingerprint is committed
- [ ] Threshold is finite and within the detector's score range
- [ ] Observed FPR ≤ target FPR on calibration data
- [ ] Evaluation metrics recorded on held-out data
- [ ] Artifact `calibration_record_hash` matches recomputation
- [ ] Artifact `calibration_dataset_hash` matches committed fingerprint
- [ ] Detector ID and version are recorded
- [ ] Capability claim is registered with `VALIDATED` tier and `EXECUTED` evidence
- [ ] Old calibration artifacts are archived (not deleted)
- [ ] Drift observatory baseline snapshot exists

---

## 7. Calibration and the Trust Map

Calibration status directly affects the Trust Map:

- **No calibration**: `calibrated_ai_probability` is `None`. The Trust Map's `human_false_positive_evidence` dimension is `unknown`.
- **Detector-local calibration**: `calibrated_ai_probability` is populated with `calibration_id`. The dimension moves toward `partial` (detector-local calibration is not ensemble calibration).
- **Ensemble calibration** (future): Requires a separate ensemble calibration artifact. Only then would a top-level probability be emitted.

The consensus module (`consensus.py`) explicitly warns when component probabilities cannot be fused:
```
"Component calibrated probabilities are not fused. A separately validated
ensemble calibration is required for a top-level probability."
```

This is an AGENTS.md hard rule (§3): "Detector-local calibration is not ensemble calibration."
