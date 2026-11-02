# Trust Model — TextForensics

> Living document. Last major update: 2026-11-02.
> See [AGENTS.md](../AGENTS.md) for the non-negotiable development contract.

---

## 1. Trust Boundaries — When to Trust Detector Outputs

TextForensics treats every detector as a **fallible, versioned measurement instrument**. Trust is not binary; it is dimensioned, evidence-backed, and always qualified.

### 1.1 The Trust Ladder

```
┌─────────────────────────────────────────────────────────────────┐
│  Level 4: Ensemble calibrated probability                       │
│  Requires: Separate ensemble calibration artifact + held-out    │
│            validation for the EXACT detector set definition     │
│  Status: Not yet implemented                                   │
├─────────────────────────────────────────────────────────────────┤
│  Level 3: Detector-local calibrated probability                 │
│  Requires: Calibration artifact with calibration_id, target     │
│            FPR, held-out evaluation metrics, Brier score        │
│  Status: Infrastructure present, artifacts per-detector         │
├─────────────────────────────────────────────────────────────────┤
│  Level 2: Family-balanced categorical consensus                 │
│  Requires: ≥ 2 methodologically independent detector families   │
│            with non-abstaining verdicts                         │
│  Status: Implemented (consensus.py)                             │
├─────────────────────────────────────────────────────────────────┤
│  Level 1: Raw detector observation                              │
│  Requires: Valid TFDP/1 prediction with score semantics,        │
│            detector identity, and verdict                       │
│  Status: Core functionality                                     │
├─────────────────────────────────────────────────────────────────┤
│  Level 0: Abstention                                            │
│  Input falls outside validated operating conditions             │
│  Status: Always available as fallback                           │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 When NOT to Trust

A detector output should be treated as **insufficient evidence** when:

1. **Trust Map overall is `insufficient`** — any `out_of_scope` dimension or ≥ 3 `unknown` dimensions
2. **Consensus is `abstain`** — fewer than 2 voting families, or equal AI/human split
3. **Calibration is missing** — `calibrated_ai_probability` is `None` without a `calibration_id`
4. **Benign instability** — verdict changes under harmless formatting normalization
5. **High analyzer disagreement** — inter-analyzer disagreement > 0.45 (engine-level)
6. **Short text** — below declared `min_words` for the active detector(s)
7. **Detector failure** — any configured detector failed execution
8. **Source echo detected** — detector output appears to echo submitted text (contract violation)

### 1.3 Warnings Are Data, Not Noise

Every prediction includes a `warnings` list. Warnings are machine-readable evidence about the output's limitations. Key warnings:

| Warning | Severity | Action |
|---|---|---|
| "Short text: detector-style signals are especially unreliable below the built-in baseline's 80-word minimum" | High | Treat as weak evidence; consider abstention |
| "High analyzer disagreement" | High | Do not rely on aggregate score |
| "Sensitive to harmless formatting normalization" | Medium | Check `robustness_stability` value |
| "No probability calibration" | Medium | Raw score only; not a probability |
| "Component calibrated probabilities are not fused" | Info | Ensemble calibration required for top-level probability |
| "Independent detector families disagree" | High | Investigate root cause; do not force consensus |

---

## 2. Qualitative Trust States

The Trust Map uses four qualitative states per dimension. These are **not** numeric scores and should never be aggregated into a single "trust percentage" without empirical validation.

### 2.1 State Definitions

| State | Meaning | When |
|---|---|---|
| `supported` | Evidence exists and covers this regime | Benchmark-backed, held-out validation for this exact dimension |
| `partial` | Some evidence exists but coverage is incomplete | Partial length coverage, single-family diversity, documented but not validated |
| `unknown` | No evidence available for this regime | No benchmark data, no capability claims |
| `out_of_scope` | Input clearly exceeds detector capabilities | Text below minimum word count for all detectors |

### 2.2 Overall Assessment Logic

The `build_trust_map` function computes overall status from dimension states:

```python
# Simplified logic from trust.py
unknown_count = sum(dimension.state == "unknown" for dimension in dimensions)
out_of_scope = any(dimension.state == "out_of_scope" for dimension in dimensions)
partial = any(dimension.state == "partial" for dimension in dimensions)

if out_of_scope or unknown_count >= 3:
    overall = "insufficient"  # Too many unknowns; abstain
elif unknown_count or partial:
    overall = "mixed"  # Partial evidence; proceed with caution
else:
    overall = "strong"  # All dimensions covered
```

**`trust_map_from_capability_ledger` uses similar logic** but maps from EvidenceTier:
- `VALIDATED` → `supported`
- `TOOL_BACKED` → `partial` (with detail: "tool-backed evidence")
- `READABLE` → `partial` (with detail: "documented but not machine-verifiable")
- No claim → `unknown`

### 2.3 State Examples by Dimension

**`text_length` dimension:**
- `supported`: Word count ≥ every detector's `min_words`
- `partial`: Word count ≥ some detectors' `min_words` but not all
- `out_of_scope`: Word count < every detector's `min_words`
- `unknown`: No detector declared a `min_words`

**`detector_diversity` dimension:**
- `supported`: ≥ 2 detector families produced usable observations, no failures
- `partial`: Limited family diversity or detector failures occurred
- `unknown`: No usable detector observations

**`benign_stability` dimension:**
- `supported`: All detectors maintained categorical verdict under probes
- `partial`: At least one detector changed verdict under a probe
- `unknown`: No stability evidence available

---

## 3. Trust Map Dimensions and Detector Capabilities

### 3.1 Dimension-to-Capability Mapping

| Trust Map Dimension | Detector Capability | Evidence Source |
|---|---|---|
| `language` | `supported_languages` list | Detector `detect()` output + benchmark slices |
| `text_length` | `min_words` declaration | Detector `detect()` output vs. actual word count |
| `domain_genre` | Domain-specific benchmark | Capability ledger claims, benchmark artifacts |
| `editing_revision` | Robustness to paraphrase | Capability ledger claims, editing benchmark |
| `human_false_positive_evidence` | FPR on human samples | Benchmark evaluation at operating point |
| `detector_diversity` | `detector_family` independence | Live observation grouping by family |
| `benign_stability` | Formatting invariance | Live robustness probes (per analysis) |
| `temporal_version_stability` | Version consistency over time | Drift observatory snapshots |

### 3.2 Capability Ledger Integration

The `CapabilityLedger` provides a mechanical way to register and query detector capabilities:

```python
from textforensics import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceTier,
    EvidenceRef,
    EvidenceLabel,
)

# Register a validated capability
claim = CapabilityClaim(
    detector_id="textforensics/builtin-heuristic",
    capability="language_coverage.en",
    tier=EvidenceTier.VALIDATED,
    evidence=[
        EvidenceRef(
            label=EvidenceLabel.EXECUTED,
            tier=EvidenceTier.VALIDATED,
            artifact="artifacts/benchmark/en_raid_v1.json",
            detail="RAID English slice, 500 human / 500 AI samples",
        )
    ],
    valid_until="2027-01-01",
)

ledger = CapabilityLedger()
ledger.register(claim)

# Query: is this validated?
is_validated = ledger.is_validated("textforensics/builtin-heuristic", "language_coverage.en")
```

The ledger maps to Trust Map dimensions via `ledger_to_trust_dimension()`:
```python
from textforensics import ledger_to_trust_dimension

dimension = ledger_to_trust_dimension(
    ledger,
    "textforensics/builtin-heuristic",
    "language_coverage",  # prefix match
)
# Returns TrustDimension with state="supported" for VALIDATED claims
```

### 3.3 Current Alpha State

In the current alpha, most Trust Map dimensions default to `unknown` because benchmark-backed evidence has not been fully registered. The exceptions are:

- **`text_length`**: Computed from detector `min_words` declarations
- **`detector_diversity`**: Computed from live observation family grouping
- **`benign_stability`**: Computed from live robustness probes

The remaining dimensions will transition to `supported`/`partial` as capability claims are registered with evidence.

---

## 4. Evidence Tiers

Three tiers classify how reliably a capability claim can be verified. This mirrors the Capability Ledger's `EvidenceTier` enum.

### 4.1 Tier Definitions

| Tier | Code | Definition | Machine-Verifiable? |
|---|---|---|---|
| **READABLE** | `readable` | Claim is documented (README, comments, research paper) but not machine-verifiable | No |
| **TOOL_BACKED** | `tool_backed` | Claim is backed by a tool that can re-derive it (benchmark runner, threshold selector) | Partially |
| **VALIDATED** | `validated` | Claim is backed by a committed, reproducible run artifact with provenance | Yes |

### 4.2 Evidence Labels

Four labels describe the nature of the evidence backing a claim:

| Label | Code | Meaning |
|---|---|---|
| **REPORTED** | `reported` | Source finding from literature or external report; not reproduced |
| **CALCULATED** | `calculated` | Architecture-derived estimate (e.g., "this model supports 128 languages by design") |
| **PROPOSED** | `proposed` | Engineering choice to test (e.g., proposed threshold, planned benchmark) |
| **EXECUTED** | `executed` | Check actually run and recorded with output artifact |

### 4.3 Validation Rules

The `validate_claim()` function enforces:
1. Every claim must have at least one `EvidenceRef`
2. A `VALIDATED` tier claim must have at least one `EXECUTED` evidence label

Claims with issues are rejected and do not contribute to Trust Map state.

### 4.4 Example Evidence Chain

```
Claim: "Builtin heuristic supports English with held-out AUROC ≥ 0.95"
│
├── EvidenceRef #1 (EXECUTED, VALIDATED)
│   ├── artifact: "artifacts/benchmark/raid_en_calibration.json"
│   └── detail: "RAID English calibration split, 250 human / 250 AI"
│
├── EvidenceRef #2 (EXECUTED, VALIDATED)
│   ├── artifact: "artifacts/benchmark/raid_en_evaluation.json"
│   └── detail: "RAID English held-out test split, 250 human / 250 AI, AUROC=0.961"
│
└── valid_until: "2027-06-01"  # Revalidate before this date
```

---

## 5. Abstention Policies

Abstention is a first-class outcome. When evidence is insufficient, the system should say so rather than produce a low-quality signal.

### 5.1 Engine-Level Abstention

The analysis engine (`engine.py`) has built-in abstention:

```python
def _verdict(score: float, diagnostic_reliability: float) -> str:
    if diagnostic_reliability < 0.28:
        return "insufficient_evidence"  # Abstain
    if score >= 0.68:
        return "machine_like_patterns"
    if score <= 0.32:
        return "human_like_patterns"
    return "indeterminate"
```

**`diagnostic_reliability`** is a composite of:
- Text length reliability: `min(1.0, word_count / 250.0)`
- Analyzer disagreement factor: `(0.65 + 0.35 * (1.0 - disagreement))`
- Stability factor: `(0.7 + 0.3 * stability)`

When reliability drops below 0.28, the engine returns `"insufficient_evidence"` regardless of score.

### 5.2 Detector-Level Abstention

The TFDP/1 protocol includes `verdict = "abstain"` as a valid verdict. A detector should abstain when:

| Condition | Detector Action |
|---|---|
| Input language not in `supported_languages` | Return `verdict="abstain"` with warning |
| Word count < `min_words` | Return `verdict="abstain"` with warning |
| Model/provider unavailable | Raise → caught as `DetectorFailure` |
| Calibration artifact missing | Return raw score only, no `calibrated_ai_probability` |
| Input is empty or too short | Raise `ValueError` (caught as `DetectorFailure`) |

### 5.3 Consensus-Level Abstention

The `family_balanced_consensus` function abstains when:

- Fewer than 2 families vote (fewer than 2 unique `detector_family` values with non-abstaining verdicts)
- Equal number of families vote AI and human
- All families abstain

### 5.4 Trust Map-Level Downgrade

When the Trust Map overall is `insufficient`, the bundle's limitations list includes:
- "The Trust Map describes evidence coverage; it is not an authorship probability."
- Short text warnings
- Detector failure counts

### 5.5 Short Text Policy

Text below 80 words triggers a specific warning:
```
"Short text: detector-style signals are especially unreliable below the built-in
baseline's 80-word minimum."
```

The `text_length` Trust Map dimension will be `out_of_scope` if the word count is below every detector's `min_words`.

### 5.6 Unsupported Language Policy

When input language is not supported:
- The `language` Trust Map dimension remains `unknown` (alpha state)
- Detectors should set `supported_languages` and emit warnings when input appears unsupported
- Future: automatic language identification + matching against `supported_languages`

### 5.7 Out-of-Domain Policy

When the domain/genre is not validated:
- The `domain_genre` Trust Map dimension is `unknown`
- No domain-specific calibration is applied
- A warning is added to the bundle limitations

---

## 6. Trust Map Schema

The Trust Map follows `textforensics.trust-map/v1`:

```json
{
  "schema": "textforensics.trust-map/v1",
  "overall": "mixed",
  "dimensions": [
    {
      "dimension": "language",
      "state": "unknown",
      "reason": "No validated language-identification evidence for this document.",
      "evidence_refs": [],
      "observed": {},
      "limitations": []
    },
    {
      "dimension": "text_length",
      "state": "supported",
      "reason": "The text meets every detector's declared minimum word count.",
      "observed": {
        "word_count": 320,
        "supported_detectors": ["textforensics/builtin-heuristic"],
        "unsupported_detectors": []
      }
    }
  ],
  "limitations": [
    "Trust Map states describe evidence coverage, not probability of authorship."
  ]
}
```

See `src/textforensics/schemas/trust-map.schema.json` for the full JSON Schema.
