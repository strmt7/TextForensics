# TextForensics

**Cross-examine AI-text detectors instead of trusting a single percentage.**

TextForensics is a local, evidence-first workbench and interoperability layer for AI-text detection. It gives different detectors one explicit output contract, preserves their individual verdicts, measures disagreement and benign-edit stability, and produces a reproducible forensic bundle with an **evidence-quality grade**.

> **Early alpha.** The repository currently ships a transparent, zero-dependency heuristic baseline to exercise the protocol and forensic pipeline. It is **not** claimed to match state-of-the-art commercial detectors yet. The architecture is deliberately ready for independent open-model and API adapters.

## The actual problem

Most detector products answer a difficult question with a deceptively simple number. But detector scores often have incompatible meanings, thresholds change, methods disagree, short or out-of-domain text is fragile, and an uncalibrated `0.82` is not necessarily an 82% probability of AI authorship.

TextForensics asks a different question first:

> **How trustworthy is the detector evidence for this specific document?**

That turns AI detection from a single-model classification problem into a forensic measurement problem.

## What is different

### 1. TFDP/1: a detector interoperability contract

Every detector adapter returns the same explicit fields:

- detector/model ID and version
- method family
- local vs remote execution
- raw score **and its semantics**
- verdict (`ai_like`, `human_like`, `abstain`)
- threshold, if one exists
- calibrated probability **only when real calibration exists**
- reliability/limitations
- evidence and runtime metadata

See [SPEC.md](SPEC.md) and [the JSON schema](schemas/detector-result.schema.json).

### 2. Verdict Integrity, not fake certainty

`textforensics report` grades the **quality of the available evidence**, not the authorship of the text. The grade considers:

- text length
- number of independent detector families
- availability of calibration
- cross-detector verdict agreement
- **family-balanced consensus**, so ten correlated variants do not get ten votes
- stability under harmless normalization

With only the built-in heuristic installed, TextForensics intentionally produces a weak/insufficient evidence grade. Adding more copies of the same model family should not magically create confidence.

### 3. Reproducible forensic bundles

A report records:

- SHA-256 of the analyzed text
- exact detector versions
- each detector's untouched result
- benign-normalization probes
- agreement and integrity factors
- optional provenance-ledger verification
- limitations and abstentions

The bundle schema is in [schemas/forensic-bundle.schema.json](schemas/forensic-bundle.schema.json).

### 4. Local provenance is separate from text detection

`textforensics snapshot` can append document hashes to a chained local ledger. That can help establish how a draft evolved, but TextForensics does **not** pretend a text classifier and process evidence answer the same question.

### 5. CLI, Python, MCP and HTTP

The same core can be used by a person, script, IDE agent or local automation.

## Quick start

```bash
git clone https://github.com/strmt7/TextForensics.git
cd TextForensics
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -e .
```

### Build a forensic report

```bash
textforensics report --file essay.txt --output report.json
```

Example structure:

```json
{
  "schema": "textforensics.forensic-bundle/v1",
  "content_sha256": "...",
  "detector_results": [
    {
      "detector_id": "textforensics/builtin-heuristic",
      "detector_family": "stylometric-heuristic",
      "score": 0.68,
      "score_semantics": "higher_means_more_machine_like; uncalibrated pattern score",
      "verdict": "abstain",
      "calibrated_ai_probability": null
    }
  ],
  "verdict_integrity": {
    "grade": "INSUFFICIENT",
    "independent_families": 1,
    "factors": [
      "single_detector_family",
      "no_probability_calibration"
    ]
  }
}
```

That `INSUFFICIENT` result is a feature, not a failure: the current evidence does not justify a confident authorship claim.

### Inspect installed detectors

```bash
textforensics detectors
```

### Basic pattern scan

```bash
textforensics scan --file essay.txt
```

### Locate heterogeneous regions

```bash
textforensics localize --file paper.txt --sentences 4
```

### Audit formulaic writing

```bash
textforensics audit --file draft.txt
```

The audit gives transparent editing observations. It does not silently rewrite text or promise detector evasion.

### Compare versions

```bash
textforensics compare draft-v1.txt draft-v2.txt --json
```

### Preserve draft-history evidence

```bash
textforensics snapshot draft.txt
# edit the file
textforensics snapshot draft.txt
textforensics verify-ledger
```

The ledger is tamper-evident local evidence, **not** an independent trusted timestamp because the local clock can be changed.

## Detector plugins

Third-party packages can register a detector without changing TextForensics itself:

```toml
[project.entry-points."textforensics.detectors"]
my_detector = "my_package:MyDetector"
```

A detector implements the TFDP/1 Python protocol and returns a `DetectorPrediction`. See [SPEC.md](SPEC.md).

The planned first serious adapters span **different method families**, not several near-identical classifiers:

- supervised transformer classifier
- likelihood/curvature detector
- alignment-imprint / representation method
- watermark/provenance evidence where available
- commercial API adapters only when explicitly configured by the user

## Benchmark and calibrate

Dataset format:

```json
{"label":"human","text":"..."}
{"label":"ai","text":"..."}
```

```bash
textforensics benchmark data.jsonl --threshold 0.50
textforensics calibrate data.jsonl --target-fpr 0.01
```

A threshold learned on one corpus must not be presented as universal. Domain, language, length and generator shift matter.

## MCP

```bash
pip install -e ".[mcp]"
textforensics-mcp
```

Current tools include:

- `analyze_ai_text`
- `build_forensic_report`
- `localize_text_patterns`
- `compare_text_versions`
- `audit_writing_naturalness`

## HTTP API

```bash
pip install -e ".[api]"
uvicorn textforensics.api:app --host 127.0.0.1 --port 8765
```

Endpoints include `/v1/analyze`, `/v1/report`, `/v1/audit` and `/v1/compare`.

## Development

The dependency-free core can be tested without downloading model weights:

```bash
python -m unittest discover -s tests -v
```

## What TextForensics will not claim

- A detector score proves authorship.
- A clean score proves human authorship.
- Raw scores from different detectors are automatically comparable.
- The current heuristic baseline is state of the art.
- A forensic evidence grade is an AI-authorship probability.
- Any rewriting process can guarantee "undetectable" text.

For high-stakes disputes, detector outputs should be reviewed alongside provenance, drafts, citations, policy and other contextual evidence.

## Roadmap

The immediate goal is to make TextForensics the **interoperability and reliability layer around AI-text detectors**, then add strong open detector adapters and reproducible evaluation rather than hiding one classifier behind a polished UI.

See [ROADMAP.md](ROADMAP.md) and [ARCHITECTURE.md](ARCHITECTURE.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
