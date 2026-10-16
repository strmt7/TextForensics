# TFDP/1 — TextForensics Detector Protocol

TFDP/1 is a small interoperability contract for AI-text detectors. It exists because detector APIs commonly expose incompatible labels, score semantics, thresholds and sentence-level outputs. The protocol does **not** pretend that raw scores from different detectors are probabilities or directly comparable.

## Minimum detector result

```json
{
  "schema": "textforensics.detector-result/v1",
  "detector_id": "vendor-or-package/model-name",
  "detector_version": "immutable-or-human-readable-version",
  "detector_family": "supervised-transformer",
  "execution": "local",
  "score": 0.73,
  "score_semantics": "higher_means_more_machine_like; raw classifier score",
  "verdict": "ai_like",
  "threshold": 0.65,
  "calibrated_ai_probability": null,
  "calibration_id": null,
  "reliability": 0.8,
  "supported_languages": ["en"],
  "min_words": 80,
  "evidence": [],
  "warnings": [],
  "runtime_ms": 12.3
}
```

## Required semantics

- `score` is an instrument output. It MUST NOT be called a probability unless independently calibrated.
- `verdict` is one of `ai_like`, `human_like`, or `abstain`.
- `detector_family` should describe the method, not the vendor. Examples: `supervised-transformer`, `likelihood-ratio`, `watermark`, `stylometric-heuristic`.
- `calibrated_ai_probability` is optional and may only be populated when a calibration procedure is documented.
- `detector_version` should be sufficient to reproduce or at least identify the instrument used.
- Adapters SHOULD abstain when inputs fall below a detector's supported length or outside a declared operating domain.

## Python plugin contract

Third-party packages may expose detector factories under the entry-point group:

```toml
[project.entry-points."textforensics.detectors"]
my_detector = "my_package:MyDetector"
```

The class implements:

```python
class Detector(Protocol):
    detector_id: str
    detector_version: str
    detector_family: str
    def detect(self, text: str) -> DetectorPrediction: ...
```

## Why the protocol separates score from probability

A value such as `0.82` can mean a classifier logit mapping, a heuristic score, a fraction of flagged sentences, or a calibrated probability depending on the system. TFDP/1 keeps those semantics explicit so an aggregator cannot silently average incompatible numbers.

## Forensic bundle

`textforensics report` wraps TFDP/1 detector results with:

- SHA-256 of the analyzed text
- detector/model versions
- benign-transformation stability probes
- cross-detector verdict agreement
- number of independent detector families
- calibration availability
- optional local provenance-ledger verification
- an **evidence-quality grade** (`A`–`D` or `INSUFFICIENT`)

The evidence-quality grade answers **“how strong is the detector evidence available for this document?”**, not **“what is the probability AI wrote it?”**.
