# Architecture

TextForensics is intentionally evidence-first. It does not treat any single detector score as proof.

## Layers

1. **Feature extraction** — deterministic text statistics.
2. **Independent analyzers** — structurally different signals return a score, reliability estimate, and evidence.
3. **Ensemble** — reliability-weighted aggregation plus analyzer disagreement.
4. **Robustness check** — harmless formatting normalizations are rescored; unstable verdicts are downgraded.
5. **Naturalness audit** — transparent editing observations, kept separate from authorship inference.
6. **Provenance** — chained local snapshots can support an authorship/process record.
7. **Interfaces** — Python API, CLI, optional HTTP API, optional MCP server.

## Detector plugin target

The next milestone introduces a stable detector protocol so independent methods can be installed without changing the core:

```python
class Detector(Protocol):
    name: str
    version: str
    def analyze(self, text: str) -> DetectorResult: ...
```

Planned adapters are research implementations of LAPD, Fast-DetectGPT/Binoculars-style likelihood methods, and supervised classifiers. Each adapter must expose its model/version and calibration metadata.

## Why disagreement matters

AI-text detectors can disagree strongly because they are trained on different corpora, models, domains and objectives. TextForensics therefore surfaces disagreement rather than hiding it behind an average.

## Why provenance is separate

A final-text detector infers origin from text. A provenance ledger records process evidence. They answer different questions and should never be conflated.
