# Architecture

TextForensics treats AI-text detectors as fallible measurement instruments.

## Design rule

**A score is not a probability, a detector is not a witness of ground truth, and agreement is not independence.**

The architecture therefore separates detector outputs, calibration, robustness, aggregation and provenance.

## Layers

1. **TFDP/1 detector protocol** — a stable result contract with explicit score semantics and abstention.
2. **Detector registry** — built-ins plus third-party Python entry points under `textforensics.detectors`.
3. **Feature/baseline layer** — the zero-dependency stylometric baseline used for development and smoke testing.
4. **Forensic orchestrator** — executes detectors without silently converting raw scores into probabilities.
5. **Verdict-integrity layer** — estimates how strong the detector evidence is for the current document.
6. **Robustness probes** — harmless text normalizations reveal unstable instrument behavior.
7. **Provenance layer** — process evidence remains separate from linguistic inference.
8. **Interfaces** — Python, CLI, MCP and optional HTTP API.

## TFDP/1

See [SPEC.md](SPEC.md). The key fields are detector identity/version, method family, execution location, raw score semantics, verdict, threshold, calibration metadata, reliability and warnings.

Third-party adapters are discovered with Python package entry points. A detector package does not need to depend on TextForensics internals beyond the public protocol objects.

## Verdict Integrity

The current grade is deliberately conservative. It considers:

- available text length
- independent detector-family count
- number of calibrated detector outputs
- cross-detector categorical agreement
- stability under benign transformations

It does **not** use the direction of the detector verdict when deciding the grade. A highly trustworthy `human_like` conclusion and a highly trustworthy `ai_like` conclusion should be judged by the same evidence-quality rules.

## Family-balanced consensus

TextForensics groups detector outputs by methodological family before forming a categorical consensus. Multiple variants of one transformer family therefore contribute one family vote rather than multiplying their influence. If two independent families split, the consensus abstains. Calibrated probabilities are only aggregated when every contributing family supplies calibrated values.

The grade is an engineering heuristic in v0.2 and will be replaced/validated against held-out reliability studies as adapters and datasets are added.

## Forensic bundle

`textforensics.forensic-bundle/v1` is designed to be portable and reproducible. It hashes the exact analyzed text and records detector versions/results rather than only the aggregate display value.

The bundle is intended to make questions such as these answerable later:

- Which detector version produced this verdict?
- Was the detector calibrated?
- Did independent method families agree?
- Did whitespace/punctuation normalization change the conclusion?
- Was the input too short for the detector's declared operating range?
- Was any provenance evidence supplied?

## Why provenance is separate

A text detector infers origin from linguistic/statistical signals. A provenance system records process evidence. TextForensics can present both, but never merges them into a fake single probability.

## Next architecture milestone

Add production detector adapters spanning genuinely different families, then make the integrity grade empirical: learn/validate reliability mappings from benchmark results stratified by domain, language, length and perturbation class.
