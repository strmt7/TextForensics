# TextForensics

**Local, evidence-first AI-text forensics.** Instead of pretending a single percentage proves authorship, TextForensics combines independent text signals, exposes disagreement and uncertainty, checks whether a verdict survives harmless formatting changes, and can preserve draft-history evidence locally.

> **Status: early alpha.** The current built-in detector is a transparent zero-dependency baseline. It is useful for developing the architecture, benchmarking pipeline, provenance workflow and interfaces; it is **not yet claimed to match leading commercial detectors**. The roadmap adds calibrated open-model detectors behind a plugin interface.

## Why this project exists

AI-text detectors often disagree, can fail on edited or out-of-distribution text, and can falsely flag human writing. A responsible tool should therefore show **evidence, uncertainty, detector disagreement, robustness and provenance** rather than return one opaque number.

TextForensics is being built around five principles:

1. **No single-detector oracle.** Independent methods stay visible.
2. **False positives matter.** Calibration is designed around a target human false-positive rate.
3. **Unstable verdicts should look unstable.** Harmless formatting perturbations are used as a sanity check.
4. **Provenance is different from detection.** Draft snapshots can support an authorship/process record without pretending to infer intent from prose.
5. **Local first.** The core sends no text anywhere.

## What works today

- `scan` — local ensemble score, confidence, analyzer disagreement and robustness stability
- `localize` — chunk-level map for heterogeneous/mixed-style documents
- `audit` — transparent naturalness/formulaic-writing observations
- `compare` — compare two versions and quantify score/similarity changes
- `snapshot` / `verify-ledger` — chained local draft hashes for tamper-evident process evidence
- `benchmark` — evaluate on labeled JSONL
- `calibrate` — choose a threshold for a requested false-positive ceiling
- optional **MCP server**
- optional **FastAPI** interface
- zero runtime dependencies for the core

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

Analyze a file:

```bash
textforensics scan --file essay.txt
```

Or pipe text:

```bash
cat essay.txt | textforensics scan
```

## Find where the signal comes from

```bash
textforensics localize --file paper.txt --sentences 4
```

This scores consecutive text segments instead of assuming an entire document has one origin or style.

## Audit formulaic writing

```bash
textforensics audit --file draft.txt
```

The audit produces explicit editing observations such as repeated sentence openings, stock phrasing or unusually uniform sentence rhythm. It does **not** silently rewrite text or promise detector evasion.

## Compare two versions

```bash
textforensics compare draft-v1.txt draft-v2.txt --json
```

## Preserve draft-history evidence

```bash
textforensics snapshot draft.txt
# edit the file
textforensics snapshot draft.txt
textforensics verify-ledger
```

The ledger chains SHA-256 records so later modification of an earlier record breaks verification. This is **tamper-evident local evidence**, not a trusted external timestamp; the local clock can be changed.

## Benchmark and calibrate

Dataset format is JSONL:

```json
{"label":"human","text":"..."}
{"label":"ai","text":"..."}
```

```bash
textforensics benchmark data.jsonl --threshold 0.50
textforensics calibrate data.jsonl --target-fpr 0.01
```

A threshold learned on one corpus should not be assumed valid on another domain, language or text length.

## MCP

```bash
pip install -e ".[mcp]"
textforensics-mcp
```

Current MCP tools:

- `analyze_ai_text`
- `localize_text_patterns`
- `compare_text_versions`
- `audit_writing_naturalness`

The intent is to let local agents inspect text without handing it to a remote detector service.

## HTTP API

```bash
pip install -e ".[api]"
uvicorn textforensics.api:app --host 127.0.0.1 --port 8765
```

## The detector architecture we are building toward

The zero-dependency analyzers are only the foundation. The next stage is a plugin ensemble containing **methodologically different** detectors rather than several variants of the same classifier:

- supervised transformer classifier
- likelihood/curvature detector
- alignment-imprint style detector
- stylometry / structural detector
- provenance and document metadata evidence where available

Each detector will expose its model/version, calibration set, threshold policy and reliability. TextForensics will then report both the ensemble and the individual methods.

Planned evaluation targets include RAID-style robustness testing, unseen generators, genre/length stratification, paraphrased/edited text and false-positive-first calibration.

See [ARCHITECTURE.md](ARCHITECTURE.md) and [ROADMAP.md](ROADMAP.md).

## What TextForensics will not claim

- A detector score is **not proof** that a person did or did not use AI.
- A clean score is **not proof of human authorship**.
- The current heuristic baseline is **not advertised as state of the art**.
- Short text, highly edited text, translated text, non-native writing and domain-specific prose can behave very differently.
- The project does not promise "100% undetectable" writing.

For high-stakes authorship disputes, detector output should be treated as one source of evidence and reviewed alongside provenance, drafts, citations and other contextual evidence.

## Development

```bash
python -m unittest discover -s tests -v
```

## Contributing

The most valuable contributions are detector adapters, reproducible benchmarks, calibration work, robustness studies, provenance importers, and tests demonstrating false positives or unstable behavior.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
