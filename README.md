# TextForensics

## **AI-text detection, audited.**

TextForensics is a local-first framework for treating AI-text detectors as **fallible measurement instruments**. It preserves what detectors actually report, then asks the more important question:

> **How trustworthy is this detector evidence for this exact kind of text, from this detector version, under these conditions?**

That makes the long-term product an **independent reliability and forensic audit layer around AI-text detection**, rather than another opaque "AI percentage".

> **Early alpha.** The repository already has a working local baseline, TFDP/1 detector protocol, forensic reports, stability probes, CLI, browser UI, MCP and HTTP surfaces. The built-in heuristic is development scaffolding and is **not claimed to match leading commercial detectors**.

## Why this direction

AI-text detectors can differ in score semantics, training distributions, supported languages, minimum usable length and failure modes. Performance can change across domains, generators and revised text. Provider models can also change over time.

TextForensics therefore separates four things that should not be collapsed into one number:

1. **Detector observations** — what each instrument said.
2. **Validation evidence** — where that detector/version has actually been tested.
3. **Applicability and stability** — whether that evidence covers the current input and remains stable.
4. **Process provenance** — draft/history evidence kept separate from linguistic inference.

The planned flagship output is a **Trust Map** plus a reproducible case file.

See:
- [Product north star](docs/PRODUCT.md)
- [Landscape and differentiation](docs/NOVELTY.md)
- [Architecture](ARCHITECTURE.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Benchmarking standard](docs/BENCHMARKING.md)
- [Quality gates](docs/QUALITY_GATES.md)
- [Agent development contract](AGENTS.md)

## What works today

### TFDP/1 detector interoperability

Every detector adapter can expose:
- detector/model identity and version,
- method family,
- local vs remote execution,
- native score **and its semantics**,
- verdict (`ai_like`, `human_like`, `abstain`),
- threshold if defined,
- calibrated probability only when calibration exists,
- declared limitations,
- evidence/runtime metadata.

See [SPEC.md](SPEC.md) and [schemas/detector-result.schema.json](schemas/detector-result.schema.json).

### Forensic reports

`textforensics report` currently records:
- SHA-256 of analyzed content,
- detector observations,
- detector family metadata,
- benign-normalization probes,
- consensus/integrity diagnostics,
- optional provenance-ledger verification,
- limitations.

The current `Verdict Integrity` A–D/INSUFFICIENT grade is an **alpha engineering heuristic with hand-designed weights**. It is not a probability, not a validated reliability estimate, and not the project's long-term trust model. The roadmap replaces it with the benchmark-backed qualitative Trust Map.

### Local provenance

`textforensics snapshot` appends document hashes to a chained local ledger. It can support a record of draft evolution, but a local ledger is not an independent trusted timestamp and process provenance remains separate from text detection.

### Interfaces

The same project can be used through:
- Python,
- CLI,
- local browser UI,
- optional MCP server,
- optional localhost HTTP API.

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

Open the local browser interface:

```bash
textforensics web
```

By default it binds locally. The built-in detector runs on the same machine.

Build a forensic report:

```bash
textforensics report --file essay.txt --output report.json
```

Inspect installed detectors:

```bash
textforensics detectors
```

Basic pattern scan:

```bash
textforensics scan --file essay.txt
```

Locate heterogeneous regions:

```bash
textforensics localize --file paper.txt --sentences 4
```

Audit formulaic writing:

```bash
textforensics audit --file draft.txt
```

The audit provides transparent writing observations. It does not silently rewrite the document or guarantee any detector result.

Compare versions:

```bash
textforensics compare draft-v1.txt draft-v2.txt --json
```

Preserve draft-history evidence:

```bash
textforensics snapshot draft.txt
# edit the file
textforensics snapshot draft.txt
textforensics verify-ledger
```

## Detector plugins

Third-party packages can register detectors through Python entry points:

```toml
[project.entry-points."textforensics.detectors"]
my_detector = "my_package:MyDetector"
```

A serious adapter should expose explicit version/score semantics and eventually satisfy the benchmark/calibration gates in [AGENTS.md](AGENTS.md).

The planned detector set prioritizes **methodological diversity**, for example:
- supervised open classifier,
- likelihood/cross-model method,
- transparent structural/stylometric baseline,
- provenance/watermark evidence when actually available,
- user-enabled official provider APIs.

Several correlated variants of one classifier family should not create artificial confidence.

## Benchmarking

The existing commands are exploratory alpha scaffolding:

```bash
textforensics benchmark data.jsonl --threshold 0.50
textforensics calibrate data.jsonl --target-fpr 0.01
```

Do **not** interpret the current `calibrate` command as a complete scientific validation pipeline: threshold fitting and final held-out evaluation must be separated before release-quality claims are made.

The planned benchmark substrate targets RAID, DetectRL and M4 with versioned run manifests, human-FPR-first operating points, calibration metrics, confidence intervals and domain/language/length/revision slices.

## MCP

```bash
pip install -e ".[mcp]"
textforensics-mcp
```

The MCP surface is an integration mechanism, not the project's novelty. It should expose structured evidence and limitations from the same core used by the CLI/API.

## HTTP API

```bash
pip install -e ".[api]"
uvicorn textforensics.api:app --host 127.0.0.1 --port 8765
```

## The capability TextForensics is building toward

### Trust Map

For the current analysis, show whether evidence is:
- **supported**
- **partial**
- **unknown**
- **out_of_scope**

across:
- language,
- length,
- domain,
- revision/editing regime,
- nearest human false-positive evidence,
- detector diversity/disagreement,
- benign stability,
- temporal/provider-version stability.

No fake 0–100 trust score is planned until such an aggregation can be empirically validated.

### Detector observatory

Run a stable probe corpus against versioned detectors/providers over time and surface:
- score-distribution drift,
- verdict flips,
- calibration/FPR regressions,
- model/provider version changes.

### Reproducible case files

Export what was observed, the input hash, exact detector/calibration versions, Trust Map, applicable benchmark evidence, stability/drift and optional process provenance. Raw text should be omitted by default.

## What TextForensics will not claim

- A detector score proves authorship.
- A clean detector result proves human authorship.
- Raw scores from different detectors are automatically comparable.
- A locally calibrated component probability automatically makes an ensemble calibrated.
- The current heuristic baseline is state of the art.
- The current integrity grade is a validated trust score.
- Text-only evidence should be the sole basis for high-stakes punishment.
- Rewriting can guarantee a particular detector outcome.

## Development

```bash
python -m unittest discover -s tests -v
```

Contributors and coding agents should read [AGENTS.md](AGENTS.md) first.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
