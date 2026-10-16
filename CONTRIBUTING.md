# Contributing

Contributions are welcome, especially detector adapters, calibration/benchmark infrastructure, false-positive analyses, Trust Map evidence, drift monitoring and reproducibility work.

## Read first

Before changing architecture or score semantics, read:
- [AGENTS.md](AGENTS.md) — hard development contract
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [docs/PRODUCT.md](docs/PRODUCT.md)
- [docs/BENCHMARKING.md](docs/BENCHMARKING.md)
- [docs/QUALITY_GATES.md](docs/QUALITY_GATES.md)

## Ground rules

- Every detector adapter states its model/version/family, license, supported regime and network behavior.
- Raw detector scores are not called probabilities unless calibrated.
- Detector-local calibration is not ensemble calibration.
- Benchmark claims include dataset/split identity, sample count, threshold policy and human false-positive rate.
- Final evaluation remains disjoint from threshold selection and calibration.
- Unsupported inputs preserve abstention/limitations.
- New analyzers/adapters include tests and documented failure modes.
- Core remains local-first; remote calls require explicit configuration.
- Do not put private raw text into logs or portable case files by default.
- Avoid adding correlated detectors solely to inflate detector count.
- Do not publish synthetic/demo fixture results as product accuracy.

## Development

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -e .[dev]
python -m unittest discover -s tests -v
```

Before a PR, work through the applicable checks in [docs/QUALITY_GATES.md](docs/QUALITY_GATES.md).

## Detector PRs

A detector adapter should include:
- stable detector ID/version/family,
- native score semantics,
- model/checkpoint/provider identity,
- dependency and hardware requirements,
- language/length/domain limitations,
- structured timeout/error behavior,
- license notes,
- tests,
- benchmark manifest/results before it becomes eligible for calibrated fusion.

A detector can land experimentally before full validation if it is unmistakably marked experimental and cannot silently influence calibrated top-level outputs.

## Performance claims

Do not add README accuracy claims from external papers. Run TextForensics against the declared benchmark and archive the run provenance first.
