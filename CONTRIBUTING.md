# Contributing

Contributions are welcome, especially detector adapters, calibration datasets, reproducible benchmarks, and false-positive analyses.

## Ground rules

- Every detector adapter must state its model/version and licensing requirements.
- Benchmark claims must include the dataset, sample count, threshold policy and false-positive rate.
- Do not describe a probabilistic score as proof of authorship.
- New analyzers need tests and a short explanation of their failure modes.

## Development

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -e .[dev]
python -m unittest discover -s tests -v
```
