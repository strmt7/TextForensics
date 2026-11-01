# TextForensics Fuzz Testing

This directory contains fuzz testing infrastructure for TextForensics using [atheris](https://github.com/google/atheris), Google's coverage-guided Python fuzzer.

## Directory Structure

```
tests/fuzz/
├── __init__.py              # Package marker
├── fuzz_json_parsing.py     # JSON parsing fuzz targets (api, casefile, benchmark)
├── fuzz_text_input_validation.py  # Text input validation fuzz targets (config, cli)
├── fuzz_detector_input.py   # Detector input handling fuzz targets
├── fuzz_ledger_parsing.py   # Ledger parsing fuzz targets (provenance)
├── fuzz_schema_validation.py  # Schema validation fuzz targets
├── fuzz_trust_map.py        # Trust map computation fuzz targets
├── run_fuzz.py              # Main fuzz test runner
├── generate_corpus.py       # Corpus generation from test data
└── test_fuzz_pytest.py      # Pytest-compatible wrapper tests
```

## Running Fuzz Tests Locally

### Using the runner script:

```bash
# Run all targets for 5 minutes each
python -m tests.fuzz.run_fuzz --duration-minutes 5

# Run a specific target
python -m tests.fuzz.run_fuzz --target json_parsing_api --duration-minutes 10

# Run with existing corpus
python -m tests.fuzz.run_fuzz --corpus-dir ./corpus --artifacts-dir ./artifacts
```

### Using pytest wrappers:

```bash
# Run all fuzz test classes
pytest tests/fuzz/test_fuzz_pytest.py -v

# Run specific test class
pytest tests/fuzz/test_fuzz_pytest.py::TestJsonParsingApi -v
```

### Using atheris directly:

```bash
# Run individual fuzz targets
python tests/fuzz/fuzz_json_parsing.py -runs=0 -max_total_time=300
```

## Fuzzing Targets

| Target | Module | Functions |
|--------|--------|-----------|
| `json_parsing_api` | `fuzz_json_parsing.py` | TextRequest, CompareRequest parsing |
| `json_parsing_casefile` | `fuzz_json_parsing.py` | Case file verification, sealing |
| `json_parsing_benchmark` | `fuzz_json_parsing.py` | JSONL score loading |
| `text_input_validation_config` | `fuzz_text_input_validation.py` | `validate_text_input`, `Settings` |
| `text_input_validation_cli` | `fuzz_text_input_validation.py` | CLI argument parsing |
| `detector_input_handling` | `fuzz_detector_input.py` | Detector execution, prediction validation |
| `ledger_parsing_provenance` | `fuzz_ledger_parsing.py` | Ledger verification, snapshotting |
| `schema_validation` | `fuzz_schema_validation.py` | Schema loading, validation |
| `trust_map_computation` | `fuzz_trust_map.py` | Trust map building, dimension calculation |

## Initial Corpus Generation

Generate initial corpus from existing test data:

```bash
python -m tests.fuzz.generate_corpus --output-dir ./corpus
```

This creates:
- `corpus/json_parsing/` - JSON parsing samples
- `corpus/text_input/` - Text input samples
- `corpus/detector_input/` - Detector test inputs/outputs
- `corpus/ledger_parsing/` - Ledger samples
- `corpus/schema_validation/` - Schema validation samples
- `corpus/trust_map/` - Trust map computation samples

## CI Integration

The main workflow is defined in `.github/workflows/fuzz.yml`:

- Runs on push to `main` (filtered by `src/**` and `tests/**` paths)
- Weekly scheduled runs (Sundays at 03:00 UTC)
- Fuzzes for 5 minutes per target per Python version
- Tests on Python 3.11, 3.12, and 3.13
- Uploads crash artifacts and corpus with 30-day retention

## Artifacts

After each run, the following artifacts are uploaded:

1. **Crash artifacts** (`fuzz-crashes-*-*/crashes/`) - Contains any inputs that caused crashes
2. **Fuzz corpus** (`fuzz-corpus-*-*/corpus/`) - Corpus used during fuzzing
3. **Coverage data** (`fuzz-coverage-*-*/coverage/`) - Coverage information

## What to Look For

The fuzz tests are designed to find:

- Parser crashes (JSON, casefile, ledger)
- Detector crashes on malformed input
- Unicode handling bugs (surrogates, invalid encodings, etc.)
- Memory exhaustion with large inputs
- Infinite loops or long-running code paths
- Schema validation errors
- Trust map computation edge cases

## Writing New Fuzz Targets

Add a new fuzz target by:

1. Create `tests/fuzz/fuzz_<name>.py`
2. Implement `TestOneInput(data: bytes)` function
3. Add to `FUZZ_TARGETS` in `tests/fuzz/run_fuzz.py`
4. Add to the workflow matrix in `.github/workflows/fuzz.yml`

### Example fuzz target skeleton:

```python
#!/usr/bin/env python3
import atheris
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

def TestOneInput(data: bytes) -> None:
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return

    # Your fuzzing logic here
    try:
        from textforensics.module import function
        function(text)
    except Exception:
        pass  # Expected for fuzzing

def main():
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

## Resources

- [Atheris Documentation](https://github.com/google/atheris)
- [Python Fuzzing Tutorial](https://google.github.io/atheris/tutorial.html)
- [OSS-Fuzz Integration](https://google.github.io/atheris/oss-fuzz.html)