#!/usr/bin/env python3
"""
Generate initial fuzz corpus from existing test data.
This script extracts realistic inputs from test files to seed the fuzzer.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from textforensics.casefile import seal_case_file
from textforensics.detectors import BuiltinHeuristicDetector
from textforensics.engine import analyze_text
from textforensics.provenance import snapshot_file
from textforensics.report import build_forensic_bundle
from textforensics.trust import build_trust_map


def generate_json_corpus(output_dir: Path) -> None:
    """Generate JSON corpus for API, casefile, and benchmark parsing."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Valid JSON samples
    valid_samples = [
        {"text": "This is a simple test text for fuzzing."},
        {"text": "Another sample with different content."},
        {"before": "Original text.", "after": "Modified text."},
        {"label": "human", "text": "Human written text sample."},
        {"label": "ai", "text": "AI generated text sample."},
        {"schema": "textforensics.case-file/v1", "tool": {"name": "TextForensics", "version": "0.1.0"}},
        {"detector_id": "test", "detector_version": "1.0", "detector_family": "test", "execution": "local"},
    ]

    # Edge case JSON samples
    edge_samples = [
        {"text": ""},
        {"text": "x" * 10000},
        {"text": "🚀 Unicode test 🌟"},
        {"text": "\x00\x01\x02\x03"},
        {"text": "A" * 2_000_000},
        {"nested": {"deep": {"structure": {"with": "values"}}}},
        {"array": [1, 2, 3, "test", {"key": "value"}]},
        {"null_value": None},
        {"number": 42, "float": 3.14, "negative": -100},
        {"bool_true": True, "bool_false": False},
    ]

    # Malformed JSON (will be written as raw bytes for atheris)
    malformed_samples = [
        b'{ "text": "unclosed quote }',
        b'{ "text": "trailing comma", }',
        b'{ "duplicate": "key", "duplicate": "value" }',
        b'{ "invalid": \x80 }',  # Invalid UTF-8
        b'not json at all',
        b'{ "text": "very long ' + b'x' * 100000 + b'" }',
        b'{ "text": "\\uD800" }',  # Lone surrogate
        b'{ "text": "test", "extra": }',  # Missing value
        b'[1, 2, 3,]',  # Trailing comma in array
        b'{ "text": "test" "missing_comma": "value" }',
    ]

    for i, sample in enumerate(valid_samples):
        (output_dir / f"valid_{i:03d}.json").write_bytes(json.dumps(sample, ensure_ascii=False).encode("utf-8"))

    for i, sample in enumerate(edge_samples):
        (output_dir / f"edge_{i:03d}.json").write_bytes(json.dumps(sample, ensure_ascii=False).encode("utf-8"))

    for i, sample in enumerate(malformed_samples):
        (output_dir / f"malformed_{i:03d}.json").write_bytes(sample)


def generate_text_corpus(output_dir: Path) -> None:
    """Generate text input corpus for validation fuzzing."""
    output_dir.mkdir(parents=True, exist_ok=True)

    text_samples = [
        "Short text.",
        "This is a normal sentence for testing purposes.",
        "A" * 100,
        "A" * 1000,
        "A" * 10000,
        "Unicode: 🚀 🌟 🎉 💯",
        "Mixed: Hello 世界 🌍",
        "Special chars: \t\n\r\x00\x01\x02",
        "Very long text. " * 1000,
        "Text with\nmultiple\nlines\nand\ttabs.",
        "Path-like: /home/user/file.txt or C:\\Windows\\System32",
        "SQL-like: SELECT * FROM users WHERE id = 1;",
        "JSON-like: {\"key\": \"value\"}",
        "XML-like: <tag>content</tag>",
        "Email: user@example.com",
        "URL: https://example.com/path?query=value",
        "Numbers: 123 45.67 -89 0xFF",
        "Symbols: !@#$%^&*()_+-=[]{}|;':\",./<>?",
    ]

    for i, text in enumerate(text_samples):
        (output_dir / f"text_{i:03d}.txt").write_text(text, encoding="utf-8")


def generate_detector_corpus(output_dir: Path) -> None:
    """Generate corpus for detector input handling."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Use the builtin detector to generate realistic predictions
    detector = BuiltinHeuristicDetector()

    test_texts = [
        "This is a simple human-written text for testing the detector.",
        "The quick brown fox jumps over the lazy dog repeatedly.",
        "AI-generated text tends to have certain statistical patterns that detectors can identify.",
        "Short.",
        "A" * 5000,
        "🚀 " * 100,
        "\x00\x01\x02" + "normal text",
        "Text with\nmany\nlines\n" * 50,
    ]

    for i, text in enumerate(test_texts):
        (output_dir / f"detector_input_{i:03d}.txt").write_text(text, encoding="utf-8")

        # Also save the prediction as a reference
        try:
            prediction = detector.detect(text)
            (output_dir / f"detector_output_{i:03d}.json").write_text(
                json.dumps(prediction.to_dict(), indent=2, ensure_ascii=False)
            )
        except Exception:
            pass  # Some inputs may cause errors, which is what we want to find


def generate_ledger_corpus(output_dir: Path) -> None:
    """Generate corpus for ledger parsing."""
    output_dir.mkdir(parents=True, exist_ok=True)

    import tempfile

    # Create a valid ledger
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        ledger_path = tmpdir / "test_ledger.jsonl"
        test_file = tmpdir / "test.txt"
        test_file.write_text("Test content for ledger snapshot.")

        try:
            record = snapshot_file(test_file, ledger_path)
            (output_dir / "valid_ledger.jsonl").write_text(
                json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except Exception:
            pass

    # Valid ledger lines
    valid_ledger_lines = [
        '{"schema": "textforensics-ledger/v1", "timestamp_utc": "2024-01-01T00:00:00+00:00", "file_name": "test.txt", "file_size": 100, "file_sha256": "a' + "0" * 63 + '", "previous_record_sha256": null, "record_sha256": "b' + "0" * 63 + '"}',
        '{"schema": "textforensics-ledger/v1", "timestamp_utc": "2024-01-01T00:00:01+00:00", "file_name": "test2.txt", "file_size": 200, "file_sha256": "c' + "0" * 63 + '", "previous_record_sha256": "b' + "0" * 63 + '", "record_sha256": "d' + "0" * 63 + '"}',
    ]

    for i, line in enumerate(valid_ledger_lines):
        (output_dir / f"ledger_valid_{i:03d}.jsonl").write_text(line + "\n", encoding="utf-8")

    # Malformed ledger lines
    malformed_ledger_lines = [
        'not json',
        '{"schema": "textforensics-ledger/v1"}',  # Missing required fields
        '{"schema": "wrong-schema", "timestamp_utc": "2024-01-01T00:00:00+00:00", "file_name": "test.txt", "file_size": 100, "file_sha256": "a' + "0" * 63 + '", "previous_record_sha256": null, "record_sha256": "b' + "0" * 63 + '"}',
        '{"schema": "textforensics-ledger/v1", "timestamp_utc": "invalid-date", "file_name": "test.txt", "file_size": 100, "file_sha256": "a' + "0" * 63 + '", "previous_record_sha256": null, "record_sha256": "b' + "0" * 63 + '"}',
        '{"schema": "textforensics-ledger/v1", "timestamp_utc": "2024-01-01T00:00:00+00:00", "file_name": "test.txt", "file_size": "not_a_number", "file_sha256": "a' + "0" * 63 + '", "previous_record_sha256": null, "record_sha256": "b' + "0" * 63 + '"}',
        '{"schema": "textforensics-ledger/v1", "timestamp_utc": "2024-01-01T00:00:00+00:00", "file_name": "test.txt", "file_size": 100, "file_sha256": "invalid_hash", "previous_record_sha256": null, "record_sha256": "b' + "0" * 63 + '"}',
    ]

    for i, line in enumerate(malformed_ledger_lines):
        (output_dir / f"ledger_malformed_{i:03d}.jsonl").write_text(line + "\n", encoding="utf-8")


def generate_schema_corpus(output_dir: Path) -> None:
    """Generate corpus for schema validation."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Valid schema instances
    valid_schemas = [
        {
            "schema": "textforensics.detector-result/v1",
            "detector_id": "test/detector",
            "detector_version": "1.0.0",
            "detector_family": "test",
            "execution": "local",
            "score": 0.5,
            "score_semantics": "higher means more AI-like",
            "verdict": "ai_like",
            "threshold": 0.5,
            "supported_languages": ["en"],
            "evidence": [],
            "warnings": [],
        },
        {
            "schema": "textforensics.forensic-bundle/v1",
            "content_sha256": "a" * 64,
            "input": {"raw_text_included": False, "word_count": 100},
            "detectors": [],
            "trust_map": {"schema": "textforensics.trust-map/v1", "overall": "mixed", "dimensions": []},
        },
        {
            "schema": "textforensics.case-file/v1",
            "tool": {"name": "TextForensics", "version": "0.1.0"},
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v1",
                "content_sha256": "a" * 64,
                "input": {"raw_text_included": False, "word_count": 100},
                "detectors": [],
                "trust_map": {"schema": "textforensics.trust-map/v1", "overall": "mixed", "dimensions": []},
            },
            "raw_text_included": False,
            "case_sha256": "b" * 64,
        },
    ]

    for i, schema in enumerate(valid_schemas):
        (output_dir / f"schema_valid_{i:03d}.json").write_text(
            json.dumps(schema, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # Invalid schema instances
    invalid_schemas = [
        {"schema": "unknown-schema/v1"},
        {"schema": "textforensics.detector-result/v1", "detector_id": ""},  # Empty required field
        {"schema": "textforensics.detector-result/v1", "detector_id": "test", "detector_version": "1.0", "detector_family": "test", "execution": "invalid", "score": 0.5, "score_semantics": "test", "verdict": "ai_like"},  # Invalid execution
        {"schema": "textforensics.detector-result/v1", "detector_id": "test", "detector_version": "1.0", "detector_family": "test", "execution": "local", "score": "not_a_number", "score_semantics": "test", "verdict": "ai_like"},  # Invalid score
        {"schema": "textforensics.forensic-bundle/v1", "content_sha256": "invalid"},  # Invalid hash
        {"schema": "textforensics.case-file/v1", "raw_text_included": True},  # Forbidden
    ]

    for i, schema in enumerate(invalid_schemas):
        (output_dir / f"schema_invalid_{i:03d}.json").write_text(
            json.dumps(schema, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def generate_trust_corpus(output_dir: Path) -> None:
    """Generate corpus for trust map computation."""
    output_dir.mkdir(parents=True, exist_ok=True)

    from textforensics.detectors import DetectorPrediction

    # Valid predictions for trust map
    predictions = [
        DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test/detector1",
            detector_version="1.0.0",
            detector_family="family1",
            execution="local",
            score=0.7,
            score_semantics="higher means more AI-like",
            verdict="ai_like",
            threshold=0.5,
            supported_languages=["en"],
            min_words=50,
            evidence=[],
            warnings=[],
        ),
        DetectorPrediction(
            schema="textforensics.detector-result/v1",
            detector_id="test/detector2",
            detector_version="1.0.0",
            detector_family="family2",
            execution="local",
            score=0.3,
            score_semantics="higher means more AI-like",
            verdict="human_like",
            threshold=0.5,
            supported_languages=["en"],
            min_words=100,
            evidence=[],
            warnings=[],
        ),
    ]

    robustness_data = [
        {"detector_id": "test/detector1", "verdict_stability": 1.0, "native_score_range": [0.65, 0.75]},
        {"detector_id": "test/detector2", "verdict_stability": 1.0, "native_score_range": [0.25, 0.35]},
    ]

    test_cases = [
        {"predictions": predictions, "word_count": 200, "robustness": robustness_data, "failure_count": 0},
        {"predictions": [predictions[0]], "word_count": 30, "robustness": [], "failure_count": 0},
        {"predictions": [], "word_count": 1000, "robustness": [], "failure_count": 1},
        {"predictions": predictions, "word_count": 50, "robustness": robustness_data, "failure_count": 0},
    ]

    for i, case in enumerate(test_cases):
        # Convert predictions to dict for serialization
        case_copy = {
            "predictions": [p.to_dict() for p in case["predictions"]],
            "word_count": case["word_count"],
            "robustness": case["robustness"],
            "failure_count": case["failure_count"],
        }
        (output_dir / f"trust_input_{i:03d}.json").write_text(
            json.dumps(case_copy, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def main():
    parser = argparse.ArgumentParser(description="Generate initial fuzz corpus from test data")
    parser.add_argument("--output-dir", type=Path, default=Path("corpus"), help="Output directory for corpus")
    args = parser.parse_args()

    print(f"Generating corpus in {args.output_dir}")

    generate_json_corpus(args.output_dir / "json_parsing")
    generate_text_corpus(args.output_dir / "text_input")
    generate_detector_corpus(args.output_dir / "detector_input")
    generate_ledger_corpus(args.output_dir / "ledger_parsing")
    generate_schema_corpus(args.output_dir / "schema_validation")
    generate_trust_corpus(args.output_dir / "trust_map")

    print("Corpus generation complete!")


if __name__ == "__main__":
    main()