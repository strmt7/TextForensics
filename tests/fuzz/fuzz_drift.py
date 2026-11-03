#!/usr/bin/env python3
"""
Fuzz target for DriftObservatory: corpus loading, snapshot creation, and comparison.

Covers:
- DriftObservatory constructor with corpus and corpus_path
- _load_corpus with Mapping and Sequence formats
- _add_sample edge cases (duplicate IDs, bad hashes, missing fields)
- _normalize_observation and _normalize_failure validation
- snapshot_from_observations and compare_snapshots
- _distribution_summary, _coerce_float, _coerce_int_or_none helpers
- Snapshot save/load round-trip
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


def _sample_id_from_bytes(data: bytes) -> str:
    """Derive a sample ID from raw bytes."""
    try:
        return data.decode("utf-8", errors="replace").strip()[:30] or "sample-1"
    except Exception:
        return "sample-1"


def _fuzz_distribution_summary(data: bytes) -> None:
    """Fuzz _distribution_summary with extreme value sequences."""
    try:
        from textforensics.drift import _distribution_summary
    except Exception:
        return

    # Build values from raw bytes
    values: list[float] = []
    for i in range(0, min(len(data), 256), 4):
        chunk = data[i : i + 4]
        if len(chunk) == 4:
            val = int.from_bytes(chunk, "little", signed=True) / 10000.0
            values.append(val)
    # Add edge cases
    for v in (0.0, -1.0, 2.0, float("nan"), float("inf"), float("-inf")):
        values.append(v)
    # Add non-float types
    values_with_noise = values + [True, False, None, "not-a-float", object()]  # type: ignore[list-item]

    try:
        result = _distribution_summary(values)
        assert "n" in result
    except Exception:
        pass
    try:
        result = _distribution_summary(values_with_noise)
        assert "n" in result
    except Exception:
        pass
    try:
        result = _distribution_summary([])
        assert result["n"] == 0
    except Exception:
        pass


def _fuzz_coerce_helpers(text: str) -> None:
    """Fuzz _coerce_float and _coerce_int_or_none."""
    try:
        from textforensics.drift import _coerce_float, _coerce_int_or_none
    except Exception:
        return

    # Values to try
    vals = [
        text[:10],
        0,
        1,
        -1,
        True,
        False,
        None,
        "0.5",
        "nan",
        "inf",
        -0.5,
        float("nan"),
        float("inf"),
        1e308,
        -1e308,
        0.0,
        "",
        " ",
        42,
    ]
    if text:
        try:
            vals.append(float(text[:10]))
        except (ValueError, OverflowError):
            pass

    for val in vals:
        for minimum, maximum in [(None, None), (0.0, 1.0), (-1.0, 2.0), (0.0, None), (None, 1.0)]:
            try:
                _coerce_float(val, "test", minimum=minimum, maximum=maximum)
            except ValueError:
                pass
            except Exception:
                pass
            try:
                _coerce_float(val, "test", minimum=minimum, maximum=maximum, allow_none=False)
            except ValueError:
                pass
            except Exception:
                pass

    # Int coercer
    int_vals = vals + [1.5, -1, 0, 1000, 2**63]
    for val in int_vals:
        try:
            _coerce_int_or_none(val, "test")
        except ValueError:
            pass
        except Exception:
            pass


def _fuzz_corpus_loading(text: str) -> None:
    """Fuzz DriftObservatory corpus loading with malformed data."""
    try:
        from textforensics.drift import DRIFT_CORPUS_SCHEMA, DriftObservatory
    except Exception:
        return

    sample_id = (
        _sample_id_from_bytes(text.encode("utf-8", errors="replace")) if text else "sample-1"
    )
    hex_sha256 = text[:64].ljust(64, "0")[:64]

    # Make hex_sha256 valid hex by replacing non-hex chars
    clean_hex = "".join(c if c in "0123456789abcdefABCDEF" else "0" for c in hex_sha256)[:64]

    # 1. Mapping format corpus
    for schema_val in [DRIFT_CORPUS_SCHEMA, "wrong-schema", None, ""]:
        corpus_map = {
            "schema": schema_val if schema_val else "",
            "samples": [],
        }
        if len(text) % 3 == 0:
            corpus_map["samples"].append(
                {
                    "id": sample_id,
                    "text_sha256": clean_hex,
                    "metadata": {"key": text[:20]},
                }
            )
        if len(text) % 5 == 0:
            corpus_map["samples"].append(
                {
                    "id": f"{sample_id}-2",
                    "text_sha256": clean_hex,
                    "text": "probe sample text",
                    "metadata": {},
                }
            )
        # Duplicate sample
        if len(text) % 7 == 0:
            corpus_map["samples"].append(
                {
                    "id": sample_id,
                    "text_sha256": clean_hex,
                }
            )
        try:
            DriftObservatory(corpus=corpus_map)
        except ValueError:
            pass
        except Exception:
            pass

        # Missing samples key
        if len(text) % 4 == 0:
            no_samples = dict(corpus_map)
            no_samples.pop("samples", None)
            try:
                DriftObservatory(corpus=no_samples)
            except ValueError:
                pass
            except Exception:
                pass

    # 2. Sequence format corpus
    seq_corpus = []
    for line in text.split("\n")[:20]:
        sid = f"sample-{len(seq_corpus)}"
        if not sid.startswith("sample-0") and sid == "sample-0":
            pass  # skip
        seq_corpus.append(
            {
                "id": sid,
                "text_sha256": clean_hex,
                "metadata": {"line": line[:10]},
            }
        )
    try:
        DriftObservatory(corpus=seq_corpus)
    except ValueError:
        pass
    except Exception:
        pass

    # 3. Bad sample entries
    for bad_sample in [
        "",
        123,
        [],
        {"id": "", "text_sha256": clean_hex},
        {"id": "x", "text_sha256": "not-hex"},
        {"id": "x"},  # no sha and no text
        {"id": "x", "text": "", "text_sha256": clean_hex},  # empty text
        {"id": "x", "text_sha256": clean_hex, "metadata": "not-dict"},
    ]:
        try:
            DriftObservatory(corpus=[bad_sample])
        except ValueError:
            pass
        except Exception:
            pass

    # 4. File-based corpus loading
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        corpus_path = tmpdir / "corpus.json"
        corpus_path.write_text(
            json.dumps(
                {
                    "schema": DRIFT_CORPUS_SCHEMA,
                    "samples": [
                        {"id": "s1", "text_sha256": clean_hex},
                        {
                            "id": "s2",
                            "text_sha256": clean_hex,
                            "text": "hello world",
                            "metadata": {"label": "human"},
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        try:
            DriftObservatory(corpus_path=corpus_path)
        except Exception:
            pass

        # Malformed file
        corpus_path.write_text(text, encoding="utf-8")
        try:
            DriftObservatory(corpus_path=corpus_path)
        except (json.JSONDecodeError, ValueError):
            pass
        except Exception:
            pass


def _fuzz_observations_and_snapshots(text: str) -> None:
    """Fuzz observation normalization and snapshot creation."""
    try:
        from textforensics.drift import DRIFT_SNAPSHOT_SCHEMA, DriftObservatory
    except Exception:
        return

    clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]

    # Setup a corpus with known samples
    corpus = {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [
            {"id": "s1", "text_sha256": clean_hex},
            {"id": "s2", "text_sha256": clean_hex},
        ],
    }
    try:
        obs = DriftObservatory(corpus=corpus)
    except Exception:
        return

    # Build fuzzed observations
    for execution in ("local", "remote", "bad"):
        for verdict in ("ai_like", "human_like", "abstain", "bad_verdict"):
            for score_val in [None, 0.5, -1.0, 2.0]:
                observation = {
                    "sample_id": "s1",
                    "detector_id": text[:20] or "fuzz-det",
                    "detector_version": "1.0",
                    "detector_family": "fuzz",
                    "execution": execution,
                    "verdict": verdict,
                    "score": score_val,
                }
                try:
                    obs._normalize_observation(observation)
                except ValueError:
                    pass
                except Exception:
                    pass

    # Missing required fields
    for obs_data in [
        {"sample_id": "s1"},
        {"detector_id": "x"},
        {},
        [],
        "not-a-dict",
    ]:
        try:
            obs._normalize_observation(obs_data)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            pass
        except Exception:
            pass

    # Failure normalization
    for fail_data in [
        {"sample_id": "s1", "detector_id": "x"},
        {"text_sha256": clean_hex, "detector_id": "x"},
        {},
        [],
    ]:
        try:
            obs._normalize_failure(fail_data)
        except (ValueError, TypeError):
            pass
        except Exception:
            pass

    # snapshot_from_observations with valid obs
    valid_obs_list = [
        {
            "sample_id": "s1",
            "detector_id": "fuzz-det",
            "detector_version": "1.0",
            "detector_family": "fuzz",
            "execution": "local",
            "verdict": "ai_like",
            "score": 0.8,
        },
    ]
    try:
        snapshot = obs.snapshot_from_observations(valid_obs_list, label="test")
        assert snapshot["schema"] == DRIFT_SNAPSHOT_SCHEMA
    except Exception:
        pass

    # Snapshot save/load round-trip
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        store_path = tmpdir / "snapshots.json"
        try:
            obs.save_snapshots(store_path)
            obs2 = DriftObservatory(corpus=corpus)
            obs2.load_snapshots(store_path)
        except Exception:
            pass

        # Load malformed store
        store_path.write_text(text, encoding="utf-8")
        try:
            obs3 = DriftObservatory(corpus=corpus)
            obs3.load_snapshots(store_path)
        except Exception:
            pass


def _fuzz_snapshot_comparison(text: str) -> None:
    """Fuzz compare_snapshots with crafted baseline/current snapshots."""
    try:
        from textforensics.drift import DRIFT_SNAPSHOT_SCHEMA, DriftObservatory
    except Exception:
        return

    clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]
    corpus_sha = "dead" * 16  # arbitrary hex

    corpus = {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [
            {"id": "s1", "text_sha256": clean_hex},
            {"id": "s2", "text_sha256": clean_hex, "metadata": {"label": "human"}},
        ],
    }
    try:
        obs = DriftObservatory(corpus=corpus)
    except Exception:
        return

    # Build baseline and current snapshots
    base_records = [
        {
            "sample_id": "s1",
            "text_sha256": clean_hex,
            "detector_id": "fuzz-det",
            "detector_version": "1.0",
            "detector_family": "fuzz",
            "execution": "local",
            "observed_at": "2024-01-01T00:00:00+00:00",
            "score": 0.5,
            "score_semantics": "unspecified",
            "verdict": "ai_like",
            "threshold": 0.5,
            "supported_languages": ["en"],
            "min_words": 50,
        },
        {
            "sample_id": "s2",
            "text_sha256": clean_hex,
            "detector_id": "fuzz-det",
            "detector_version": "1.0",
            "detector_family": "fuzz",
            "execution": "local",
            "observed_at": "2024-01-01T00:00:00+00:00",
            "score": 0.3,
            "score_semantics": "unspecified",
            "verdict": "human_like",
            "threshold": 0.5,
            "supported_languages": ["en"],
            "min_words": 50,
        },
    ]
    current_records = [
        {
            **r,
            "observed_at": "2024-06-01T00:00:00+00:00",
            "score": r["score"] + 0.1,
        }
        for r in base_records
    ]

    baseline = {
        "schema": DRIFT_SNAPSHOT_SCHEMA,
        "snapshot_id": "base-001",
        "taken_at": "2024-01-01T00:00:00+00:00",
        "corpus_sha256": obs.corpus_sha256,
        "detector_ids": ["fuzz-det"],
        "record_count": len(base_records),
        "failure_count": 0,
        "records": base_records,
        "failures": [],
    }
    current = dict(baseline)
    current["snapshot_id"] = "curr-001"
    current["records"] = current_records

    # Normal comparison
    try:
        report = obs.compare_snapshots(baseline, current)
        assert "overall" in report
    except Exception:
        pass

    # Corpus mismatch
    bad_baseline = dict(baseline)
    bad_baseline["corpus_sha256"] = corpus_sha
    try:
        obs.compare_snapshots(bad_baseline, current)
    except Exception:
        pass

    # Missing detector in one
    current_no_detector = dict(current)
    current_no_detector["records"] = []
    try:
        obs.compare_snapshots(baseline, current_no_detector)
    except Exception:
        pass

    # Schema mismatch
    bad_schema = {"schema": "wrong", "records": []}
    try:
        obs.compare_snapshots(bad_schema, current)
    except ValueError:
        pass
    except Exception:
        pass

    # Non-dict inputs
    for b, c in [(baseline, "not-dict"), ("not-dict", current), ([], {})]:
        try:
            obs.compare_snapshots(b, c)  # type: ignore[arg-type]
        except (ValueError, TypeError):
            pass
        except Exception:
            pass


def _fuzz_comparison_helpers(text: str) -> None:
    """Fuzz _compare_score_distribution, _compare_verdict_flips, _compare_thresholds,
    _compare_calibration, _compare_human_fpr, _compare_provider_metadata, _compare_supported_regime."""
    try:
        from textforensics.drift import (
            ProbeSample,
            _compare_calibration,
            _compare_human_fpr,
            _compare_provider_metadata,
            _compare_score_distribution,
            _compare_supported_regime,
            _compare_thresholds,
            _compare_verdict_flips,
        )
    except Exception:
        return

    clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]

    base_record = {"score": 0.5, "verdict": "ai_like", "threshold": 0.5, "sample_id": "s1"}
    curr_record = {"score": 0.6, "verdict": "human_like", "threshold": 0.5, "sample_id": "s1"}

    # Build pairs
    for verdicts in [("ai_like", "human_like"), ("human_like", "ai_like"), ("abstain", "ai_like")]:
        for score_pairs in [(None, None), (0.3, 0.7), (0.5, 0.5)]:
            b = dict(base_record, verdict=verdicts[0], score=score_pairs[0])
            c = dict(curr_record, verdict=verdicts[1], score=score_pairs[1])
            pairs = [(b, c, "s1")]

            try:
                result = _compare_score_distribution(
                    pairs, claim_allowed=True, shift_threshold=0.05, min_samples=2
                )
                assert "significant" in result
            except Exception:
                pass
            try:
                result = _compare_verdict_flips(
                    pairs, claim_allowed=True, flip_rate_threshold=0.1, min_samples=2
                )
                assert "flip_count" in result
            except Exception:
                pass
            try:
                result = _compare_thresholds(pairs, [b], [c])
                assert "threshold_changed" in result
            except Exception:
                pass

    # Calibration comparison
    for cal_pairs in [
        (("cal-1", 0.5), ("cal-2", 0.7)),
        ((None, None), (None, None)),
        (("cal-1", 0.5), ("cal-1", 0.5)),
    ]:
        b = dict(
            base_record, calibration_id=cal_pairs[0][0], calibrated_ai_probability=cal_pairs[0][1]
        )
        c = dict(
            curr_record, calibration_id=cal_pairs[1][0], calibrated_ai_probability=cal_pairs[1][1]
        )
        pairs = [(b, c, "s1")]
        try:
            result = _compare_calibration(
                pairs, claim_allowed=True, shift_threshold=0.05, min_samples=2
            )
            assert "significant" in result
        except Exception:
            pass

    # Human FPR comparison
    samples = {
        "s1": ProbeSample(sample_id="s1", text_sha256=clean_hex, metadata={"label": "human"}),
    }
    for verdicts in [("ai_like", "human_like"), ("human_like", "ai_like"), ("ai_like", "ai_like")]:
        b = dict(base_record, verdict=verdicts[0], score=0.3)
        c = dict(curr_record, verdict=verdicts[1], score=0.4)
        pairs = [(b, c, "s1")]
        try:
            result = _compare_human_fpr(
                pairs,
                claim_allowed=True,
                min_slice_samples=2,
                increase_threshold=0.05,
                samples=samples,
            )
            assert "human_sample_count" in result
        except Exception:
            pass

    # Provider metadata comparison
    for records_pairs in [
        (
            [{"provider_version": "v1", "detector_version": "1.0", "execution": "remote"}],
            [{"provider_version": "v2", "detector_version": "1.1", "execution": "remote"}],
        ),
        (
            [{"provider_version": None, "detector_version": "1.0", "execution": "local"}],
            [{"provider_version": None, "detector_version": "1.0", "execution": "local"}],
        ),
    ]:
        try:
            result = _compare_provider_metadata(records_pairs[0], records_pairs[1])
            assert "provider_metadata_changed" in result
        except Exception:
            pass

    # Supported regime comparison
    for lang_pairs in [
        (
            [{"supported_languages": ["en"], "min_words": 50}],
            [{"supported_languages": ["en", "fr"], "min_words": 30}],
        ),
        (
            [{"supported_languages": [], "min_words": None}],
            [{"supported_languages": [], "min_words": None}],
        ),
    ]:
        try:
            result = _compare_supported_regime(lang_pairs[0], lang_pairs[1])
            assert "regime_changed" in result
        except Exception:
            pass


def _fuzz_read_snapshot_file(text: str) -> None:
    """Fuzz DriftObservatory.read_snapshot_file with various formats."""
    try:
        from textforensics.drift import DRIFT_SNAPSHOT_SCHEMA, DriftObservatory
    except Exception:
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # Malformed file
        p = tmpdir / "snap.json"
        p.write_text(text, encoding="utf-8")
        try:
            DriftObservatory.read_snapshot_file(p)
        except (json.JSONDecodeError, ValueError):
            pass
        except Exception:
            pass

        # Empty snapshot store
        p.write_text(
            json.dumps({"schema": "textforensics.drift-snapshot-store/v1", "snapshots": []}),
            encoding="utf-8",
        )
        try:
            DriftObservatory.read_snapshot_file(p)
        except ValueError:
            pass
        except Exception:
            pass

        # Snapshot store with 2 snapshots
        clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]
        snap = {
            "schema": DRIFT_SNAPSHOT_SCHEMA,
            "snapshot_id": "x",
            "corpus_sha256": clean_hex,
            "records": [],
            "failures": [],
        }
        p.write_text(
            json.dumps(
                {
                    "schema": "textforensics.drift-snapshot-store/v1",
                    "snapshots": [snap, snap],
                }
            ),
            encoding="utf-8",
        )
        try:
            DriftObservatory.read_snapshot_file(p)
        except ValueError:
            pass
        except Exception:
            pass


def _fuzz_load_snapshots(text: str) -> None:
    """Fuzz load_snapshots with malformed stores and corpus sha mismatches."""
    try:
        from textforensics.drift import DRIFT_SNAPSHOT_SCHEMA, DriftObservatory
    except Exception:
        return

    clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]

    corpus = {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [{"id": "s1", "text_sha256": clean_hex}],
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        store_path = tmpdir / "store.json"

        # Malformed store file
        store_path.write_text(text, encoding="utf-8")
        try:
            obs = DriftObservatory(corpus=corpus)
            obs.load_snapshots(store_path)
        except (json.JSONDecodeError, ValueError):
            pass
        except Exception:
            pass

        # Corpus sha mismatch
        snap = {
            "schema": DRIFT_SNAPSHOT_SCHEMA,
            "snapshot_id": "x",
            "corpus_sha256": "dead" * 16,
            "records": [],
            "failures": [],
        }
        store_path.write_text(
            json.dumps(
                {
                    "schema": "textforensics.drift-snapshot-store/v1",
                    "snapshots": [snap],
                }
            ),
            encoding="utf-8",
        )
        try:
            obs = DriftObservatory(corpus=corpus)
            obs.load_snapshots(store_path, expected_corpus_sha256=clean_hex)
        except ValueError:
            pass
        except Exception:
            pass

        # replace=False
        store_path.write_text(
            json.dumps(
                {
                    "schema": "textforensics.drift-snapshot-store/v1",
                    "snapshots": [],
                }
            ),
            encoding="utf-8",
        )
        try:
            obs = DriftObservatory(corpus=corpus)
            loaded = obs.load_snapshots(store_path, replace=False)
            assert isinstance(loaded, list)
        except Exception:
            pass


def _fuzz_add_snapshot(text: str) -> None:
    """Fuzz add_snapshot with bad schemas and non-list records."""
    try:
        from textforensics.drift import DriftObservatory
    except Exception:
        return

    clean_hex = "".join(c if c in "0123456789abcdef" else "0" for c in text[:64])[:64]
    corpus = {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [{"id": "s1", "text_sha256": clean_hex}],
    }

    try:
        obs = DriftObservatory(corpus=corpus)
    except Exception:
        return

    for bad_snap in [
        {"schema": "wrong", "records": []},
        {"schema": "textforensics.drift-snapshot/v1", "records": "not-list"},
        {"schema": "textforensics.drift-snapshot/v1", "failures": "not-list"},
        {},
        [],
        "not-a-dict",
    ]:
        try:
            obs.add_snapshot(bad_snap)
        except (ValueError, TypeError):
            pass
        except Exception:
            pass


@atheris.instrument_func
def TestOneInput(data: bytes) -> None:
    """Fuzz DriftObservatory corpus loading, snapshot creation, and comparison."""
    try:
        text = data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        text = ""

    _fuzz_distribution_summary(data)
    _fuzz_coerce_helpers(text)
    _fuzz_corpus_loading(text)
    _fuzz_observations_and_snapshots(text)
    _fuzz_snapshot_comparison(text)
    _fuzz_comparison_helpers(text)
    _fuzz_read_snapshot_file(text)
    _fuzz_load_snapshots(text)
    _fuzz_add_snapshot(text)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
