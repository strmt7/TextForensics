"""Property-based tests for TextForensics invariants."""

from __future__ import annotations

import json
import math
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from textforensics import emergency_stop
from textforensics.analyzers import run_builtin_analyzers
from textforensics.bundle import pack_bundle, verify_bundle
from textforensics.casefile import CASE_SCHEMA, seal_case_file, verify_case_file
from textforensics.detectors import (
    _FORBIDDEN_EVIDENCE_KEYS,
    _forbidden_evidence_paths,
    _validate_no_source_echo,
    BuiltinHeuristicDetector,
    DetectorContractError,
    DetectorPrediction,
    discover_detector_registry,
    execute_detector,
    validate_prediction,
)
from textforensics.drift import DRIFT_CORPUS_SCHEMA, DriftObservatory
from textforensics.engine import _verdict, analyze_text
from textforensics.features import extract_features
from textforensics.threshold_selection import select_threshold, validate_no_contamination
from textforensics.trust import TRUST_STATES, build_trust_map

PROPERTY_SETTINGS = settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)

FILE_SETTINGS = settings(
    max_examples=10,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


@pytest.fixture(autouse=True)
def _clear_emergency_stop(monkeypatch):
    monkeypatch.delenv(emergency_stop.ENV_VAR, raising=False)


WORD_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
word_st = st.text(alphabet=WORD_ALPHABET, min_size=1, max_size=8)
text_st = st.lists(word_st, min_size=1, max_size=60).map(" ".join)

score_st = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
maybe_score_st = st.one_of(st.none(), score_st)
hex64_st = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
verdict_st = st.sampled_from(["ai_like", "human_like", "abstain"])

safe_key_st = st.sampled_from(["alpha", "beta", "gamma", "delta", "epsilon", "zeta"])
safe_text_st = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789 .,-_", max_size=12)
json_scalar_st = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-100, max_value=100),
    score_st,
    safe_text_st,
)
json_value_st = st.recursive(
    json_scalar_st,
    lambda children: st.one_of(
        st.lists(children, max_size=2),
        st.dictionaries(safe_key_st, children, max_size=2),
    ),
    max_leaves=8,
)


def _prediction(**overrides) -> DetectorPrediction:
    data = {
        "schema": "textforensics.detector-result/v1",
        "detector_id": "test/detector",
        "detector_version": "1.0.0",
        "detector_family": "test-family",
        "execution": "local",
        "score": 0.5,
        "score_semantics": "test native score",
        "verdict": "ai_like",
        "threshold": 0.5,
        "calibrated_ai_probability": None,
        "calibration_id": None,
        "reliability": 0.5,
        "supported_languages": ["en"],
        "min_words": 10,
        "evidence": [],
        "warnings": [],
        "runtime_ms": 1.0,
    }
    data.update(overrides)
    return DetectorPrediction(**data)


def _without_runtime(prediction: DetectorPrediction) -> dict:
    data = prediction.to_dict()
    data.pop("runtime_ms", None)
    return data


_DETECTED_DETECTORS = list(discover_detector_registry().detectors.values())


@PROPERTY_SETTINGS
@given(text=text_st)
def test_score_bounds(text: str) -> None:
    features = extract_features(text)
    analyzers = run_builtin_analyzers(features)
    for analyzer in analyzers:
        assert 0.0 <= analyzer.score <= 1.0
        assert 0.0 <= analyzer.reliability <= 1.0

    result = analyze_text(text, include_robustness=False)
    assert 0.0 <= result.score <= 1.0
    assert 0.0 <= result.confidence <= 1.0
    assert 0.0 <= result.disagreement <= 1.0
    assert 0.0 <= result.robustness_stability <= 1.0

    for detector in _DETECTED_DETECTORS:
        prediction, failure = execute_detector(detector, text)
        assert failure is None
        assert prediction is not None
        if prediction.score is not None:
            assert 0.0 <= prediction.score <= 1.0
        if prediction.calibrated_ai_probability is not None:
            assert 0.0 <= prediction.calibrated_ai_probability <= 1.0
        if prediction.reliability is not None:
            assert 0.0 <= prediction.reliability <= 1.0


@PROPERTY_SETTINGS
@given(text=text_st)
def test_deterministic_mode(text: str) -> None:
    first = analyze_text(text, include_robustness=True)
    second = analyze_text(text, include_robustness=True)
    assert first == second

    detector = BuiltinHeuristicDetector()
    prediction_a, failure_a = execute_detector(detector, text)
    prediction_b, failure_b = execute_detector(detector, text)
    assert failure_a is None
    assert failure_b is None
    assert prediction_a is not None
    assert prediction_b is not None
    assert _without_runtime(prediction_a) == _without_runtime(prediction_b)


SHORT_AI_TEXT = ("In conclusion, the robust solution seamlessly delves into tapestry. ") * 3


@st.composite
def long_human_text(draw):
    suffix = draw(st.integers(min_value=1, max_value=999999))
    counter = 0

    def next_word() -> str:
        nonlocal counter
        counter += 1
        return f"W{suffix}{counter}"

    specs = [
        (3, "."),
        (28, "?"),
        (4, "!"),
        (35, "."),
        (5, "?"),
        (40, "."),
        (6, "!"),
        (32, "."),
    ]
    sentences = []
    for n, end in specs:
        tokens = [next_word() for _ in range(n)]
        if n > 2:
            tokens[1] = tokens[1] + ","
        if n > 4:
            tokens[3] = tokens[3] + ":"
        if n > 6:
            tokens[5] = "(" + tokens[5] + ")"
        if n > 8:
            tokens[7] = tokens[7] + "-" + next_word()
        if n > 10:
            tokens[9] = tokens[9] + ";"
        sentences.append(" ".join(tokens) + end)

    paragraphs = [
        " ".join(sentences[0:2]),
        " ".join(sentences[2:5]),
        " ".join(sentences[5:8]),
    ]
    return "\n\n".join(paragraphs)


@PROPERTY_SETTINGS
@given(long_text=long_human_text())
def test_longer_text_does_not_necessarily_score_higher(long_text: str) -> None:
    assert len(long_text) > len(SHORT_AI_TEXT)
    short_score = analyze_text(SHORT_AI_TEXT, include_robustness=False).score
    long_score = analyze_text(long_text, include_robustness=False).score
    assert long_score < short_score


@PROPERTY_SETTINGS
@given(score=score_st, reliability=score_st)
def test_verdict_consistency(score: float, reliability: float) -> None:
    first = _verdict(score, reliability)
    second = _verdict(score, reliability)
    assert first == second
    assert first in {
        "insufficient_evidence",
        "machine_like_patterns",
        "human_like_patterns",
        "indeterminate",
    }


@PROPERTY_SETTINGS
@given(text=text_st)
def test_verdict_is_allowed(text: str) -> None:
    result = analyze_text(text, include_robustness=False)
    assert result.verdict in {
        "insufficient_evidence",
        "machine_like_patterns",
        "human_like_patterns",
        "indeterminate",
    }


@PROPERTY_SETTINGS
@given(text=text_st)
def test_detector_contract_builtin_output(text: str) -> None:
    detector = BuiltinHeuristicDetector()
    prediction, failure = execute_detector(detector, text)
    assert failure is None
    assert prediction is not None
    assert prediction.calibrated_ai_probability is None
    assert prediction.calibration_id is None
    assert _forbidden_evidence_paths(prediction.evidence) == []


@PROPERTY_SETTINGS
@given(probability=score_st)
def test_validator_rejects_uncalibrated_probability(probability: float) -> None:
    prediction = _prediction(calibrated_ai_probability=probability, calibration_id=None)
    with pytest.raises(DetectorContractError):
        validate_prediction(prediction)


@PROPERTY_SETTINGS
@given(calibration_id=st.text(alphabet="abcdef", min_size=1, max_size=8))
def test_validator_rejects_calibration_without_probability(calibration_id: str) -> None:
    prediction = _prediction(calibrated_ai_probability=None, calibration_id=calibration_id)
    with pytest.raises(DetectorContractError):
        validate_prediction(prediction)


@PROPERTY_SETTINGS
@given(
    probability=st.one_of(
        st.floats(min_value=1.0001, max_value=10.0, allow_nan=False, allow_infinity=False),
        st.floats(min_value=-10.0, max_value=-0.0001, allow_nan=False, allow_infinity=False),
    )
)
def test_validator_rejects_out_of_range_probability(probability: float) -> None:
    prediction = _prediction(calibrated_ai_probability=probability, calibration_id="cal-1")
    with pytest.raises(DetectorContractError):
        validate_prediction(prediction)


@PROPERTY_SETTINGS
@given(key=st.sampled_from(sorted(_FORBIDDEN_EVIDENCE_KEYS)))
def test_validator_rejects_forbidden_evidence_keys(key: str) -> None:
    prediction = _prediction(evidence=[{key: "value"}])
    with pytest.raises(DetectorContractError):
        validate_prediction(prediction)


@PROPERTY_SETTINGS
@given(
    text=st.lists(
        st.text(alphabet="abcdefghij", min_size=3, max_size=6),
        min_size=9,
        max_size=15,
    ).map(" ".join)
)
def test_validator_rejects_source_echo(text: str) -> None:
    prediction = _prediction(evidence=[{"note": text}])
    with pytest.raises(DetectorContractError):
        _validate_no_source_echo(prediction, text)


@st.composite
def trust_prediction_st(draw):
    return DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id=draw(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_", min_size=1, max_size=10)
        ),
        detector_version="1",
        detector_family=draw(st.sampled_from(["family-a", "family-b", "family-c"])),
        execution="local",
        score=draw(maybe_score_st),
        score_semantics="test",
        verdict=draw(verdict_st),
        threshold=draw(maybe_score_st),
        calibrated_ai_probability=None,
        calibration_id=None,
        reliability=draw(maybe_score_st),
        supported_languages=draw(st.lists(st.sampled_from(["en", "fr", "de"]), max_size=2)),
        min_words=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=200))),
        evidence=[],
        warnings=[],
        runtime_ms=None,
    )


robustness_row_st = st.fixed_dictionaries(
    {
        "detector_id": st.text(alphabet="abcdefghij", min_size=1, max_size=5),
        "verdict_stability": st.one_of(st.none(), score_st),
        "native_score_range": st.one_of(st.none(), st.lists(score_st, max_size=2)),
    }
)


@PROPERTY_SETTINGS
@given(
    predictions=st.lists(trust_prediction_st(), max_size=3),
    word_count=st.integers(min_value=0, max_value=1000),
    robustness=st.lists(robustness_row_st, max_size=3),
    failure_count=st.integers(min_value=0, max_value=3),
)
def test_trust_map_states_allowed(
    predictions: list[DetectorPrediction],
    word_count: int,
    robustness: list[dict],
    failure_count: int,
) -> None:
    trust_map = build_trust_map(
        predictions,
        word_count=word_count,
        robustness=robustness,
        failure_count=failure_count,
    )
    assert trust_map.schema == "textforensics.trust-map/v1"
    assert trust_map.overall in {"insufficient", "mixed", "strong"}
    for dimension in trust_map.dimensions:
        assert dimension.state in TRUST_STATES
        assert isinstance(dimension.dimension, str)
        assert dimension.dimension


@FILE_SETTINGS
@given(
    human_scores=st.lists(score_st, min_size=1, max_size=5),
    ai_scores=st.lists(score_st, min_size=1, max_size=5),
    target_fpr=score_st,
)
def test_threshold_selection_preserves_fpr_target(
    human_scores: list[float],
    ai_scores: list[float],
    target_fpr: float,
) -> None:
    rows = [("human", score) for score in human_scores] + [("ai", score) for score in ai_scores]
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "calibration.jsonl"
        path.write_text(
            json.dumps({"label": "human", "text": "sample"}) + "\n",
            encoding="utf-8",
        )
        with patch(
            "textforensics.threshold_selection._load_scores",
            return_value=(rows, 0),
        ):
            result = select_threshold(path, target_fpr=target_fpr)

    assert math.isfinite(result.threshold)
    assert 0.0 <= result.observed_fpr <= target_fpr + 1e-12
    assert 0.0 <= result.observed_tpr <= 1.0
    assert result.human_samples == len(human_scores)
    assert result.ai_samples == len(ai_scores)


def _write_labeled_jsonl(path: Path, texts: list[str], split: str) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for index, text in enumerate(texts):
            label = "human" if index % 2 == 0 else "ai"
            handle.write(
                json.dumps({"label": label, "text": text, "split": split}) + "\n"
            )


@st.composite
def disjoint_text_pairs(draw):
    calibration = draw(
        st.lists(
            st.sampled_from(["cal_alpha", "cal_beta", "cal_gamma"]),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    test = draw(
        st.lists(
            st.sampled_from(["test_alpha", "test_beta", "test_gamma"]),
            min_size=1,
            max_size=3,
            unique=True,
        )
    )
    return calibration, test


@st.composite
def overlapping_text_pairs(draw):
    shared = draw(
        st.lists(
            st.sampled_from(["shared_alpha", "shared_beta"]),
            min_size=1,
            max_size=2,
            unique=True,
        )
    )
    calibration_extra = draw(
        st.lists(
            st.sampled_from(["cal_extra_alpha", "cal_extra_beta"]),
            min_size=0,
            max_size=2,
            unique=True,
        )
    )
    test_extra = draw(
        st.lists(
            st.sampled_from(["test_extra_alpha", "test_extra_beta"]),
            min_size=0,
            max_size=2,
            unique=True,
        )
    )
    return shared + calibration_extra, shared + test_extra


@FILE_SETTINGS
@given(pair=disjoint_text_pairs())
def test_calibration_disjoint_validation_passes(pair: tuple[list[str], list[str]]) -> None:
    calibration_texts, test_texts = pair
    with tempfile.TemporaryDirectory() as td:
        calibration_path = Path(td) / "calibration.jsonl"
        test_path = Path(td) / "evaluation.jsonl"
        _write_labeled_jsonl(calibration_path, calibration_texts, "calibration")
        _write_labeled_jsonl(test_path, test_texts, "evaluation")

        calibration_rows = [("human", text) for text in calibration_texts]
        with patch(
            "textforensics.threshold_selection._load_scores",
            return_value=(calibration_rows, 0),
        ):
            result = validate_no_contamination(calibration_path, test_path)

    assert result["valid"] is True
    assert result["contamination_detected"] is False
    assert result["shared_samples"] == 0


@FILE_SETTINGS
@given(
    texts=st.lists(
        st.sampled_from(["dup_alpha", "dup_beta", "dup_gamma"]),
        min_size=1,
        max_size=3,
        unique=True,
    )
)
def test_calibration_identical_dataset_is_contaminated(texts: list[str]) -> None:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "same.jsonl"
        _write_labeled_jsonl(path, texts, "calibration")
        result = validate_no_contamination(path, path)

    assert result["contamination_detected"] is True
    assert result["valid"] is False


@FILE_SETTINGS
@given(pair=overlapping_text_pairs())
def test_calibration_overlap_is_detected(pair: tuple[list[str], list[str]]) -> None:
    calibration_texts, test_texts = pair
    with tempfile.TemporaryDirectory() as td:
        calibration_path = Path(td) / "calibration.jsonl"
        test_path = Path(td) / "evaluation.jsonl"
        _write_labeled_jsonl(calibration_path, calibration_texts, "calibration")
        _write_labeled_jsonl(test_path, test_texts, "evaluation")

        calibration_rows = [("human", text) for text in calibration_texts]
        with patch(
            "textforensics.threshold_selection._load_scores",
            return_value=(calibration_rows, 0),
        ):
            result = validate_no_contamination(calibration_path, test_path)

    assert result["contamination_detected"] is True
    assert result["valid"] is False
    assert result["shared_samples"] > 0


@st.composite
def forensic_bundle_st(draw):
    return {
        "schema": "textforensics.forensic-bundle/v1",
        "generated_at_utc": "2026-01-01T00:00:00+00:00",
        "content_sha256": draw(hex64_st),
        "input": {
            "raw_text_included": False,
            "text_sha256": draw(hex64_st),
            "word_count": draw(st.integers(min_value=0, max_value=10000)),
        },
        "detector_results": draw(st.lists(json_value_st, max_size=2)),
        "detector_failures": draw(st.lists(json_value_st, max_size=1)),
        "trust_map": {
            "overall": draw(st.sampled_from(["strong", "mixed", "insufficient"])),
            "dimensions": [],
        },
        "metadata": draw(json_value_st),
    }


@FILE_SETTINGS
@given(bundle=forensic_bundle_st())
def test_case_file_hash_round_trip(bundle: dict) -> None:
    case = seal_case_file(
        bundle,
        deterministic=True,
        fixed_timestamp="2026-01-01T00:00:00+00:00",
    )
    assert case["schema"] == CASE_SCHEMA
    assert case["raw_text_included"] is False
    assert verify_case_file(case)["valid"] is True

    serialized = json.dumps(case, ensure_ascii=False)
    deserialized = json.loads(serialized)
    assert verify_case_file(deserialized)["valid"] is True

    repeated = seal_case_file(
        bundle,
        deterministic=True,
        fixed_timestamp="2026-01-01T00:00:00+00:00",
    )
    assert repeated == case

    tampered = json.loads(serialized)
    tampered["tampered"] = True
    bad = verify_case_file(tampered)
    assert bad["valid"] is False
    assert "case_hash_mismatch" in bad["errors"]


@st.composite
def bundle_files_st(draw):
    count = draw(st.integers(min_value=1, max_value=3))
    names = draw(
        st.lists(
            st.text(alphabet="abcdefghij0123456789_-", min_size=1, max_size=8),
            min_size=count,
            max_size=count,
            unique=True,
        )
    )
    extensions = draw(
        st.lists(
            st.sampled_from(["", ".json", ".txt", ".bin"]),
            min_size=count,
            max_size=count,
        )
    )
    files = {}
    for name, extension in zip(names, extensions, strict=True):
        files[f"f_{name}{extension}"] = draw(st.binary(min_size=0, max_size=32))
    return files


@FILE_SETTINGS
@given(files=bundle_files_st(), fmt=st.sampled_from(["tar.gz", "zip"]))
def test_bundle_pack_verify_round_trip(files: dict[str, bytes], fmt: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "case"
        source.mkdir()
        for name, data in files.items():
            (source / name).write_bytes(data)

        bundle_path = Path(td) / f"bundle.{fmt}"
        manifest = pack_bundle(source, bundle_path)
        assert manifest.format == fmt
        assert manifest.bundle_filename == bundle_path.name
        assert set(manifest.per_file_digests) == set(files)

        result = verify_bundle(bundle_path)
        assert result.valid is True
        assert result.bundle_digest_match is True
        assert result.per_file_status == {name: "ok" for name in files}

        bundle_path.write_bytes(bundle_path.read_bytes() + b"tamper")
        bad = verify_bundle(bundle_path)
        assert bad.valid is False


@st.composite
def drift_corpus_observations(draw):
    count = draw(st.integers(min_value=1, max_value=3))
    sample_ids = draw(
        st.lists(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-", min_size=1, max_size=10),
            min_size=count,
            max_size=count,
            unique=True,
        )
    )
    text_hashes = draw(st.lists(hex64_st, min_size=count, max_size=count))
    corpus = {
        "schema": DRIFT_CORPUS_SCHEMA,
        "samples": [
            {"id": sample_id, "text_sha256": text_hash}
            for sample_id, text_hash in zip(sample_ids, text_hashes, strict=True)
        ],
    }

    detector_id = draw(st.sampled_from(["detector-one", "detector-two"]))
    detector_family = draw(st.sampled_from(["family-one", "family-two"]))
    records = []
    for sample_id, text_hash in zip(sample_ids, text_hashes, strict=True):
        records.append(
            {
                "sample_id": sample_id,
                "text_sha256": text_hash,
                "detector_id": detector_id,
                "detector_version": "1.0.0",
                "detector_family": detector_family,
                "execution": "local",
                "score": draw(maybe_score_st),
                "score_semantics": "higher_means_more_machine_like; test",
                "verdict": draw(verdict_st),
                "threshold": draw(maybe_score_st),
                "calibrated_ai_probability": None,
                "calibration_id": None,
                "reliability": draw(maybe_score_st),
                "supported_languages": ["en"],
                "min_words": draw(
                    st.one_of(st.none(), st.integers(min_value=0, max_value=100))
                ),
            }
        )
    return corpus, records


@PROPERTY_SETTINGS
@given(data=drift_corpus_observations())
def test_drift_snapshot_comparison_idempotence(data: tuple[dict, list[dict]]) -> None:
    corpus, records = data
    observatory = DriftObservatory(corpus=corpus)

    baseline = observatory.snapshot_from_observations(
        records,
        snapshot_id="baseline",
        taken_at="2026-01-01T00:00:00+00:00",
        label="baseline",
    )
    current = observatory.snapshot_from_observations(
        records,
        snapshot_id="current",
        taken_at="2026-01-02T00:00:00+00:00",
        label="current",
    )

    first = observatory.compare_snapshots(baseline, current)
    second = observatory.compare_snapshots(baseline, current)
    first.pop("generated_at")
    second.pop("generated_at")
    assert first == second

    self_first = observatory.compare_snapshots(baseline, baseline)
    self_second = observatory.compare_snapshots(baseline, baseline)
    self_first.pop("generated_at")
    self_second.pop("generated_at")
    assert self_first == self_second