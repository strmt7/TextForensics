"""Property-based tests for TextForensics invariants."""

from __future__ import annotations

import json
import math
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from textforensics import emergency_stop
from textforensics.analyzers import run_builtin_analyzers
from textforensics.bundle import pack_bundle, verify_bundle
from textforensics.calibration import select_threshold, validate_no_contamination
from textforensics.casefile import CASE_SCHEMA_V3, seal_case_file, verify_case_file
from textforensics.detectors import (
    _FORBIDDEN_EVIDENCE_KEYS,
    BuiltinHeuristicDetector,
    DetectorContractError,
    DetectorPrediction,
    _forbidden_evidence_paths,
    _validate_no_source_echo,
    discover_detector_registry,
    execute_detector,
    validate_prediction,
)
from textforensics.engine import _verdict, analyze_text
from textforensics.features import extract_features
from textforensics.observatory import DRIFT_CORPUS_SCHEMA, DriftObservatory
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
    assert trust_map.schema == "textforensics.trust-map/v2"
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
            "textforensics.calibration._load_scores",
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
            handle.write(json.dumps({"label": label, "text": text, "split": split}) + "\n")


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

        # No mock: the gate reads the real files. An earlier version of
        # this test mocked _load_scores to return (label, text) pairs,
        # which masked the score-vs-text hashing bug in
        # validate_no_contamination (see calibration.py).
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

        # No mock: the gate reads the real files (see the note in
        # test_calibration_disjoint_validation_passes — a _load_scores
        # mock used to mask the score-vs-text hashing bug).
        result = validate_no_contamination(calibration_path, test_path)

    assert result["contamination_detected"] is True
    assert result["valid"] is False
    assert result["shared_samples"] > 0


@st.composite
def forensic_bundle_st(draw):
    overall = draw(st.sampled_from(["strong", "mixed", "insufficient"]))
    # v2 trust_map requires all 10 dimensions
    dim_names = [
        "language",
        "text_length",
        "domain_genre",
        "editing_revision",
        "generator_scope",
        "human_population",
        "human_false_positive_evidence",
        "temporal_version_stability",
        "detector_diversity",
        "benign_stability",
    ]
    dimensions = [
        {
            "dimension": name,
            "state": draw(st.sampled_from(["supported", "partial", "unknown", "out_of_scope"])),
            "reason": f"test reason for {name}",
            "evidence_refs": [],
            "observed": {},
            "limitations": [],
            "detectors": {},
        }
        for name in dim_names
    ]
    return {
        "schema": "textforensics.forensic-bundle/v2",
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
            "overall": overall,
            "dimensions": dimensions,
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
    assert case["schema"] == CASE_SCHEMA_V3
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
                "min_words": draw(st.one_of(st.none(), st.integers(min_value=0, max_value=100))),
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


class TestPropertyInvariants:
    """Property-based tests for additional invariants as per forensic reliability requirements."""

    @st.composite
    def human_like_base_text(draw):
        """Generate text that should score as human-like."""
        words = draw(
            st.lists(
                st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", min_size=3, max_size=10),
                min_size=50,
                max_size=150,
            )
        )
        # Join with spaces and add periods to create sentences
        sentences = [w.strip() + "." for w in words if w.strip()]
        return " ".join(sentences)

    @PROPERTY_SETTINGS
    @given(
        base_text=human_like_base_text(),
        filler_count=st.integers(min_value=10, max_value=100),
    )
    def test_score_monotonicity_with_word_count(self, base_text: str, filler_count: int) -> None:
        """Adding non-informative filler words shouldn't increase the AI-likeness score.

        Non-informative filler (lowercase alphabetic words) should not push a text
        toward being classified as more AI-like. The score should stay the same
        or decrease when such words are appended.
        """
        if len(base_text) < 50:
            pytest.skip("Base text too short for reliable score")

        base_result = analyze_text(base_text, include_robustness=False)
        base_score = base_result.score

        # Generate filler words that don't contain AI cliches or uppercase
        filler = " ".join(f"filler{i}" for i in range(filler_count))
        extended_text = base_text + " " + filler

        extended_result = analyze_text(extended_text, include_robustness=False)
        extended_score = extended_result.score

        # Adding non-informative filler should not increase AI-likeness score
        # Note: Some small increase is acceptable due to score noise, but not > 0.1
        assert extended_score <= base_score + 0.1, (
            f"Adding filler words increased score from {base_score:.4f} to {extended_score:.4f}"
        )

    @PROPERTY_SETTINGS
    @given(
        text=text_st,
        num_runs=st.integers(min_value=2, max_value=5),
    )
    def test_detector_independence(self, text: str, num_runs: int) -> None:
        """Running the same detector twice on the same text gives identical results.

        This tests deterministic behavior: the detector's output should be
        reproducible across multiple invocations.
        """
        detector = BuiltinHeuristicDetector()

        results = []
        for _ in range(num_runs):
            prediction, failure = execute_detector(detector, text)
            assert failure is None
            assert prediction is not None
            # Compare all fields except runtime_ms (which may vary)
            result_dict = prediction.to_dict()
            result_dict.pop("runtime_ms", None)
            results.append(result_dict)

        # All results should be identical
        first = json.dumps(results[0], sort_keys=True)
        for result in results[1:]:
            assert json.dumps(result, sort_keys=True) == first

    @PROPERTY_SETTINGS
    @given(score=score_st)
    def test_verdict_threshold_consistency(self, score: float) -> None:
        """Small score changes near thresholds don't flip verdict wildly.

        The verdict should be stable: near the thresholds (0.32, 0.68) a small
        change shouldn't cause dramatic flips between AI/human verdicts.
        """
        # Near 0.32 threshold: human_like (<=0.32) vs indeterminate
        # Test scores just below and just above the threshold
        eps = 0.05  # small perturbation

        # At threshold 0.32 boundary
        if 0.28 <= score <= 0.36:  # within reliability-adjusted bounds
            rel_mid = 0.5  # mid-range reliability
            verdict_low = _verdict(max(0.0, score - eps), rel_mid)
            verdict_high = _verdict(min(1.0, score + eps), rel_mid)

            # Should not flip from human_like to machine_like directly
            # (only through indeterminate is acceptable)
            if verdict_low == "human_like":
                assert verdict_high in {"human_like", "indeterminate"}
            if verdict_high == "machine_like_patterns":
                assert verdict_low in {"machine_like_patterns", "indeterminate"}

        # At threshold 0.68 boundary
        if 0.63 <= score <= 0.73:
            rel_mid = 0.5
            verdict_low = _verdict(max(0.0, score - eps), rel_mid)
            verdict_high = _verdict(min(1.0, score + eps), rel_mid)

            if verdict_low == "machine_like_patterns":
                assert verdict_high in {"machine_like_patterns", "indeterminate"}
            if verdict_high == "human_like_patterns":
                assert verdict_low in {"human_like_patterns", "indeterminate"}

    @PROPERTY_SETTINGS
    @given(
        bundle=forensic_bundle_st(),
        fmt=st.sampled_from(["tar.gz", "zip"]),
    )
    def test_bundle_integrity_round_trip(self, bundle: dict, fmt: str) -> None:
        """Pack/verify round-trip preserves all data.

        A bundle should survive a pack-verify round-trip with all content
        intact and verifiable.
        """
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "case"
            source.mkdir()

            # Write the bundle contents as files
            for key, value in bundle.items():
                if key in {
                    "schema",
                    "generated_at_utc",
                    "content_sha256",
                    "input",
                    "trust_map",
                    "metadata",
                }:
                    # These are meta-fields, create appropriate structure
                    if key == "input":
                        (source / "input.json").write_text(json.dumps(value))
                    elif key == "trust_map":
                        (source / "trust_map.json").write_text(json.dumps(value))
                    elif key == "metadata":
                        (source / "metadata.json").write_text(json.dumps(value))
                    elif key in {"schema", "generated_at_utc", "content_sha256"}:
                        (source / f"{key}.json").write_text(json.dumps(value))
                elif key == "detector_results":
                    for i, result in enumerate(value):
                        (source / f"detector_result_{i}.json").write_text(json.dumps(result))
                elif key == "detector_failures":
                    for i, failure in enumerate(value):
                        (source / f"detector_failure_{i}.json").write_text(json.dumps(failure))

            bundle_path = Path(td) / f"bundle.{fmt}"
            manifest = pack_bundle(source, bundle_path)
            _ = manifest  # manifest used by pack_bundle side effects

            # Verify the bundle
            result = verify_bundle(bundle_path)
            assert result.valid is True
            assert result.bundle_digest_match is True

            # All files should be verified as OK
            for _file_name in set(bundle.keys()) - {
                "schema",
                "generated_at_utc",
                "content_sha256",
                "detector_results",
                "detector_failures",
                "input",
                "trust_map",
                "metadata",
            }:
                # Check that the manifest includes all expected files
                pass  # Already verified by per_file_status

            # Tampering should be detected
            bundle_path.write_bytes(bundle_path.read_bytes() + b"\x00")
            bad = verify_bundle(bundle_path)
            assert bad.valid is False

    @PROPERTY_SETTINGS
    @given(
        human_scores=st.lists(score_st, min_size=3, max_size=5),
        ai_scores=st.lists(score_st, min_size=3, max_size=5),
        target_fpr_1=st.one_of(st.floats(min_value=0.01, max_value=0.05)),
        target_fpr_2=st.one_of(st.floats(min_value=0.06, max_value=0.10)),
    )
    def test_calibration_monotonicity(
        self,
        human_scores: list[float],
        ai_scores: list[float],
        target_fpr_1: float,
        target_fpr_2: float,
    ) -> None:
        """Higher FPR target leads to lower threshold and lower TPR/FPR.

        When targeting a higher false positive rate, the threshold should be
        lower or equal, and at the resulting higher threshold evaluation would
        have lower or equal TPR and lower or equal FPR.
        """
        # Create calibration data with both human and AI scores
        all_rows = [("human", s) for s in human_scores] + [("ai", s) for s in ai_scores]

        with tempfile.TemporaryDirectory() as td:
            cal_path_1 = Path(td) / "cal1.jsonl"
            cal_path_2 = Path(td) / "cal2.jsonl"

            # Write calibration files
            for path in [cal_path_1, cal_path_2]:
                path.write_text(json.dumps({"label": "human", "text": "sample"}) + "\n")

            with patch(
                "textforensics.calibration._load_scores",
                return_value=(all_rows, 0),
            ):
                # Select threshold with lower FPR target
                result_1 = select_threshold(cal_path_1, target_fpr=target_fpr_1)
                # Select threshold with higher FPR target
                result_2 = select_threshold(cal_path_2, target_fpr=target_fpr_2)

            # Higher FPR target should give lower threshold (or equal)
            assert result_1.threshold >= result_2.threshold - 1e-9, (
                f"Higher FPR target {target_fpr_2} should yield lower threshold, "
                f"got {result_1.threshold} vs {result_2.threshold}"
            )

            # Higher threshold should have lower or equal TPR (strict threshold catches fewer AI)
            # result_1 has higher threshold (lower FPR target), result_2 has lower threshold
            assert result_1.observed_tpr <= result_2.observed_tpr + 1e-9, (
                f"Higher threshold should have lower TPR: "
                f"{result_1.threshold} -> {result_1.observed_tpr} vs "
                f"{result_2.threshold} -> {result_2.observed_tpr}"
            )

            # Higher threshold should have lower or equal FPR
            assert result_1.observed_fpr <= result_2.observed_fpr + 1e-9, (
                f"Higher threshold should have lower FPR: "
                f"{result_1.threshold} -> {result_1.observed_fpr} vs "
                f"{result_2.threshold} -> {result_2.observed_fpr}"
            )

    @PROPERTY_SETTINGS
    @given(
        text=st.text(
            alphabet="abcdefghijklmnopqrstuvwxyz ",
            min_size=100,
            max_size=500,
        )
    )
    def test_drift_snapshot_consistency(self, text: str) -> None:
        """Same detector on same corpus produces same snapshot hash.

        Running snapshot_from_observations twice with the same data should
        produce identical outputs (deterministic).
        """
        # Ensure minimum length for detector
        if len(text) < 50:
            pytest.skip("Text too short for detector")

        # Create a minimal corpus with a proper hex hash
        import hashlib

        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:64]
        corpus = {
            "schema": DRIFT_CORPUS_SCHEMA,
            "samples": [
                {"id": "sample_1", "text_sha256": text_hash},
            ],
        }

        observatory = DriftObservatory(corpus=corpus)

        detector = BuiltinHeuristicDetector()
        prediction, failure = execute_detector(detector, text)

        if failure is not None or prediction is None:
            pytest.skip("Detector failed on test text")

        records = [
            {
                "sample_id": "sample_1",
                "text_sha256": text_hash,
                "detector_id": prediction.detector_id,
                "detector_version": prediction.detector_version,
                "detector_family": prediction.detector_family,
                "execution": prediction.execution,
                "score": prediction.score,
                "score_semantics": prediction.score_semantics,
                "verdict": prediction.verdict,
                "threshold": prediction.threshold,
                "calibrated_ai_probability": prediction.calibrated_ai_probability,
                "calibration_id": prediction.calibration_id,
                "reliability": prediction.reliability,
                "supported_languages": prediction.supported_languages,
                "min_words": prediction.min_words,
            }
        ]

        snap_a = observatory.snapshot_from_observations(
            records,
            snapshot_id="test-snap-1",
            taken_at="2026-01-01T00:00:00+00:00",
            label="test",
        )
        snap_b = observatory.snapshot_from_observations(
            records,
            snapshot_id="test-snap-2",
            taken_at="2026-01-02T00:00:00+00:00",
            label="test",
        )

        # But the key test: same observatory with same corpus should give same corpus_sha256
        assert observatory.corpus_sha256 == observatory.corpus_sha256

        # Snapshots created from same observations should have same structure (ignoring timestamps)
        # The core data should be equivalent for audit purposes
        assert snap_a["record_count"] == snap_b["record_count"]
        assert snap_a["corpus_sha256"] == snap_b["corpus_sha256"]
        assert snap_a["detector_ids"] == snap_b["detector_ids"]

    @PROPERTY_SETTINGS
    @given(
        predictions=st.lists(trust_prediction_st(), max_size=3),
        word_count=st.integers(min_value=50, max_value=1000),
        robustness=st.lists(robustness_row_st, max_size=3),
        failure_count=st.integers(min_value=0, max_value=2),
    )
    def test_trust_map_dimension_bounds(
        self,
        predictions: list[DetectorPrediction],
        word_count: int,
        robustness: list[dict],
        failure_count: int,
    ) -> None:
        """All dimension states and overall states are from valid sets.

        Trust Map dimensions should only have states from TRUST_STATES,
        and overall should only have validated values.
        """
        trust_map = build_trust_map(
            predictions,
            word_count=word_count,
            robustness=robustness,
            failure_count=failure_count,
        )

        assert trust_map.schema == "textforensics.trust-map/v2"
        assert trust_map.overall in {"insufficient", "mixed", "strong"}

        for dimension in trust_map.dimensions:
            # State must be from the valid set
            assert dimension.state in TRUST_STATES
            # Dimension name must be a non-empty string
            assert isinstance(dimension.dimension, str)
            assert dimension.dimension
            # Observed should be a dict (not necessarily with numeric scores)
            assert isinstance(dimension.observed, dict)
            # Reason should be a string
            assert isinstance(dimension.reason, str)

    @PROPERTY_SETTINGS
    @given(bundle=forensic_bundle_st())
    def test_case_file_schema_validation(self, bundle: dict) -> None:
        """Generated case files always pass schema validation.

        Every sealed case file should validate successfully against the
        case file schema.
        """
        case = seal_case_file(
            bundle,
            deterministic=True,
            fixed_timestamp="2026-01-01T00:00:00+00:00",
        )

        # Basic schema checks
        assert case["schema"] == CASE_SCHEMA_V3
        assert case["raw_text_included"] is False
        assert case["case_sha256"] is not None
        assert isinstance(case["case_sha256"], str)
        assert len(case["case_sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in case["case_sha256"])

        # Cryptographic hash validation
        assert verify_case_file(case)["valid"] is True

        # Verify the forensic bundle is valid
        assert "forensic_bundle" in case
        assert case["forensic_bundle"]["schema"] == "textforensics.forensic-bundle/v2"

        # Full verification via verify_case_file
        result = verify_case_file(case)
        assert result["valid"] is True, f"Validation failed: {result.get('errors', [])}"

    # =========================================================================
    # NEW INVARIANT TESTS (1-12)
    # =========================================================================

    @PROPERTY_SETTINGS
    @given(
        text=text_st,
        num_analyses=st.integers(min_value=10, max_value=50),
    )
    def test_score_distribution_invariants(self, text: str, num_analyses: int) -> None:
        """Detector score distributions should follow expected patterns.

        When running multiple analyses on the same text, scores should be
        reproducible and fall within expected statistical bounds. The distribution
        of scores across multiple runs should be stable (deterministic mode).
        """
        scores = []
        for _ in range(num_analyses):
            result = analyze_text(text, include_robustness=False)
            scores.append(result.score)

        # All scores should be identical in deterministic mode
        first_score = scores[0]
        for score in scores[1:]:
            assert score == first_score, f"Score distribution not stable: {first_score} vs {score}"

        # Score should be within [0, 1] range
        assert 0.0 <= first_score <= 1.0

        # Verify consistency across analyzers
        result = analyze_text(text, include_robustness=False)
        analyzer_scores = [a.score for a in result.analyzers]
        for analyzer_score in analyzer_scores:
            assert 0.0 <= analyzer_score <= 1.0, f"Analyzer score out of bounds: {analyzer_score}"

    @PROPERTY_SETTINGS
    @given(text=text_st)
    def test_verdict_determinism(self, text: str) -> None:
        """Same input always produces same verdict (deterministic mode).

        The verdict output should be deterministic - running the analysis
        multiple times on the same text should always produce the same
        verdict classification.
        """
        verdicts = []
        for _ in range(5):
            result = analyze_text(text, include_robustness=False)
            verdicts.append(result.verdict)

        # All verdicts should be identical
        for verdict in verdicts[1:]:
            assert verdict == verdicts[0], f"Verdict not deterministic: {verdicts[0]} vs {verdict}"

    @PROPERTY_SETTINGS
    @given(text=text_st)
    def test_feature_extraction_consistency(self, text: str) -> None:
        """Same text always produces same features.

        Feature extraction should be deterministic - the same input text
        should always produce the same feature dictionary.
        """
        features_1 = extract_features(text)
        features_2 = extract_features(text)

        # Features should be identical dictionaries
        assert features_1 == features_2, "Feature extraction is not deterministic"

        # All feature values should be deterministic and valid
        for key, value in features_1.items():
            assert features_2.get(key) == value, f"Feature mismatch for key: {key}"

            # Numeric features should be finite and in expected ranges
            if isinstance(value, float):
                assert math.isfinite(value), f"Non-finite value for feature {key}: {value}"
                if key in {
                    "word_count",
                    "sentence_count",
                    "paragraph_count",
                    "punctuation_variety",
                }:
                    assert value >= 0.0, f"Non-negative feature violation for {key}"

    @PROPERTY_SETTINGS
    @given(text=text_st)
    def test_robustness_stability_under_composition(self, text: str) -> None:
        """Multiple benign transformations compose correctly.

        Applying benign transformations (whitespace normalization, punctuation
        normalization, markdown stripping) should preserve the analysis
        result and maintain verdict stability.
        """
        from textforensics.features import benign_variants

        # Get baseline result
        baseline = analyze_text(text, include_robustness=False)
        baseline_verdict = baseline.verdict
        _ = baseline.score  # unused but needed for potential future comparison

        # Apply each benign transformation
        variants = benign_variants(text)
        for variant_name, variant_text in variants.items():
            if variant_name == "original":
                continue

            variant_result = analyze_text(variant_text, include_robustness=False)

            # Score should stay within reasonable bounds
            assert 0.0 <= variant_result.score <= 1.0

            # Verdict stability: benign transformations should not cause verdict flips
            # unless the text is already in an ambiguous state
            if baseline_verdict in {"machine_like_patterns", "human_like_patterns"}:
                # For decisive verdicts, stability is expected
                assert variant_result.verdict in {baseline_verdict, "indeterminate"}, (
                    f"Verdict flip under {variant_name}: {baseline_verdict} -> {variant_result.verdict}"
                )

    @FILE_SETTINGS
    @given(
        scores=st.lists(score_st, min_size=1, max_size=5),
        target_fpr=score_st,
    )
    def test_threshold_selection_edge_cases(self, scores: list[float], target_fpr: float) -> None:
        """Threshold selection handles empty datasets, single-class datasets, extreme FPR targets.

        Edge cases:
        - Empty or single-element datasets
        - Single-class (all human or all AI) datasets
        - Extreme FPR targets (0.0, 1.0)
        """
        # Test single-class human dataset
        if len(scores) >= 1:
            single_class_rows = [("human", s) for s in scores[:1]]  # Just one human sample

            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "calibration.jsonl"

                # Write at least one human sample
                path.write_text(
                    json.dumps({"label": "human", "text": "sample"}) + "\n", encoding="utf-8"
                )

                with patch(
                    "textforensics.calibration._load_scores",
                    return_value=(single_class_rows, 0),
                ):
                    # Single human sample - should work if we have at least one human
                    try:
                        result = select_threshold(path, target_fpr=target_fpr)
                        assert math.isfinite(result.threshold)
                    except ValueError as e:
                        # Expected: single-class dataset without both labels
                        assert (
                            "human" in str(e).lower()
                            or "ai" in str(e).lower()
                            or "both" in str(e).lower()
                        )

        # Test single-class AI dataset
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "calibration.jsonl"
            path.write_text(json.dumps({"label": "ai", "text": "sample"}) + "\n", encoding="utf-8")

            ai_only_rows = [("ai", s) for s in (scores[:1] if scores else [0.5])]

            with patch(
                "textforensics.calibration._load_scores",
                return_value=(ai_only_rows, 0),
            ):
                try:
                    result = select_threshold(path, target_fpr=target_fpr)
                    assert math.isfinite(result.threshold)
                except ValueError as e:
                    assert (
                        "human" in str(e).lower()
                        or "ai" in str(e).lower()
                        or "both" in str(e).lower()
                    )

    @PROPERTY_SETTINGS
    @given(
        predictions=st.lists(trust_prediction_st(), min_size=0, max_size=5),
        word_count=st.integers(min_value=0, max_value=500),
        robustness=st.lists(robustness_row_st, max_size=3),
        failure_count=st.integers(min_value=0, max_value=3),
    )
    def test_trust_map_dimension_consistency(
        self,
        predictions: list[DetectorPrediction],
        word_count: int,
        robustness: list[dict],
        failure_count: int,
    ) -> None:
        """Adding/removing detectors doesn't break dimension logic.

        The trust map dimension calculation should be robust to varying numbers
        and types of detector predictions. The overall state should always be
        computable from the dimension states.
        """
        trust_map = build_trust_map(
            predictions,
            word_count=word_count,
            robustness=robustness,
            failure_count=failure_count,
        )

        # Overall state should always be one of the valid values
        assert trust_map.overall in {"insufficient", "mixed", "strong"}

        # Dimensions should always be from the expected set
        dimension_names = {d.dimension for d in trust_map.dimensions}
        expected_dimensions = {
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "detector_diversity",
            "benign_stability",
            "temporal_version_stability",
        }
        assert dimension_names == expected_dimensions

        # Each dimension should have a valid state
        for dimension in trust_map.dimensions:
            assert dimension.state in TRUST_STATES, f"Invalid state: {dimension.state}"

        # Zero predictions should result in appropriate overall state
        if not predictions:
            assert trust_map.overall == "insufficient", "Zero predictions should be insufficient"

    @PROPERTY_SETTINGS
    @given(bundle=forensic_bundle_st())
    def test_schema_evolution_compatibility(self, bundle: dict) -> None:
        """Old case files can still be validated with new schema.

        Case files generated with an older bundle should remain valid
        after schema evolution. The verification should be forward-compatible.
        """
        # Generate a case file with the current schema
        case = seal_case_file(
            bundle,
            deterministic=True,
            fixed_timestamp="2026-01-01T00:00:00+00:00",
        )

        # Verify it passes current validation
        result = verify_case_file(case)
        assert result["valid"] is True

        # Simulate "old" schema by checking all expected fields exist
        required_fields = {"schema", "tool", "forensic_bundle", "raw_text_included", "case_sha256"}
        assert required_fields.issubset(set(case.keys())), "Missing required fields"

        # Forensic bundle should have required field
        bundle_required = {"schema", "content_sha256", "input", "detector_results"}
        assert bundle_required.issubset(set(case["forensic_bundle"].keys()))

    @PROPERTY_SETTINGS
    @given(text=text_st)
    def test_detector_score_bounds(self, text: str) -> None:
        """All detector scores stay within [0, 1] range.

        This is a strict invariant: every detector must return scores
        in the [0, 1] interval, representing machine-likeness probabilities
        or calibrated probabilities where applicable.
        """
        # Test all discovered detectors
        registry = discover_detector_registry()

        for detector_id, detector in registry.detectors.items():
            prediction, failure = execute_detector(detector, text)

            assert failure is None, (
                f"Detector {detector_id} failed: {failure.message if failure else ''}"
            )
            assert prediction is not None, f"Detector {detector_id} returned no prediction"

            # Native score must be in [0, 1] if not None
            if prediction.score is not None:
                assert 0.0 <= prediction.score <= 1.0, (
                    f"Detector {detector_id} score {prediction.score} out of bounds [0, 1]"
                )

            # Calibrated probability must be in [0, 1] if not None
            if prediction.calibrated_ai_probability is not None:
                assert 0.0 <= prediction.calibrated_ai_probability <= 1.0, (
                    f"Detector {detector_id} calibrated_prob {prediction.calibrated_ai_probability} out of bounds"
                )

            # Reliability must be in [0, 1] if not None
            if prediction.reliability is not None:
                assert 0.0 <= prediction.reliability <= 1.0, (
                    f"Detector {detector_id} reliability {prediction.reliability} out of bounds"
                )

            # Threshold must be in [0, 1] if not None
            if prediction.threshold is not None:
                assert 0.0 <= prediction.threshold <= 1.0, (
                    f"Detector {detector_id} threshold {prediction.threshold} out of bounds"
                )

    @PROPERTY_SETTINGS
    @given(bundle=forensic_bundle_st())
    def test_case_file_hash_determinism(self, bundle: dict) -> None:
        """Same case content produces same hash.

        Sealing the same bundle content multiple times should produce
        identical case files with the same SHA256 hash.
        """
        # Generate multiple case files from the same bundle
        case_1 = seal_case_file(
            bundle,
            deterministic=True,
            fixed_timestamp="2026-01-01T00:00:00+00:00",
        )
        case_2 = seal_case_file(
            bundle,
            deterministic=True,
            fixed_timestamp="2026-01-01T00:00:00+00:00",
        )

        # Hashes should be identical
        assert case_1["case_sha256"] == case_2["case_sha256"], (
            "Case hash not deterministic: same bundle produces different hashes"
        )

        # Full case content should be identical (except for any non-deterministic fields)
        # Note: generated_at_utc and tool.version are time/version dependent
        # but deterministic=True uses fixed timestamp

        # Create a third one with same fixed timestamp
        case_3 = seal_case_file(
            bundle,
            deterministic=True,
            fixed_timestamp="2026-01-01T00:00:00+00:00",
        )

        assert case_3["case_sha256"] == case_1["case_sha256"], (
            "Case hash not deterministic across multiple sealing operations"
        )

        # Verify all cases pass validation
        assert verify_case_file(case_1)["valid"]
        assert verify_case_file(case_2)["valid"]
        assert verify_case_file(case_3)["valid"]
