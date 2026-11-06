from __future__ import annotations

import unittest

from textforensics.conditions import InputConditions
from textforensics.detectors import DetectorPrediction
from textforensics.evidence import (
    EvidenceRecord,
    EvidenceRegistry,
    MetricEstimate,
    RunProvenance,
    SliceConditions,
    ValidationSlice,
)
from textforensics.trust import (
    TRUST_STATES,
    TrustDimension,
    TrustMap,
    build_trust_map,
)


def prediction(
    detector_id="detector",
    family="family",
    verdict="ai_like",
    score=0.8,
    min_words=None,
    supported_languages=("en",),
):
    return DetectorPrediction(
        schema="textforensics.detector-result/v2",
        detector_id=detector_id,
        detector_version="1",
        detector_family=family,
        execution="local",
        score=score,
        score_semantics="test native score",
        verdict=verdict,
        threshold=0.5,
        calibrated_ai_probability=None,
        calibration_id=None,
        supported_languages=list(supported_languages),
        min_words=min_words,
    )


def hex64(seed: int) -> str:
    return f"{seed:064x}"


def _slice(
    *,
    languages=("en",),
    domains=("general",),
    editing=("human_only",),
    n_human=200,
    n_ai=200,
    fpr=0.02,
    fpr_ci=(0.01, 0.03),
    generators=("g1", "g2", "g3"),
    generator_scope="multi",
    human_populations=("pop_a", "pop_b"),
):
    fpr_metric = MetricEstimate(
        value=fpr, n=n_human, ci_lower=fpr_ci[0], ci_upper=fpr_ci[1], method="wilson"
    )
    return ValidationSlice(
        slice_id="s1",
        conditions=SliceConditions(
            languages=languages,
            domains=domains,
            editing_regimes=editing,
            min_words=100,
            max_words=1000,
            generators=generators,
            generator_scope=generator_scope,
            human_populations=human_populations,
        ),
        n_human=n_human,
        n_ai=n_ai,
        metrics={
            "fpr": fpr_metric,
            "auroc": MetricEstimate(
                value=0.95, n=n_human + n_ai, ci_lower=0.94, ci_upper=0.96, method="wilson"
            ),
        },
        threshold=0.5,
    )


def _record(
    detector_id="a",
    detector_version="1",
    detector_family="fam1",
    slice_=None,
    evaluated_at="2026-11-01T00:00:00+00:00",
):
    return EvidenceRecord(
        evidence_id=f"ev-{detector_id}",
        detector_id=detector_id,
        detector_version=detector_version,
        detector_family=detector_family,
        evaluated_at_utc=evaluated_at,
        benchmark=__import__(
            "textforensics.evidence", fromlist=["BenchmarkProvenance"]
        ).BenchmarkProvenance(
            name="raid",
            version="1.0",
            fingerprint_sha256=hex64(1),
            split="test",
            license="MIT",
            artifact_path="data/raid.jsonl",
            artifact_sha256=hex64(2),
            contamination_controls=["disjoint_sample_ids"],
        ),
        slices=(slice_ or _slice(),),
        provenance=RunProvenance(
            git_sha="abc1234",
            command="textforensics benchmark",
            environment_sha256=hex64(3),
            executed_at_utc=evaluated_at,
            run_artifact_path="runs/1.json",
            run_artifact_sha256=hex64(4),
        ),
    )


def _registry(*records) -> EvidenceRegistry:
    return EvidenceRegistry(list(records))


def _stale_record(detector_id: str = "a") -> EvidenceRecord:
    """An evidence record old enough to fail the freshness window."""
    return _record(detector_id=detector_id, evaluated_at="2025-06-01T00:00:00+00:00")


def _declared_conditions(word_count: int = 200) -> InputConditions:
    """Conditions whose language/domain/editing are explicitly declared so
    that a matching registry slice can actually apply."""
    return InputConditions(
        schema="textforensics.input-conditions/v1",
        language="en",
        language_confidence="declared",
        script="latin",
        word_count=word_count,
        char_count=word_count * 5,
        length_band="medium",
        domain_genre="general",
        domain_confidence="declared",
        editing_regime="human_only",
        generator=None,
        human_population="unknown",
        declared={
            "source": "caller",
            "fields": ["language", "domain_genre", "editing_regime"],
            "values": {
                "language": "en",
                "domain_genre": "general",
                "editing_regime": "human_only",
            },
        },
        cues={},
        extraction_version="1",
    )


class TrustMapContractTests(unittest.TestCase):
    def test_states_are_the_declared_qualitative_set(self):
        self.assertEqual(
            TRUST_STATES,
            {"supported", "partial", "unknown", "out_of_scope"},
        )

    def test_dimension_and_map_serialize(self):
        dim = TrustDimension(
            dimension="text_length",
            state="supported",
            reason="ok",
            observed={"word_count": 100},
        )
        self.assertEqual(dim.to_dict()["dimension"], "text_length")
        tm = TrustMap(
            schema="textforensics.trust-map/v1",
            overall="mixed",
            dimensions=[dim],
        )
        self.assertEqual(tm.to_dict()["overall"], "mixed")

    def test_length_partial_when_metadata_admits_input_without_registry(self):
        # Detector metadata alone can only ever reach partial: held-out
        # validation evidence is required for supported.
        tm = build_trust_map(
            [prediction(min_words=80)],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "partial")

    def test_length_supported_when_registry_matches(self):
        registry = _registry(_record(detector_id="detector"))
        tm = build_trust_map(
            [prediction(min_words=80)],
            word_count=200,
            robustness=[],
            registry=registry,
            conditions=_declared_conditions(),
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "supported")

    def test_length_partial_when_some_detectors_unsupported(self):
        tm = build_trust_map(
            [prediction("a", min_words=80), prediction("b", "fam2", min_words=400)],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "partial")

    def test_length_out_of_scope_when_below_all_minima(self):
        tm = build_trust_map(
            [prediction("a", min_words=80), prediction("b", "fam2", min_words=400)],
            word_count=40,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "out_of_scope")

    def test_length_unknown_when_no_minimum_declared(self):
        tm = build_trust_map(
            [prediction("a")],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "text_length")
        self.assertEqual(dim.state, "unknown")

    def test_diversity_supported_with_two_families_and_no_failures(self):
        tm = build_trust_map(
            [prediction("a", "fam1"), prediction("b", "fam2")],
            word_count=200,
            robustness=[],
            failure_count=0,
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "supported")

    def test_diversity_partial_with_one_family(self):
        tm = build_trust_map(
            [prediction("a", "fam1")],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "partial")

    def test_diversity_partial_when_detectors_failed(self):
        tm = build_trust_map(
            [prediction("a", "fam1"), prediction("b", "fam2")],
            word_count=200,
            robustness=[],
            failure_count=1,
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "partial")

    def test_diversity_unknown_with_no_observations(self):
        tm = build_trust_map(
            [],
            word_count=200,
            robustness=[],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "unknown")

    def test_stability_supported_when_all_verdicts_hold(self):
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.05,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "supported")

    def test_stability_partial_when_verdict_flips(self):
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 0.75,
                "native_score_range": 0.2,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "partial")

    def test_stability_unknown_without_probes(self):
        tm = build_trust_map([prediction("a")], word_count=200, robustness=[])
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "unknown")

    def test_overall_is_insufficient_when_many_dimensions_unknown(self):
        tm = build_trust_map(
            [prediction("a")],
            word_count=200,
            robustness=[],
        )
        self.assertEqual(tm.overall, "insufficient")

    def test_overall_is_mixed_with_some_unknown(self):
        # With a stale-but-present registry the evidence dimensions are
        # partial (freshness fails) while the live dimensions are supported,
        # so overall is mixed.
        registry = _registry(
            _record(detector_id="a", evaluated_at="2025-06-01T00:00:00+00:00"),
            _record(detector_id="b", evaluated_at="2025-06-01T00:00:00+00:00"),
        )
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.0,
            }
        ]
        tm = build_trust_map(
            [prediction("a", "fam1"), prediction("b", "fam2")],
            word_count=200,
            robustness=robustness,
            registry=registry,
            conditions=_declared_conditions(),
        )
        self.assertEqual(tm.overall, "mixed")
        partial = sum(d.state == "partial" for d in tm.dimensions)
        self.assertGreaterEqual(partial, 3)

    def test_overall_is_strong_only_when_no_unknown_and_no_partial(self):
        # With a registry that covers every evidence dimension and live
        # dimensions fully supported, overall reaches strong.
        registry = _registry(_record(detector_id="a"), _record(detector_id="b"))
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.0,
            },
            {
                "detector_id": "b",
                "verdict_stability": 1.0,
                "native_score_range": 0.0,
            },
        ]
        tm = build_trust_map(
            [
                prediction("a", "fam1", min_words=80),
                prediction("b", "fam2", min_words=80),
            ],
            word_count=200,
            robustness=robustness,
            registry=registry,
            conditions=_declared_conditions(),
        )
        # Nine of ten dimensions are supported; temporal_version_stability is
        # partial because no longitudinal drift snapshots are registered, so
        # overall is mixed, not strong.  Strong remains unreachable today.
        self.assertEqual(tm.overall, "mixed")
        self.assertEqual(sum(d.state == "supported" for d in tm.dimensions), len(tm.dimensions) - 1)

    def test_overall_is_insufficient_without_registry(self):
        # Without a registry every evidence dimension is unknown and no
        # benign-stability probes are supplied, so overall is insufficient.
        tm = build_trust_map(
            [prediction("a", "fam1")],
            word_count=200,
            robustness=[],
        )
        self.assertEqual(tm.overall, "insufficient")

    def test_trust_map_is_not_an_authorship_probability(self):
        tm = build_trust_map([prediction("a")], word_count=200, robustness=[])
        self.assertTrue(
            any(
                "not probability of authorship" in limitation.lower()
                for limitation in tm.limitations
            )
        )


if __name__ == "__main__":
    unittest.main()
