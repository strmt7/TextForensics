from __future__ import annotations

import unittest

from textforensics.conditions import InputConditions
from textforensics.detectors import DetectorPrediction
from textforensics.evidence import (
    DetectorCoverage,
    DimensionCoverage,
    EvidenceRecord,
    EvidenceRegistry,
    MetricEstimate,
    RunProvenance,
    SliceConditions,
    ValidationSlice,
)
from textforensics.policy import (
    CapabilityClaim,
    CapabilityLedger,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
)
from textforensics.trust import (
    EVIDENCE_DIMENSIONS,
    TRUST_DIMENSIONS,
    TRUST_STATES,
    TrustDimension,
    TrustMap,
    _aggregate_evidence_dimension,
    _coverage_counts,
    _overall_state,
    _parse_row_completeness,
    _stability_dimension,
    assess_trust_map,
    build_trust_map,
    trust_map_from_capability_ledger,
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
            set(TRUST_STATES),
            {"supported", "partial", "unknown", "out_of_scope"},
        )
        # TRUST_STATES is an ordered tuple (not a frozenset) on purpose:
        # _coverage_counts() iterates it, so trust_map.coverage key order
        # is deterministic across processes (hash randomisation must not
        # change output ordering).
        self.assertEqual(
            list(TRUST_STATES),
            ["supported", "partial", "unknown", "out_of_scope"],
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


def _dim(state: str, dimension: str) -> TrustDimension:
    return TrustDimension(dimension=dimension, state=state, reason="test")


def _overall_from_states(states) -> str:
    """Drive the private overall-state rule with one state per dimension."""
    assert len(states) == len(TRUST_DIMENSIONS)
    return _overall_state(
        [_dim(state, name) for state, name in zip(states, TRUST_DIMENSIONS, strict=True)]
    )


def _coverage_row(
    detector_id: str,
    *,
    state: str = "supported",
    reason: str,
    observed: dict | None = None,
) -> DetectorCoverage:
    """One DetectorCoverage row whose ``language`` dimension carries the
    given state/reason/observed payload; every other evidence dimension is
    unknown, so aggregation behaviour is attributable to ``language``."""
    dimensions = {
        name: DimensionCoverage(
            dimension=name,
            state=state if name == "language" else "unknown",
            reason=reason if name == "language" else "no coverage",
            observed=dict(observed) if name == "language" and observed else {},
        )
        for name in EVIDENCE_DIMENSIONS
    }
    return DetectorCoverage(
        detector_id=detector_id,
        detector_version="1",
        detector_family="fam",
        dimensions=dimensions,
    )


def _ledger_claim(
    detector_id: str = "a",
    capability: str = "language",
    tier: EvidenceTier = EvidenceTier.VALIDATED,
    valid_until: str | None = None,
) -> CapabilityClaim:
    return CapabilityClaim(
        detector_id=detector_id,
        capability=capability,
        tier=tier,
        evidence=[
            EvidenceRef(
                label=EvidenceLabel.EXECUTED,
                tier=tier,
                artifact="runs/1.json",
            )
        ],
        valid_until=valid_until,
    )


def _ledger_with(*claims: CapabilityClaim) -> CapabilityLedger:
    ledger = CapabilityLedger()
    for claim in claims:
        ledger.register(claim)
    return ledger


class TrustMutationKillTests(unittest.TestCase):
    """Behaviour tests that distinguish the original trust.py from each
    surviving cosmic-ray mutant in the Phase 5 wave-2 batch (indices
    [0]-[53] of the classification table).  Each test asserts real,
    observable behaviour — an error message, a dimension state, a count,
    or a summary value — never merely that a call succeeds."""

    # -- TrustMap coverage validation ([0], [1]) -------------------------

    def test_coverage_missing_state_message_names_the_missing_state(self):
        # Mutant [0] negates `if missing:`: the ValueError is still raised
        # but its message no longer names the missing state.
        dim = TrustDimension(dimension="text_length", state="supported", reason="ok")
        with self.assertRaisesRegex(ValueError, r"missing state\(s\): out_of_scope"):
            TrustMap(
                schema="textforensics.trust-map/v2",
                overall="mixed",
                dimensions=[dim],
                coverage={"supported": 1, "partial": 0, "unknown": 0},
            )

    def test_coverage_extra_state_message_names_the_extra_state(self):
        # Mutant [1] negates `if extra:`: the ValueError is still raised
        # but its message no longer names the unexpected state.
        dim = TrustDimension(dimension="text_length", state="supported", reason="ok")
        with self.assertRaisesRegex(ValueError, r"unexpected state\(s\): stale"):
            TrustMap(
                schema="textforensics.trust-map/v2",
                overall="mixed",
                dimensions=[dim],
                coverage={
                    "supported": 1,
                    "partial": 0,
                    "unknown": 0,
                    "out_of_scope": 0,
                    "stale": 0,
                },
            )

    # -- Benign-stability dimension ([2], [15], [16], [17], [33], [39],
    #    [48], [49], [50]) ------------------------------------------------

    def test_stability_partial_when_drift_exceeds_declared_bound_assess(self):
        # Mutant [2] negates the drift-bound check so drift is never
        # flagged; mutant [33] raises the assess_trust_map default bound
        # from 0.10 to 1.1 so a 0.20 drift passes.  Both must stay partial.
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.20,
            }
        ]
        tm = assess_trust_map(_declared_conditions(), [prediction("a")], robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "partial")

    def test_stability_partial_when_drift_exceeds_declared_bound_build(self):
        # Same drift case through the build_trust_map default bound;
        # mutant [39] raises that default from 0.10 to 1.1.
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.20,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "partial")

    def test_stability_floor_below_one_is_partial_even_when_drift_is_within_bound(
        self,
    ):
        # Verdict floor 0.75 with drift 0.05 inside the 0.10 bound: the
        # original is partial because the floor is below 1.0.  Mutant
        # [15] lowers the floor threshold to 0.0, mutant [49] turns the
        # first `and` into `or`, and mutant [50] turns the second `and`
        # into `or`; all three would report supported.
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 0.75,
                "native_score_range": 0.05,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "partial")

    def test_stability_floor_is_rounded_to_six_places(self):
        # Mutant [16] rounds to 7 places and mutant [17] to 5 places;
        # the observed floor must be round(0.1234567, 6) == 0.123457.
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 0.1234567,
                "native_score_range": 0.05,
            }
        ]
        tm = build_trust_map([prediction("a")], word_count=200, robustness=robustness)
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.observed["verdict_stability_floor"], 0.123457)

    def test_stability_bool_range_is_unknown_drift(self):
        # A boolean native_score_range is not a numeric range: drift is
        # unknown, so the dimension is partial even with a perfect
        # verdict floor and no drift bound.  Mutant [48] turns the
        # `and` in the numeric check into `or`, so True counts as a
        # known range of 1.0 and the dimension reports supported.
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": True,
            }
        ]
        tm = build_trust_map(
            [prediction("a")],
            word_count=200,
            robustness=robustness,
            max_native_drift=None,
        )
        dim = next(d for d in tm.dimensions if d.dimension == "benign_stability")
        self.assertEqual(dim.state, "partial")

    # -- Evidence aggregation ([3], [4], [18], [19], [20], [51]) ---------

    def test_aggregate_copies_per_detector_observed(self):
        # Mutant [3] negates `if dimension.observed:`: observed payloads
        # from detectors are dropped and empty ones are copied instead.
        rows = (
            _coverage_row("a", reason="language reason from detector a", observed={"fpr": 0.02}),
            _coverage_row("b", reason="language reason from detector b"),
        )
        dim = _aggregate_evidence_dimension("language", rows)
        self.assertEqual(dim.observed["detector_observed"], {"a": {"fpr": 0.02}})

    def test_aggregate_single_state_uses_first_detector_reason(self):
        # When every detector agrees on the state, the reason is the
        # first detector's reason.  Mutant [4] negates the single-state
        # check, mutants [18]/[19] change `== 1` to `== 2`/`== 0`, mutant
        # [20] takes rows[-1] instead of rows[0], and mutant [51] turns
        # the `and` into `or` (yielding the state string "supported"
        # instead of the reason); all five change the reason.
        rows = (
            _coverage_row("a", reason="language reason from detector a"),
            _coverage_row("b", reason="language reason from detector b"),
        )
        dim = _aggregate_evidence_dimension("language", rows)
        self.assertEqual(dim.state, "supported")
        self.assertEqual(dim.reason, "language reason from detector a")

    # -- Overall state ([5], [21], [22], [23], [24], [25], [26], [52], [53])

    def test_overall_insufficient_when_no_supported_or_partial(self):
        # 0 supported, 0 partial, 3 unknown: insufficient.  Mutant [5]
        # negates the first comparison, mutant [21] changes supported
        # 0 to 1, mutant [22] to -1, mutant [23] changes partial 0 to
        # 1, mutant [24] to -1; all five fall through to "mixed".
        states = [
            "unknown",
            "unknown",
            "unknown",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
        ]
        self.assertEqual(_overall_from_states(states), "insufficient")

    def test_overall_mixed_when_some_supported_and_no_partial(self):
        # 5 supported, 0 partial: mixed, not insufficient.  Mutant [5]
        # (negated first comparison) and mutant [52] (`and` -> `or`)
        # both return "insufficient" here.
        states = [
            "supported",
            "supported",
            "supported",
            "supported",
            "supported",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
        ]
        self.assertEqual(_overall_from_states(states), "mixed")

    def test_overall_insufficient_when_no_supported_and_many_unknown(self):
        # 0 supported, 1 partial, 4 unknown: insufficient via the
        # unknown>=4 rule.  Mutant [25] raises the threshold to 5 and
        # falls through to "mixed".
        states = [
            "partial",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
        ]
        self.assertEqual(_overall_from_states(states), "insufficient")

    def test_overall_mixed_when_no_supported_but_few_unknown(self):
        # 0 supported, 1 partial, 3 unknown: mixed.  Mutant [26]
        # lowers the unknown threshold to 3 and returns "insufficient".
        states = [
            "partial",
            "unknown",
            "unknown",
            "unknown",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
        ]
        self.assertEqual(_overall_from_states(states), "mixed")

    def test_overall_mixed_when_supported_but_many_unknown(self):
        # 1 supported, 0 partial, 4 unknown: mixed.  Mutant [53]
        # (`and` -> `or` on the unknown rule) returns "insufficient"
        # because unknown >= 4 alone triggers it, and mutant [52]
        # returns "insufficient" because partial == 0 alone triggers it.
        states = [
            "supported",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
            "out_of_scope",
        ]
        self.assertEqual(_overall_from_states(states), "mixed")

    # -- Coverage counts ([27], [28], [29], [30]) ------------------------

    def test_coverage_counts_are_exact(self):
        # Mutant [27] starts each count at 1, mutant [28] at -1,
        # mutant [29] increments by 2, mutant [30] increments by 0.
        dims = [
            _dim("supported", "language"),
            _dim("supported", "text_length"),
            _dim("partial", "domain_genre"),
        ]
        self.assertEqual(
            _coverage_counts(dims),
            {"supported": 2, "partial": 1, "unknown": 0, "out_of_scope": 0},
        )

    # -- assess_trust_map validation and defaults ([6], [7], [8], [9],
    #    [31], [32], [34], [35], [36], [37], [38]) -----------------------

    def test_assess_rejects_negative_max_native_drift(self):
        # Mutant [6] negates the `is not None` check so the guard never
        # fires; mutant [36] changes `< 0` to `< -1` so -0.5 passes.
        with self.assertRaisesRegex(ValueError, "non-negative"):
            assess_trust_map(
                _declared_conditions(),
                [prediction("a")],
                max_native_drift=-0.5,
            )

    def test_assess_rejects_negative_failure_count(self):
        # Mutant [35] changes `< 0` to `< -1` so -1 passes validation.
        with self.assertRaisesRegex(ValueError, "non-negative"):
            assess_trust_map(_declared_conditions(), [prediction("a")], failure_count=-1)

    def test_diversity_supported_with_two_families_under_defaults(self):
        # Two families and the default failure_count of 0 give a
        # supported diversity dimension.  Mutant [31] changes the
        # default failure_count to 1 (diversity becomes partial),
        # mutant [32] changes it to -1 and mutant [34] changes the
        # default max_native_drift to -0.9 (both raise ValueError).
        tm = assess_trust_map(
            _declared_conditions(),
            [prediction("a", "fam1"), prediction("b", "fam2")],
        )
        dim = next(d for d in tm.dimensions if d.dimension == "detector_diversity")
        self.assertEqual(dim.state, "supported")

    def test_registry_verification_failure_is_recorded_as_limitation(self):
        # Mutant [7] negates `registry_verified is False`: the failure
        # limitation is omitted for False and added for True/None.
        tm = assess_trust_map(_declared_conditions(), [prediction("a")], registry_verified=False)
        self.assertIn("Evidence artifact verification failed.", tm.limitations)

    def test_registry_verification_status_verified(self):
        # Mutant [8] negates the `is True` branch: a verified registry
        # is reported as "not_checked" instead of "verified".
        registry = _registry(_record(detector_id="a"))
        tm = assess_trust_map(
            _declared_conditions(),
            [prediction("a", "fam1")],
            registry=registry,
            registry_verified=True,
        )
        summary = tm.evidence_registry
        self.assertIsNotNone(summary)
        self.assertTrue(summary["verified"])
        self.assertEqual(summary["verification_status"], "verified")

    def test_registry_verification_status_failed(self):
        # Mutant [9] negates the `is False` branch: a failed registry
        # is reported as "not_checked" instead of "failed".
        registry = _registry(_record(detector_id="a"))
        tm = assess_trust_map(
            _declared_conditions(),
            [prediction("a", "fam1")],
            registry=registry,
            registry_verified=False,
        )
        summary = tm.evidence_registry
        self.assertIsNotNone(summary)
        self.assertFalse(summary["verified"])
        self.assertEqual(summary["verification_status"], "failed")

    def test_registry_summary_reports_zero_records_without_registry(self):
        # Mutants [37]/[38] change the no-registry record_count from 0
        # to 1 / -1.
        tm = assess_trust_map(_declared_conditions(), [prediction("a")])
        summary = tm.evidence_registry
        self.assertIsNotNone(summary)
        self.assertEqual(summary["record_count"], 0)
        self.assertEqual(summary["verification_status"], "not_checked")

    # -- build_trust_map defaults ([40], [42], [43]) --------------------

    def test_build_accepts_zero_word_count(self):
        # 0 is a non-negative word count.  Mutant [40] changes the
        # guard to `< 1`, so word_count=0 is rejected.
        tm = build_trust_map([], word_count=0)
        self.assertIsNotNone(tm.input_conditions)
        self.assertEqual(tm.input_conditions["word_count"], 0)

    def test_build_synthesised_conditions_have_zero_char_count(self):
        # Synthesised conditions carry char_count=0.  Mutant [42]
        # changes it to 1 and mutant [43] to -1.
        tm = build_trust_map([prediction("a")], word_count=200)
        self.assertIsNotNone(tm.input_conditions)
        self.assertEqual(tm.input_conditions["char_count"], 0)

    # -- Capability-ledger view ([10], [11], [12], [13], [45]) -----------

    def test_ledger_length_capability_maps_to_text_length_dimension(self):
        # Mutant [14] negates the equality in _legacy_dimension_name:
        # `not normalized == prefix or startswith(...)` is true for the
        # first alias whose prefix differs, so every capability maps to
        # "language" (the first alias) instead of its own dimension.
        # A "length" claim must land on text_length, not language.
        ledger = _ledger_with(_ledger_claim(capability="length"))
        tm = trust_map_from_capability_ledger(ledger)
        dim = tm.dimension("text_length")
        self.assertIsNotNone(dim)
        self.assertEqual(dim.state, "supported")
        self.assertIsNone(tm.dimension("language"))
        self.assertEqual(tm.overall, "strong")

    def test_ledger_expiry_limitation_names_claim_and_date(self):
        # Mutant [10] negates `if claim.valid_until:`: the expiry
        # limitation is omitted for dated claims (and added, with
        # "None", for undated ones).
        ledger = _ledger_with(_ledger_claim(valid_until="2027-01-01"))
        tm = trust_map_from_capability_ledger(ledger)
        dim = tm.dimension("language")
        self.assertIsNotNone(dim)
        self.assertIn("Claim for language expires 2027-01-01.", dim.limitations)

    def test_ledger_validated_claim_is_supported_and_overall_strong(self):
        # A single VALIDATED claim maps to a supported dimension and a
        # strong overall.  Mutant [11] negates the `not relevant`
        # check so every dimension becomes unknown; mutant [12]
        # negates the empty-dimensions check so a non-empty ledger
        # reports insufficient; mutant [13] negates the
        # out_of_scope_count term so any ledger reports insufficient;
        # mutant [45] changes max(1, ...) to max(0, ...) so the
        # single-dimension case (unknown 0 >= 0) reports insufficient.
        ledger = _ledger_with(_ledger_claim())
        tm = trust_map_from_capability_ledger(ledger)
        dim = tm.dimension("language")
        self.assertIsNotNone(dim)
        self.assertEqual(dim.state, "supported")
        self.assertEqual(tm.overall, "strong")


# ---------------------------------------------------------------------------
# W1 follow-up mutation kills (audit-w1-worker-f)
#
# Each test kills the W1 new/changed-code mutants Worker E proved
# killable (audit-w1-e-stop-draft.py / audit-w1-e-probe-results.json,
# 148/148). Test IDs TR-01..TR-07, TR-02b, TR-04b match the STOP draft;
# TR-04 was withdrawn by Worker E (no kill — only the exception
# message distinguishes the mutant; that is TR-04b).
# ---------------------------------------------------------------------------


class TrustW1FollowUpMutationKillTests(unittest.TestCase):
    def test_stability_excluded_rows_visible(self):
        # TR-01: 7 mutants in _stability_dimension (excluded counters).
        rows = [
            {
                "detector_id": "d1",
                "verdict_stability": 1.0,
                "completeness": {
                    "selected": 4,
                    "attempted": 2,
                    "succeeded": 2,
                    "abstained": 0,
                    "failed": 0,
                },
            },  # incomplete
            {"detector_id": "d2", "verdict_stability": "high"},  # non-numeric
            {
                "detector_id": "d3",
                "verdict_stability": 1.0,
                "native_score_range": 0.1,
            },  # usable, legacy
        ]
        dim = _stability_dimension(rows, max_native_drift=None)
        self.assertEqual(dim.observed["incomplete_probe_sets_excluded"], 1)
        self.assertIn("1 incomplete or failed probe set(s) were excluded", dim.limitations[-1])
        self.assertEqual(dim.state, "supported")
        # And with NO usable rows, the reason names the excluded count.
        dim2 = _stability_dimension(rows[:2], max_native_drift=None)
        self.assertEqual(dim2.state, "unknown")
        self.assertIn("1 probe set(s) did not complete successfully", dim2.reason)
        self.assertEqual(dim2.observed["incomplete_probe_sets_excluded"], 1)

    def test_stability_continues_past_bad_rows(self):
        # TR-02: 5 mutants in _stability_dimension (row-loop continue).
        rows = [
            {
                "detector_id": "bad1",
                "verdict_stability": 1.0,
                "completeness": {
                    "selected": 4,
                    "attempted": 4,
                    "succeeded": 3,
                    "abstained": 0,
                    "failed": 1,
                },
            },  # not eligible
            {"detector_id": "bad2", "verdict_stability": "high"},  # non-numeric
            {
                "detector_id": "bad3",
                "completeness": {
                    "selected": "x",
                    "attempted": 1,
                    "succeeded": 1,
                    "abstained": 0,
                    "failed": 0,
                },
            },  # unparseable
            {
                "detector_id": "good",
                "verdict_stability": 1.0,
                "native_score_range": 0.1,
            },  # usable legacy row AFTER the bad rows
        ]
        dim = _stability_dimension(rows, max_native_drift=None)
        self.assertEqual(dim.state, "supported")
        self.assertEqual(dim.observed["incomplete_probe_sets_excluded"], 2)

    def test_stability_skips_non_mapping_rows(self):
        # TR-02b: 1 mutant (non-mapping-row continue -> break).
        rows = [
            "not-a-mapping",
            {
                "detector_id": "good",
                "verdict_stability": 1.0,
                "native_score_range": 0.1,
            },
        ]
        dim = _stability_dimension(rows, max_native_drift=None)
        self.assertEqual(dim.state, "supported")  # string skipped, good row usable
        self.assertEqual(
            dim.observed["detectors"][0],
            {"detector_id": "good", "native_score_range": 0.1},
        )

    def test_stability_drift_loop_continues_past_unknown_range(self):
        # TR-03: 1 mutant (drift-loop continue -> break).
        rows = [
            {"detector_id": "d1", "verdict_stability": 1.0},  # no range -> unknown
            {
                "detector_id": "d2",
                "verdict_stability": 1.0,
                "native_score_range": 0.9,
            },  # over the bound
        ]
        dim = _stability_dimension(rows, max_native_drift=0.5)
        self.assertEqual(dim.state, "partial")  # d2 exceeds the bound
        self.assertEqual(len(dim.observed["detectors"]), 2)  # break mutant drops d2
        self.assertEqual(
            dim.observed["detectors"][1],
            {"detector_id": "d2", "native_score_range": 0.9},
        )

    def test_parse_row_completeness_rejects_bad_counts(self):
        # TR-04: kills NO mutant (Worker E, probe round 1) — the
        # ReplaceOrWithAnd:2 mutant's guard never fires, but
        # CompletenessAccounting.__post_init__ still raises ValueError
        # for the same inputs, so the test passes either way. It is
        # landed anyway as a behaviour pin for the rejection itself;
        # the message distinguisher is TR-04b below.
        with self.assertRaises(ValueError):
            _parse_row_completeness(
                {
                    "completeness": {
                        "selected": True,
                        "attempted": 1,
                        "succeeded": 1,
                        "abstained": 0,
                        "failed": 0,
                    }
                }
            )
        with self.assertRaises(ValueError):
            _parse_row_completeness(
                {
                    "completeness": {
                        "selected": 1.5,
                        "attempted": 1,
                        "succeeded": 1,
                        "abstained": 0,
                        "failed": 0,
                    }
                }
            )
        # No completeness record at all is None, not an error.
        self.assertIsNone(_parse_row_completeness({"detector_id": "d"}))

    def test_parse_row_completeness_rejection_message(self):
        # TR-04b (tier 2): 1 mutant (bool or not-int -> and). The ONLY
        # distinguisher is the exception message: the original raises
        # 'robustness completeness selected must be an integer', while
        # the mutant's guard never fires and CompletenessAccounting
        # raises 'selected must be a non-negative integer.'
        with self.assertRaisesRegex(
            ValueError, "robustness completeness selected must be an integer"
        ):
            _parse_row_completeness(
                {
                    "completeness": {
                        "selected": True,
                        "attempted": 1,
                        "succeeded": 1,
                        "abstained": 0,
                        "failed": 0,
                    }
                }
            )
        with self.assertRaisesRegex(
            ValueError, "robustness completeness selected must be an integer"
        ):
            _parse_row_completeness(
                {
                    "completeness": {
                        "selected": 1.5,
                        "attempted": 1,
                        "succeeded": 1,
                        "abstained": 0,
                        "failed": 0,
                    }
                }
            )

    def test_stability_rejects_bad_verdict_values(self):
        # TR-05: 1 mutant (bool or not-(int,float) -> and).
        dim = _stability_dimension(
            [{"detector_id": "d", "verdict_stability": "high"}],
            max_native_drift=None,
        )
        self.assertEqual(dim.state, "unknown")  # str verdict skipped, no usable rows
        dim2 = _stability_dimension(
            [{"detector_id": "d", "verdict_stability": True}],
            max_native_drift=None,
        )
        self.assertEqual(dim2.state, "unknown")  # bool verdict skipped too

    def test_stability_drift_boundary_is_exclusive(self):
        # TR-06: 1 mutant (value > max -> >=).
        rows = [{"detector_id": "d", "verdict_stability": 1.0, "native_score_range": 0.5}]
        dim = _stability_dimension(rows, max_native_drift=0.5)
        self.assertEqual(dim.state, "supported")  # drift at the bound is within it
        rows2 = [
            {
                "detector_id": "d",
                "verdict_stability": 1.0,
                "native_score_range": 0.500001,
            }
        ]
        self.assertEqual(_stability_dimension(rows2, max_native_drift=0.5).state, "partial")

    def test_stability_floor_above_one_is_supported(self):
        # TR-07 (tier 2): 1 mutant (verdict_floor >= 1.0 -> == 1.0).
        rows = [{"detector_id": "d", "verdict_stability": 1.5, "native_score_range": 0.1}]
        dim = _stability_dimension(rows, max_native_drift=None)
        self.assertEqual(dim.state, "supported")  # floor 1.5 >= 1.0


if __name__ == "__main__":
    unittest.main()
