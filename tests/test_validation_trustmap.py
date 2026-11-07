"""Tests for Trust Map v3 support and the U1 derivation engine (Package B).

All records here are synthetic fixtures (dataset_name "synthetic-test",
clearly invented values). No dataset data, no raw text, and no measured
numbers appear in these tests.
"""

from __future__ import annotations

import importlib.util
import unittest

from textforensics.conditions import InputConditions, length_band
from textforensics.detectors import DetectorPrediction
from textforensics.schema import validate_trust_map
from textforensics.trust import (
    TRUST_SCHEMA,
    TRUST_SCHEMA_V3,
    TRUST_STATES,
    TRUST_STATES_V3,
    TrustDimension,
    TrustMap,
    _coverage_counts,
    assess_trust_map,
)
from textforensics.validation import (
    CONTAMINATED_LABEL,
    CONTAMINATION_UNKNOWN_LABEL,
    INPUT_EDITING_REGIME_MAP,
    ValidationRecord,
    ValidationRegistry,
    _overall_state_v3,
    compute_signature,
    derive_trust_map,
    empty_validation_registry,
)

DETECTOR_ID = "textforensics/builtin-heuristic"
VERSION = "0.1.0"
NOW = "2026-11-06T00:00:00+00:00"
RECORD_ID = "evr-20261106-synthetic-test-builtin-heuristic"


def make_record_dict(
    *,
    status: str = "supported",
    record_id: str | None = None,
    detector_id: str = DETECTOR_ID,
    detector_version: str = VERSION,
    language: str = "en",
    domain: tuple[str, ...] = ("synthetic",),
    genre: str | None = "synthetic-test",
    editing_regime: str = "raw",
    generator_families: tuple[str, ...] = ("synthetic",),
    populations: tuple[str, ...] = ("synthetic",),
    floor_words: int = 80,
    max_words: int | None = None,
    n_human: int = 120,
    n_ai: int = 120,
    contamination: str = "no",
    fpr_value: float = 0.02,
    fpr_ci: tuple[float, float] | None = (0.0, 0.05),
    due: str = "2027-02-04",
    demoted_by: str | None = None,
) -> dict:
    """Build a complete synthetic record dict, signed with compute_signature."""
    metric = {
        "value": 0.8,
        "n": n_human + n_ai,
        "ci_lower": 0.7,
        "ci_upper": 0.9,
        "method": "bootstrap, 1000 resamples, seed 20261106",
    }
    fpr_metric = {
        "value": fpr_value,
        "n": n_human,
        "ci_lower": None if fpr_ci is None else fpr_ci[0],
        "ci_upper": None if fpr_ci is None else fpr_ci[1],
        "method": "bootstrap, 1000 resamples, seed 20261106",
        "operating_point": ("builtin-heuristic native verdict (analyze_text); no score threshold"),
    }
    record = {
        "schema": "textforensics.evidence-record/v1",
        "record_id": record_id or RECORD_ID,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "detector_family": "stylometric-heuristic",
        "calibration_id": None,
        "status": status,
        "supersedes": None,
        "regime": {
            "language": language,
            "script": "Latn",
            "language_variety": None,
            "length_bucket": {
                "min_words": floor_words,
                "max_words": max_words,
                "floor_words": floor_words,
                "measured_min_words": floor_words + 5,
                "measured_median_words": floor_words + 40,
                "measured_max_words": floor_words + 320,
            },
            "domain": list(domain),
            "genre": genre,
            "generator": {
                "families": list(generator_families),
                "vintage": "synthetic",
                "current_as_of": "2026-11-06",
            },
            "editing_regime": editing_regime,
            "human_population": {
                "populations": list(populations),
                "determined_how": "synthetic test fixture",
            },
            "attack_slice": None,
        },
        "data": {
            "dataset_name": "synthetic-test",
            "dataset_version": "1.0",
            "file_sha256": "a" * 64,
            "row_hash_method": "sha256 of normalised text (benchmark fingerprint)",
            "split": "test",
            "split_role": "test",
            "n_human": n_human,
            "n_ai": n_ai,
            "licence": "MIT",
            "licence_reference": "https://example.invalid/synthetic-test-licence",
            "contamination_flag": contamination,
            "near_duplicate_rate": None,
            "near_duplicate_method": None,
        },
        "run": {
            "run_id": "EV-20261106-synthetic-test",
            "run_artifact": "docs/evidence/runs/EV-20261106-synthetic-test.json",
            "run_artifact_sha256": "b" * 64,
            "run_date": "2026-11-06",
            "runner": "synthetic-test",
            "code_version": "a" * 40,
            "dependency_lock_sha": None,
            "hardware": "synthetic-test",
            "runtime": "CPython 3.12.3 on Linux",
            "seeds": {"bootstrap_seed": 20261106},
            "command": "python scripts/seed_validation.py --synthetic-test",
            "drops_manifest": [],
            "reporting_rules": "synthetic test fixture",
        },
        "metrics": [
            {
                "slice_id": "synthetic-test",
                "n_human": n_human,
                "n_ai": n_ai,
                "auroc": dict(metric),
                "tpr_at_fpr_0_01": dict(metric, value=0.5, n=n_ai, ci_lower=0.4, ci_upper=0.6),
                "tpr_at_fpr_0_05": dict(metric, value=0.7, n=n_ai, ci_lower=0.6, ci_upper=0.8),
                "fpr_native": fpr_metric,
                "coverage": 1.0,
                "abstention_rate": 0.0,
                "worst_slice": True,
            }
        ],
        "limits": {
            "known_failure_modes": ["synthetic test fixture"],
            "limitations": ["not validated for anything real"],
            "next_revalidation_due": due,
            "appeal_note": "synthetic test fixture",
            "reviewer": None,
            "review_date": None,
            "demoted_by": demoted_by,
        },
        "signature": "0" * 64,
    }
    record["signature"] = compute_signature(record)
    return record


def make_conditions(**overrides) -> InputConditions:
    """Build input conditions matching the default synthetic record."""
    word_count = overrides.get("word_count", 120)
    base = {
        "schema": "textforensics.input-conditions/v1",
        "language": "en",
        "language_confidence": "high",
        "script": "Latn",
        "word_count": word_count,
        "char_count": word_count * 5,
        "length_band": length_band(word_count),
        "domain_genre": "synthetic",
        "domain_confidence": "high",
        "editing_regime": "machine_only",
        "generator": "synthetic",
        "human_population": "synthetic",
        "declared": {"source": "caller", "fields": ["language"], "values": {}},
        "cues": {},
        "extraction_version": "1",
    }
    base.update(overrides)
    return InputConditions(**base)


def registry_of(*record_dicts: dict) -> ValidationRegistry:
    return ValidationRegistry([ValidationRecord.from_dict(item) for item in record_dicts])


def derive(conditions: InputConditions, registry: ValidationRegistry, **overrides) -> TrustMap:
    params: dict = {
        "detector_id": DETECTOR_ID,
        "detector_version": VERSION,
        "now": NOW,
    }
    params.update(overrides)
    return derive_trust_map(conditions, registry, **params)


def prediction(detector_id: str = "detector", family: str = "family") -> DetectorPrediction:
    return DetectorPrediction(
        schema="textforensics.detector-result/v2",
        detector_id=detector_id,
        detector_version="1",
        detector_family=family,
        execution="local",
        score=0.8,
        score_semantics="test native score",
        verdict="ai_like",
        threshold=0.5,
    )


class TrustV3SupportTests(unittest.TestCase):
    def test_v3_constants(self):
        self.assertEqual(TRUST_SCHEMA_V3, "textforensics.trust-map/v3")
        self.assertEqual(TRUST_STATES_V3, TRUST_STATES + ("stale",))
        self.assertEqual(TRUST_STATES, ("supported", "partial", "unknown", "out_of_scope"))

    def test_dimension_accepts_stale(self):
        dim = TrustDimension(dimension="language", state="stale", reason="record is stale")
        self.assertEqual(dim.state, "stale")

    def test_dimension_still_rejects_unknown_state(self):
        with self.assertRaises(ValueError):
            TrustDimension(dimension="language", state="bogus", reason="x")

    def test_trust_map_accepts_v3_schema(self):
        dims = [TrustDimension(dimension="language", state="stale", reason="x")]
        trust_map = TrustMap(
            schema=TRUST_SCHEMA_V3,
            overall="mixed",
            dimensions=dims,
            coverage={
                "supported": 0,
                "partial": 0,
                "unknown": 0,
                "out_of_scope": 0,
                "stale": 1,
            },
        )
        self.assertEqual(trust_map.schema, TRUST_SCHEMA_V3)

    def test_trust_map_rejects_unknown_schema(self):
        with self.assertRaises(ValueError):
            TrustMap(schema="textforensics.trust-map/v9", overall="mixed", dimensions=[])

    def test_coverage_validation_is_schema_dependent(self):
        # v2 requires exactly the four v2 states.
        TrustMap(
            schema=TRUST_SCHEMA,
            overall="mixed",
            dimensions=[],
            coverage={"supported": 1, "partial": 0, "unknown": 0, "out_of_scope": 0},
        )
        with self.assertRaises(ValueError):
            TrustMap(
                schema=TRUST_SCHEMA,
                overall="mixed",
                dimensions=[],
                coverage={
                    "supported": 1,
                    "partial": 0,
                    "unknown": 0,
                    "out_of_scope": 0,
                    "stale": 0,
                },
            )
        # v3 requires exactly the five v3 states.
        with self.assertRaises(ValueError):
            TrustMap(
                schema=TRUST_SCHEMA_V3,
                overall="mixed",
                dimensions=[],
                coverage={
                    "supported": 1,
                    "partial": 0,
                    "unknown": 0,
                    "out_of_scope": 0,
                },
            )
        TrustMap(
            schema=TRUST_SCHEMA_V3,
            overall="mixed",
            dimensions=[],
            coverage={
                "supported": 1,
                "partial": 0,
                "unknown": 0,
                "out_of_scope": 0,
                "stale": 0,
            },
        )

    def test_coverage_counts_takes_states_tuple(self):
        dims = [
            TrustDimension(dimension="language", state="stale", reason="x"),
            TrustDimension(dimension="text_length", state="supported", reason="x"),
        ]
        counts = _coverage_counts(dims, TRUST_STATES_V3)
        self.assertEqual(
            counts,
            {"supported": 1, "partial": 0, "unknown": 0, "out_of_scope": 0, "stale": 1},
        )
        # The default is still the v2 states, so a stale dimension errors
        # there exactly as before (v2 maps never carry stale counts).
        with self.assertRaises(KeyError):
            _coverage_counts(dims)

    def test_v2_behaviour_unchanged(self):
        trust_map = assess_trust_map(make_conditions(), [], registry=None, now=NOW)
        self.assertEqual(trust_map.schema, TRUST_SCHEMA)
        self.assertEqual(
            set(trust_map.coverage),
            {"supported", "partial", "unknown", "out_of_scope"},
        )
        self.assertNotIn("stale", trust_map.coverage)


class DeriveSupportedTests(unittest.TestCase):
    def test_fully_matching_record_supports_seven_dimensions(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict()))
        self.assertEqual(trust_map.schema, TRUST_SCHEMA_V3)
        self.assertEqual(trust_map.overall, "mixed")
        states = {dim.dimension: dim.state for dim in trust_map.dimensions}
        for name in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
        ):
            self.assertEqual(states[name], "supported", name)
        # Temporal stability caps at partial from a single snapshot.
        self.assertEqual(states["temporal_version_stability"], "partial")
        self.assertIn("single snapshot", trust_map.dimension("temporal_version_stability").reason)
        # Live dimensions are unknown without observations.
        self.assertEqual(states["detector_diversity"], "unknown")
        self.assertEqual(states["benign_stability"], "unknown")
        self.assertEqual(
            trust_map.coverage,
            {"supported": 7, "partial": 1, "unknown": 2, "out_of_scope": 0, "stale": 0},
        )

    def test_every_evidence_dimension_cites_record_id(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict()))
        for name in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        ):
            dim = trust_map.dimension(name)
            assert dim is not None
            self.assertEqual(dim.evidence_refs, [RECORD_ID], name)

    def test_temporal_limitation_is_recorded(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict()))
        dim = trust_map.dimension("temporal_version_stability")
        assert dim is not None
        self.assertTrue(
            any("single snapshot" in item for item in dim.limitations),
            dim.limitations,
        )


class DeriveUnknownOutOfScopeTests(unittest.TestCase):
    def test_empty_registry_all_unknown_overall_insufficient(self):
        trust_map = derive(make_conditions(), empty_validation_registry())
        states = {dim.dimension: dim.state for dim in trust_map.dimensions}
        for name in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        ):
            self.assertEqual(states[name], "unknown", name)
        self.assertEqual(trust_map.overall, "insufficient")
        self.assertEqual(
            trust_map.coverage,
            {"supported": 0, "partial": 0, "unknown": 10, "out_of_scope": 0, "stale": 0},
        )
        self.assertTrue(
            any(DETECTOR_ID in item for item in trust_map.limitations),
            trust_map.limitations,
        )

    def test_records_for_other_detectors_only_all_unknown(self):
        other = registry_of(make_record_dict(detector_id="textforensics/other-detector"))
        trust_map = derive(make_conditions(), other)
        states = {dim.dimension: dim.state for dim in trust_map.dimensions}
        for name in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        ):
            self.assertEqual(states[name], "unknown", name)
        self.assertEqual(trust_map.overall, "insufficient")

    def test_language_und_is_unknown(self):
        trust_map = derive(
            make_conditions(language="und", language_confidence="low"),
            registry_of(make_record_dict()),
        )
        self.assertEqual(trust_map.dimension("language").state, "unknown")
        self.assertIn("und", trust_map.dimension("language").reason)
        # The regime-level dimensions cannot be tied to an unobserved language.
        self.assertEqual(trust_map.dimension("human_false_positive_evidence").state, "unknown")
        self.assertEqual(trust_map.dimension("temporal_version_stability").state, "unknown")
        # The other aspects still match.
        self.assertEqual(trust_map.dimension("text_length").state, "supported")

    def test_word_count_below_every_floor_is_out_of_scope(self):
        trust_map = derive(
            make_conditions(word_count=10),
            registry_of(make_record_dict(floor_words=80)),
        )
        dim = trust_map.dimension("text_length")
        assert dim is not None
        self.assertEqual(dim.state, "out_of_scope")
        self.assertEqual(trust_map.overall, "insufficient")

    def test_uncovered_language_is_out_of_scope(self):
        trust_map = derive(
            make_conditions(language="fr", language_confidence="high"),
            registry_of(make_record_dict(language="en")),
        )
        self.assertEqual(trust_map.dimension("language").state, "out_of_scope")
        self.assertEqual(trust_map.overall, "insufficient")

    def test_uncovered_domain_is_out_of_scope(self):
        trust_map = derive(
            make_conditions(domain_genre="legal", domain_confidence="high"),
            registry_of(make_record_dict(domain=("synthetic",))),
        )
        self.assertEqual(trust_map.dimension("domain_genre").state, "out_of_scope")

    def test_unknown_domain_is_unknown(self):
        trust_map = derive(
            make_conditions(domain_genre="unknown", domain_confidence="unknown"),
            registry_of(make_record_dict()),
        )
        self.assertEqual(trust_map.dimension("domain_genre").state, "unknown")

    def test_undeclared_generator_is_unknown(self):
        trust_map = derive(
            make_conditions(generator=None),
            registry_of(make_record_dict()),
        )
        self.assertEqual(trust_map.dimension("generator_scope").state, "unknown")

    def test_uncovered_generator_is_out_of_scope(self):
        trust_map = derive(
            make_conditions(generator="other-family"),
            registry_of(make_record_dict(generator_families=("synthetic",))),
        )
        self.assertEqual(trust_map.dimension("generator_scope").state, "out_of_scope")

    def test_undeclared_population_is_unknown(self):
        trust_map = derive(
            make_conditions(human_population="unknown"),
            registry_of(make_record_dict()),
        )
        self.assertEqual(trust_map.dimension("human_population").state, "unknown")

    def test_uncovered_population_is_out_of_scope(self):
        trust_map = derive(
            make_conditions(human_population="other-population"),
            registry_of(make_record_dict(populations=("synthetic",))),
        )
        self.assertEqual(trust_map.dimension("human_population").state, "out_of_scope")

    def test_unknown_editing_is_unknown(self):
        trust_map = derive(
            make_conditions(editing_regime="unknown"),
            registry_of(make_record_dict()),
        )
        self.assertEqual(trust_map.dimension("editing_revision").state, "unknown")


class DeriveStaleTests(unittest.TestCase):
    def test_stale_via_version_change(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict(detector_version="0.1.0")),
            detector_version="0.2.0",
        )
        for name in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
            "temporal_version_stability",
        ):
            dim = trust_map.dimension(name)
            assert dim is not None
            self.assertEqual(dim.state, "stale", name)
            self.assertEqual(dim.evidence_refs, [RECORD_ID], name)
            self.assertIn(RECORD_ID, dim.reason, name)
            self.assertIn("0.2.0", dim.reason, name)
        # Stale counts as neither supported nor partial.
        self.assertEqual(trust_map.overall, "insufficient")
        self.assertEqual(trust_map.coverage["stale"], 8)

    def test_stale_via_due_date_expiry(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict(due="2027-02-04")),
            now="2027-03-01T00:00:00+00:00",
        )
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "stale")
        self.assertIn("2027-02-04", dim.reason)
        self.assertIn(RECORD_ID, dim.reason)

    def test_due_date_itself_is_not_stale(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict(due="2027-02-04")),
            now="2027-02-04T00:00:00+00:00",
        )
        self.assertEqual(trust_map.dimension("language").state, "supported")

    def test_stale_via_demotion(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict(demoted_by="u3-observatory")),
        )
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "stale")
        self.assertIn("u3-observatory", dim.reason)
        self.assertIn(RECORD_ID, dim.reason)

    def test_fresh_record_wins_over_stale_record(self):
        stale_id = "evr-20261106-synthetic-test-a-builtin-heuristic"
        fresh_id = "evr-20261106-synthetic-test-b-builtin-heuristic"
        registry = registry_of(
            make_record_dict(record_id=stale_id, detector_version="0.1.0"),
            make_record_dict(record_id=fresh_id, detector_version="0.2.0"),
        )
        trust_map = derive(make_conditions(), registry, detector_version="0.2.0")
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "supported")
        # Both regime-matching records are cited, stale or not.
        self.assertEqual(dim.evidence_refs, [stale_id, fresh_id])


class DeriveCappingTests(unittest.TestCase):
    def test_contamination_yes_caps_at_partial(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict(contamination="yes")))
        for name in (
            "language",
            "text_length",
            "domain_genre",
            "editing_revision",
            "generator_scope",
            "human_population",
            "human_false_positive_evidence",
        ):
            dim = trust_map.dimension(name)
            assert dim is not None
            self.assertEqual(dim.state, "partial", name)
            self.assertIn(CONTAMINATED_LABEL, dim.limitations, name)
            self.assertIn(CONTAMINATED_LABEL, dim.reason, name)

    def test_contamination_unknown_caps_at_partial(self):
        trust_map = derive(
            make_conditions(), registry_of(make_record_dict(contamination="unknown"))
        )
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "partial")
        self.assertIn(CONTAMINATION_UNKNOWN_LABEL, dim.limitations)

    def test_contested_caps_at_partial(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict(status="contested")))
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "partial")
        self.assertIn("contested", dim.reason)
        self.assertTrue(any("contested" in item for item in dim.limitations), dim.limitations)

    def test_thin_human_samples_cap_at_partial(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict(n_human=50)))
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "partial")
        self.assertIn("n_human=50", dim.reason)

    def test_thin_ai_samples_cap_at_partial(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict(n_ai=99)))
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "partial")
        self.assertIn("n_ai=99", dim.reason)

    def test_missing_mandatory_field_caps_at_partial(self):
        # A stored "supported" record missing a mandatory-for-supported
        # field (genre) has effective status partial; the engine must see
        # the capped status, not the stored one.
        trust_map = derive(make_conditions(), registry_of(make_record_dict(genre=None)))
        dim = trust_map.dimension("language")
        assert dim is not None
        self.assertEqual(dim.state, "partial")
        self.assertIn("partial", dim.reason)


class FprGatingTests(unittest.TestCase):
    def test_fpr_unknown_when_no_records_for_detector(self):
        trust_map = derive(make_conditions(), empty_validation_registry())
        dim = trust_map.dimension("human_false_positive_evidence")
        assert dim is not None
        self.assertEqual(dim.state, "unknown")
        other = registry_of(make_record_dict(detector_id="textforensics/other-detector"))
        trust_map = derive(make_conditions(), other)
        self.assertEqual(trust_map.dimension("human_false_positive_evidence").state, "unknown")

    def test_fpr_without_ci_is_partial(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict(fpr_ci=None)))
        dim = trust_map.dimension("human_false_positive_evidence")
        assert dim is not None
        self.assertEqual(dim.state, "partial")
        self.assertIn("confidence interval", dim.reason)
        # The other dimensions are unaffected by the FPR gate.
        self.assertEqual(trust_map.dimension("language").state, "supported")

    def test_fpr_ci_upper_above_ceiling_is_partial(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict(fpr_ci=(0.0, 0.06))),
        )
        dim = trust_map.dimension("human_false_positive_evidence")
        assert dim is not None
        self.assertEqual(dim.state, "partial")
        self.assertIn("0.06", dim.reason)

    def test_fpr_with_ci_under_ceiling_is_supported(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict(fpr_ci=(0.0, 0.05))),
        )
        dim = trust_map.dimension("human_false_positive_evidence")
        assert dim is not None
        self.assertEqual(dim.state, "supported")
        self.assertEqual(dim.observed.get("fpr_ci_upper"), 0.05)
        self.assertEqual(dim.observed.get("fpr_ceiling"), 0.05)

    def test_fpr_ceiling_parameter_is_respected(self):
        registry = registry_of(make_record_dict(fpr_ci=(0.0, 0.05)))
        strict = derive(make_conditions(), registry, fpr_ceiling=0.01)
        self.assertEqual(strict.dimension("human_false_positive_evidence").state, "partial")
        loose = derive(make_conditions(), registry, fpr_ceiling=0.10)
        self.assertEqual(loose.dimension("human_false_positive_evidence").state, "supported")


class EditingMappingTests(unittest.TestCase):
    def test_each_input_regime_maps_to_record_regime(self):
        cases = (
            ("machine_only", "raw"),
            ("human_only", "raw"),
            ("machine_then_human_edited", "human-edited"),
            ("machine_then_machine_paraphrased", "paraphrased"),
            ("mixed", "mixed-origin"),
        )
        for input_regime, record_regime in cases:
            with self.subTest(input_regime=input_regime):
                self.assertEqual(INPUT_EDITING_REGIME_MAP[input_regime], record_regime)
                trust_map = derive(
                    make_conditions(editing_regime=input_regime),
                    registry_of(make_record_dict(editing_regime=record_regime)),
                )
                self.assertEqual(trust_map.dimension("editing_revision").state, "supported")

    def test_llm_edited_record_is_not_auto_matched(self):
        trust_map = derive(
            make_conditions(editing_regime="machine_only"),
            registry_of(make_record_dict(editing_regime="LLM-edited")),
        )
        dim = trust_map.dimension("editing_revision")
        assert dim is not None
        self.assertEqual(dim.state, "out_of_scope")
        self.assertIn("not auto-matched", dim.reason)

    def test_humanised_record_is_not_auto_matched(self):
        trust_map = derive(
            make_conditions(editing_regime="machine_then_human_edited"),
            registry_of(make_record_dict(editing_regime="humanised")),
        )
        self.assertEqual(trust_map.dimension("editing_revision").state, "out_of_scope")


class LiveDimensionTests(unittest.TestCase):
    def test_live_dimensions_unknown_without_observations(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict()))
        diversity = trust_map.dimension("detector_diversity")
        stability = trust_map.dimension("benign_stability")
        assert diversity is not None and stability is not None
        self.assertEqual(diversity.state, "unknown")
        self.assertEqual(stability.state, "unknown")

    def test_live_dimensions_with_observations(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict()),
            predictions=[
                prediction(detector_id="d1", family="family-a"),
                prediction(detector_id="d2", family="family-b"),
            ],
            robustness=[
                {
                    "detector_id": "d1",
                    "verdict_stability": 1.0,
                    "native_score_range": 0.05,
                },
                {
                    "detector_id": "d2",
                    "verdict_stability": 1.0,
                    "native_score_range": 0.02,
                },
            ],
        )
        self.assertEqual(trust_map.dimension("detector_diversity").state, "supported")
        self.assertEqual(trust_map.dimension("benign_stability").state, "supported")
        # Overall is still mixed: temporal stability caps at partial.
        self.assertEqual(trust_map.overall, "mixed")
        self.assertEqual(trust_map.coverage["supported"], 9)
        self.assertEqual(trust_map.coverage["partial"], 1)

    def test_live_diversity_partial_with_single_family(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict()),
            predictions=[prediction(detector_id="d1", family="family-a")],
        )
        self.assertEqual(trust_map.dimension("detector_diversity").state, "partial")

    def test_live_stability_partial_when_verdict_changes(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict()),
            robustness=[
                {
                    "detector_id": "d1",
                    "verdict_stability": 0.5,
                    "native_score_range": 0.05,
                },
            ],
        )
        self.assertEqual(trust_map.dimension("benign_stability").state, "partial")


class OverallStateTests(unittest.TestCase):
    def _dims(self, *states: str) -> list[TrustDimension]:
        names = (
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
        )
        return [
            TrustDimension(dimension=name, state=state, reason="x")
            for name, state in zip(names, states, strict=True)
        ]

    def test_strong_requires_all_ten_supported(self):
        self.assertEqual(_overall_state_v3(self._dims(*("supported",) * 10)), "strong")
        self.assertEqual(_overall_state_v3(self._dims(*("supported",) * 9, "partial")), "mixed")
        self.assertEqual(_overall_state_v3(self._dims(*("supported",) * 9, "stale")), "mixed")

    def test_empty_dimension_list_is_insufficient_not_strong(self):
        # 0 == 0 must not report "strong" for no evidence: the primary
        # must agree with verify._recompute_overall_v3 (and the v2
        # replay) that an empty dimension list yields "insufficient".
        self.assertEqual(_overall_state_v3([]), "insufficient")

    def test_insufficient_when_nothing_supported_or_partial(self):
        self.assertEqual(_overall_state_v3(self._dims(*("unknown",) * 10)), "insufficient")
        self.assertEqual(_overall_state_v3(self._dims(*("stale",) * 10)), "insufficient")
        self.assertEqual(
            _overall_state_v3(self._dims(*("unknown",) * 9, "out_of_scope")),
            "insufficient",
        )

    def test_insufficient_when_language_or_length_out_of_scope(self):
        dims = self._dims(*("supported",) * 10)
        dims[0] = TrustDimension(dimension="language", state="out_of_scope", reason="x")
        self.assertEqual(_overall_state_v3(dims), "insufficient")
        dims = self._dims(*("supported",) * 10)
        dims[1] = TrustDimension(dimension="text_length", state="out_of_scope", reason="x")
        self.assertEqual(_overall_state_v3(dims), "insufficient")

    def test_engine_overall_insufficient_when_language_out_of_scope(self):
        trust_map = derive(
            make_conditions(language="fr", language_confidence="high"),
            registry_of(make_record_dict(language="en")),
        )
        self.assertEqual(trust_map.overall, "insufficient")


class SchemaValidationTests(unittest.TestCase):
    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_produced_v3_map_validates_against_schema(self):
        from jsonschema import Draft202012Validator

        from textforensics.schema import load_schema

        trust_map = derive(make_conditions(), registry_of(make_record_dict()))
        validator = Draft202012Validator(load_schema("trust-map"))
        self.assertEqual(
            list(validator.iter_errors(trust_map.to_dict())),
            [],
        )

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_v2_map_still_validates(self):
        trust_map = assess_trust_map(make_conditions(), [], registry=None, now=NOW)
        self.assertEqual(validate_trust_map(trust_map.to_dict()), [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_synthetic_v3_map_with_stale_dimension_validates(self):
        trust_map = derive(
            make_conditions(),
            registry_of(make_record_dict()),
            detector_version="0.2.0",
        )
        self.assertEqual(validate_trust_map(trust_map.to_dict()), [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_synthetic_v2_map_with_stale_dimension_fails_schema(self):
        # The v2 contract is NOT widened: a stale dimension is invalid in v2
        # even though the Python dataclass accepts the union of states.
        trust_map = TrustMap(
            schema=TRUST_SCHEMA,
            overall="mixed",
            dimensions=[TrustDimension(dimension="language", state="stale", reason="x")],
            limitations=[],
            input_conditions={},
            evidence_registry={
                "registry_id": None,
                "record_count": 0,
                "verified": False,
                "verification_status": "not_checked",
            },
            coverage={"supported": 0, "partial": 0, "unknown": 0, "out_of_scope": 0},
            generated_at_utc=NOW,
        )
        self.assertNotEqual(validate_trust_map(trust_map.to_dict()), [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "jsonschema is a development dependency",
    )
    def test_synthetic_v3_map_missing_stale_coverage_fails_schema(self):
        trust_map = derive(make_conditions(), registry_of(make_record_dict()))
        payload = trust_map.to_dict()
        del payload["coverage"]["stale"]
        self.assertNotEqual(validate_trust_map(payload), [])


if __name__ == "__main__":
    unittest.main()
