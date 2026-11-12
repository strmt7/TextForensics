"""W2 Worker A regression tests (audit CORE-01/02/07/11, S04, C10).

Each test is written from the audit's stated expected result, not from
current product output. All fixtures are synthetic and disposable; no
real user text, no external corpus, no measured numbers.

Run order note: these tests are RED on the W1 head (f1d8c83) and must
turn green only via the W2-A source fixes.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import date
from pathlib import Path
from types import SimpleNamespace

from textforensics.conditions import InputConditions
from textforensics.detectors import DetectorPrediction
from textforensics.evidence import (
    BenchmarkProvenance,
    EvidenceRecord,
    EvidenceRegistry,
    MetricEstimate,
    RunProvenance,
    SliceConditions,
    ValidationSlice,
    assess_detector_coverage,
)
from textforensics.models import AnalyzerResult
from textforensics.validation import (
    ValidationRecord,
    ValidationRegistry,
    compute_signature,
    derive_trust_map,
)

NOW = "2026-11-06T00:00:00+00:00"
V3_VERSION = "0.1.0"
V3_DETECTOR = "textforensics/builtin-heuristic"


def hex64(seed: int) -> str:
    return f"{seed:064x}"


# ---------------------------------------------------------------------------
# V2 (evidence.py) fixtures
# ---------------------------------------------------------------------------


def _v2_conditions(word_count: int = 200) -> InputConditions:
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


def _v2_record(
    *,
    detector_id: str = "a",
    detector_version: str = "1",
    split: str = "test",
    editing: tuple[str, ...] = ("human_only",),
    evaluated_at: str = "2026-11-01T00:00:00+00:00",
    n_human: int = 200,
    n_ai: int = 200,
    fpr_ci: tuple[float, float] | None = (0.01, 0.03),
    benchmark_fingerprint: str | None = None,
    benchmark_hash: str | None = None,
    run_hash: str | None = None,
    status: str = "active",
) -> EvidenceRecord:
    fpr_metric = MetricEstimate(
        value=0.02,
        n=n_human,
        ci_lower=None if fpr_ci is None else fpr_ci[0],
        ci_upper=None if fpr_ci is None else fpr_ci[1],
        method="wilson",
    )
    slice_ = ValidationSlice(
        slice_id="s1",
        conditions=SliceConditions(
            languages=("en",),
            domains=("general",),
            editing_regimes=editing,
            min_words=100,
            max_words=1000,
            generators=("g1", "g2", "g3"),
            generator_scope="multi",
            human_populations=("pop_a", "pop_b"),
        ),
        n_human=n_human,
        n_ai=n_ai,
        metrics={
            "fpr": fpr_metric,
            "auroc": MetricEstimate(
                value=0.95,
                n=n_human + n_ai,
                ci_lower=0.94,
                ci_upper=0.96,
                method="wilson",
            ),
        },
        threshold=0.5,
    )
    return EvidenceRecord(
        evidence_id=f"ev-{detector_id}-{detector_version}-{split}",
        detector_id=detector_id,
        detector_version=detector_version,
        detector_family="fam1",
        evaluated_at_utc=evaluated_at,
        benchmark=BenchmarkProvenance(
            name="raid",
            version="1.0",
            fingerprint_sha256=benchmark_fingerprint or hex64(1),
            split=split,
            license="MIT",
            artifact_path="data/raid.jsonl",
            artifact_sha256=benchmark_hash or hex64(2),
            contamination_controls=["disjoint_sample_ids"],
        ),
        slices=(slice_,),
        provenance=RunProvenance(
            git_sha="abc1234",
            command="textforensics benchmark",
            environment_sha256=hex64(3),
            executed_at_utc=evaluated_at,
            run_artifact_path="runs/1.json",
            run_artifact_sha256=run_hash or hex64(4),
        ),
        status=status,
    )


def _write_artifacts(root: Path) -> tuple[str, str, str]:
    """Write real benchmark/run artifact bytes; return (fingerprint, bench, run) hashes."""
    bench = root / "data" / "raid.jsonl"
    run = root / "runs" / "1.json"
    bench.parent.mkdir(parents=True, exist_ok=True)
    run.parent.mkdir(parents=True, exist_ok=True)
    bench.write_bytes(b'{"text": "synthetic", "label": 0}\n')
    run.write_bytes(b'{"run": "synthetic"}\n')
    fingerprint = hashlib.sha256(b"synthetic-evaluation-set").hexdigest()
    return (
        fingerprint,
        hashlib.sha256(bench.read_bytes()).hexdigest(),
        hashlib.sha256(run.read_bytes()).hexdigest(),
    )


def _eligible_inputs(registry: EvidenceRegistry, root: Path):
    """Build the eligibility inputs for a registry whose artifacts live under root."""
    from textforensics.evidence import DisjointnessProof, InferenceIdentity

    verification = registry.verify_artifacts(root=root)
    record = registry.records[0]
    proof = DisjointnessProof(
        status="verified",
        overlap_count=0,
        training_count=1000,
        evaluation_count=400,
        training_hash=hex64(9),
        evaluation_hash=record.benchmark.fingerprint_sha256,
    )
    identity = InferenceIdentity(
        detector_id=record.detector_id,
        detector_version=record.detector_version,
        provider=None,
        model=None,
        config_hash=None,
        native_score_semantics=None,
        calibration_id=None,
        regime="human_only",
    )
    return {
        "identity": identity,
        "disjointness": proof,
        "artifact_verification": verification,
    }


def _v2_coverage(registry: EvidenceRegistry, **kwargs):
    return assess_detector_coverage(
        detector_id="a",
        detector_version="1",
        detector_family="fam1",
        supported_languages=("en",),
        min_words=80,
        max_words=1000,
        conditions=_v2_conditions(),
        registry=registry,
        now=NOW,
        **kwargs,
    )


def _supported_dimensions(coverage) -> set[str]:
    return {name for name, dim in coverage.dimensions.items() if dim.state == "supported"}


# ---------------------------------------------------------------------------
# V3 (validation.py) fixtures
# ---------------------------------------------------------------------------


def _v3_record_dict(
    *,
    status: str = "supported",
    record_id: str = "evr-20261106-synthetic-test-builtin-heuristic",
    detector_id: str = V3_DETECTOR,
    detector_version: str = V3_VERSION,
    language: str = "en",
    domain: tuple[str, ...] = ("synthetic",),
    editing_regime: str = "raw",
    generator_families: tuple[str, ...] = ("synthetic",),
    populations: tuple[str, ...] = ("synthetic",),
    floor_words: int = 80,
    n_human: int = 120,
    n_ai: int = 120,
    contamination: str = "no",
    split_role: str = "test",
    due: str = "2027-02-04",
    demoted_by: str | None = None,
    fpr_slices: tuple[dict, ...] | None = None,
) -> dict:
    """Synthetic U1 record dict, hash-sealed with compute_signature.

    ``fpr_slices``: one entry per declared slice, each
    ``{"slice_id": ..., "value": ..., "ci": (lower, upper) | None,
    "worst_slice": bool}``. Defaults to a single slice with CI upper 0.05.
    """
    if fpr_slices is None:
        fpr_slices = (
            {"slice_id": "synthetic-test", "value": 0.02, "ci": (0.0, 0.05), "worst_slice": True},
        )
    metrics = []
    for spec in fpr_slices:
        ci = spec["ci"]
        metric = {
            "value": 0.8,
            "n": n_human + n_ai,
            "ci_lower": 0.7,
            "ci_upper": 0.9,
            "method": "bootstrap, 1000 resamples, seed 20261106",
        }
        metrics.append(
            {
                "slice_id": spec["slice_id"],
                "n_human": n_human,
                "n_ai": n_ai,
                "auroc": dict(metric),
                "tpr_at_fpr_0_01": dict(metric, value=0.5, n=n_ai, ci_lower=0.4, ci_upper=0.6),
                "tpr_at_fpr_0_05": dict(metric, value=0.7, n=n_ai, ci_lower=0.6, ci_upper=0.8),
                "fpr_native": {
                    "value": spec["value"],
                    "n": n_human,
                    "ci_lower": None if ci is None else ci[0],
                    "ci_upper": None if ci is None else ci[1],
                    "method": "bootstrap, 1000 resamples, seed 20261106",
                    "operating_point": (
                        "builtin-heuristic native verdict (analyze_text); no score threshold"
                    ),
                },
                "coverage": 1.0,
                "abstention_rate": 0.0,
                "worst_slice": bool(spec.get("worst_slice", False)),
            }
        )
    record = {
        "schema": "textforensics.evidence-record/v1",
        "record_id": record_id,
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
                "max_words": None,
                "floor_words": floor_words,
                "measured_min_words": floor_words + 5,
                "measured_median_words": floor_words + 40,
                "measured_max_words": floor_words + 320,
            },
            "domain": list(domain),
            "genre": "synthetic-test",
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
            "split_role": split_role,
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
        "metrics": metrics,
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


def _v3_conditions(**overrides) -> InputConditions:
    from textforensics.conditions import length_band

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


def _v3_registry(*record_dicts: dict) -> ValidationRegistry:
    return ValidationRegistry([ValidationRecord.from_dict(item) for item in record_dicts])


def _v3_derive(conditions: InputConditions, registry: ValidationRegistry):
    return derive_trust_map(
        conditions,
        registry,
        detector_id=V3_DETECTOR,
        detector_version=V3_VERSION,
        now=NOW,
    )


def _v3_dim(trust_map, name: str):
    return next(item for item in trust_map.dimensions if item.dimension == name)


def _prediction(detector_id: str = "a", family: str = "fam1") -> DetectorPrediction:
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


# ---------------------------------------------------------------------------
# CORE-01 — V2 coverage accepts scientifically ineligible evidence
# ---------------------------------------------------------------------------


class Core01Tests(unittest.TestCase):
    def test_audit_repro_yields_no_supported_dimension(self):
        """Wildcard version + train split + incompatible editing regime +
        missing artifacts must not produce any supported dimension."""
        record = _v2_record(
            detector_version="*",
            split="train",
            editing=("machine_only",),
        )
        coverage = _v2_coverage(EvidenceRegistry([record]))
        self.assertEqual(_supported_dimensions(coverage), set())

    def test_each_ineligibility_axis_alone_blocks_support(self):
        """Varying one axis at a time from an otherwise eligible record
        must never leave a supported dimension."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fingerprint, bench_hash, run_hash = _write_artifacts(root)
            base_kwargs = {
                "benchmark_fingerprint": fingerprint,
                "benchmark_hash": bench_hash,
                "run_hash": run_hash,
            }
            from textforensics.evidence import DisjointnessProof

            def eligible_inputs_for(registry):
                return _eligible_inputs(registry, root)

            # Control: fully eligible -> supported dimensions exist.
            control = _v2_record(**base_kwargs)
            control_cov = _v2_coverage(
                EvidenceRegistry([control]), **eligible_inputs_for(EvidenceRegistry([control]))
            )
            self.assertIn("language", _supported_dimensions(control_cov))

            variants = {
                "train split": _v2_record(split="train", **base_kwargs),
                "wildcard version": _v2_record(detector_version="*", **base_kwargs),
                "retracted": _v2_record(status="retracted", **base_kwargs),
                "stale": _v2_record(evaluated_at="2024-01-01T00:00:00+00:00", **base_kwargs),
                "thin samples": _v2_record(n_human=10, n_ai=10, **base_kwargs),
            }
            for label, record in variants.items():
                with self.subTest(axis=label):
                    registry = EvidenceRegistry([record])
                    coverage = _v2_coverage(registry, **eligible_inputs_for(registry))
                    self.assertEqual(
                        _supported_dimensions(coverage),
                        set(),
                        f"{label} must not establish support",
                    )

            # Missing artifacts: verification reports the record as not ok.
            missing = _v2_record(**base_kwargs)
            missing_cov = _v2_coverage(
                EvidenceRegistry([missing]),
                **eligible_inputs_for(EvidenceRegistry([missing])),
            )
            # The proof/verification inputs above were built against the
            # same registry, whose artifacts ARE present; rebuild the
            # verification against an empty root to simulate missing files.
            empty_root = root / "empty"
            empty_root.mkdir()
            _inputs = _eligible_inputs(EvidenceRegistry([missing]), root)
            identity = _inputs["identity"]
            proof = _inputs["disjointness"]
            verification = EvidenceRegistry([missing]).verify_artifacts(root=empty_root)
            self.assertFalse(verification.verified)
            missing_cov = _v2_coverage(
                EvidenceRegistry([missing]),
                identity=identity,
                disjointness=proof,
                artifact_verification=verification,
            )
            self.assertEqual(_supported_dimensions(missing_cov), set())
            self.assertEqual(_supported_dimensions(missing_cov), set())

            # Unknown contamination: proof status unknown -> no support.
            unknown_proof = DisjointnessProof(
                status="unknown",
                overlap_count=0,
                training_count=1000,
                evaluation_count=400,
                training_hash=hex64(9),
                evaluation_hash=fingerprint,
            )
            _inputs = _eligible_inputs(EvidenceRegistry([control]), root)
            identity = _inputs["identity"]
            verification = _inputs["artifact_verification"]
            coverage = _v2_coverage(
                EvidenceRegistry([control]),
                identity=identity,
                disjointness=unknown_proof,
                artifact_verification=verification,
            )
            self.assertEqual(_supported_dimensions(coverage), set())

            # Contaminated proof: overlap > 0 -> no support.
            contaminated = DisjointnessProof(
                status="contaminated",
                overlap_count=3,
                training_count=1000,
                evaluation_count=400,
                training_hash=hex64(9),
                evaluation_hash=fingerprint,
            )
            coverage = _v2_coverage(
                EvidenceRegistry([control]),
                identity=identity,
                disjointness=contaminated,
                artifact_verification=verification,
            )
            self.assertEqual(_supported_dimensions(coverage), set())

            # No eligibility inputs at all (caller-supplied record only)
            # -> no support: unverified declarations are never promoted.
            coverage = _v2_coverage(EvidenceRegistry([control]))
            self.assertEqual(_supported_dimensions(coverage), set())

    def test_ineligible_record_is_preserved_as_partial_not_dropped(self):
        """A train-split record stays visible as partial evidence; it is
        capped, not deleted and not relabelled unknown."""
        record = _v2_record(split="train")
        coverage = _v2_coverage(EvidenceRegistry([record]))
        dim = coverage.dimensions["language"]
        self.assertEqual(dim.state, "partial")
        self.assertIn("train", " ".join(dim.limitations) + dim.reason)

    def test_records_for_no_longer_matches_wildcard_version(self):
        registry = EvidenceRegistry([_v2_record(detector_version="*")])
        self.assertEqual(registry.records_for("a", "1"), ())
        # An exact-version record still matches exactly.
        registry = EvidenceRegistry([_v2_record(detector_version="1")])
        self.assertEqual(len(registry.records_for("a", "1")), 1)
        self.assertEqual(registry.records_for("a", "2"), ())

    def test_fully_eligible_control_supports_applicable_dimensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fingerprint, bench_hash, run_hash = _write_artifacts(root)
            record = _v2_record(
                benchmark_fingerprint=fingerprint,
                benchmark_hash=bench_hash,
                run_hash=run_hash,
            )
            registry = EvidenceRegistry([record])
            coverage = _v2_coverage(registry, **_eligible_inputs(registry, root))
            supported = _supported_dimensions(coverage)
            for name in (
                "language",
                "text_length",
                "domain_genre",
                "editing_revision",
                "generator_scope",
                "human_population",
                "human_false_positive_evidence",
            ):
                self.assertIn(name, supported, f"{name} should be supported")
            # Temporal stability caps at partial from a single snapshot.
            self.assertEqual(coverage.dimensions["temporal_version_stability"].state, "partial")


# ---------------------------------------------------------------------------
# CORE-02 — Human-FPR support selects the most favorable slice
# ---------------------------------------------------------------------------


class Core02V3Tests(unittest.TestCase):
    def test_adverse_slice_in_same_record_blocks_support(self):
        """CI uppers 0.01 and 0.9 in one sealed record: supported is
        wrong; the reported upper must be the worst (0.9), not the min."""
        record = _v3_record_dict(
            fpr_slices=(
                {"slice_id": "slice-good", "value": 0.005, "ci": (0.0, 0.01), "worst_slice": False},
                {"slice_id": "slice-bad", "value": 0.5, "ci": (0.1, 0.9), "worst_slice": True},
            )
        )
        trust_map = _v3_derive(_v3_conditions(), _v3_registry(record))
        dim = _v3_dim(trust_map, "human_false_positive_evidence")
        self.assertNotEqual(dim.state, "supported")
        self.assertEqual(dim.observed.get("fpr_ci_upper"), 0.9)

    def test_worst_slice_flag_cannot_hide_adverse_slice(self):
        """Flagging the GOOD slice as worst_slice must not change the
        gate: the worst upper across declared slices governs."""
        record = _v3_record_dict(
            fpr_slices=(
                {"slice_id": "slice-good", "value": 0.005, "ci": (0.0, 0.01), "worst_slice": True},
                {"slice_id": "slice-bad", "value": 0.5, "ci": (0.1, 0.9), "worst_slice": False},
            )
        )
        dim = _v3_dim(
            _v3_derive(_v3_conditions(), _v3_registry(record)),
            "human_false_positive_evidence",
        )
        self.assertNotEqual(dim.state, "supported")
        self.assertEqual(dim.observed.get("fpr_ci_upper"), 0.9)

    def test_favorable_record_cannot_hide_adverse_record(self):
        """Adding a favorable record must not rescue an adverse
        applicable record: conflicting evidence is preserved, support
        is vetoed."""
        good = _v3_record_dict(
            record_id="evr-20261106-synthetic-good-builtin-heuristic",
            fpr_slices=(
                {"slice_id": "slice-good", "value": 0.005, "ci": (0.0, 0.01), "worst_slice": True},
            ),
        )
        bad = _v3_record_dict(
            record_id="evr-20261106-synthetic-bad-builtin-heuristic",
            fpr_slices=(
                {"slice_id": "slice-bad", "value": 0.5, "ci": (0.1, 0.9), "worst_slice": True},
            ),
        )
        dim = _v3_dim(
            _v3_derive(_v3_conditions(), _v3_registry(good, bad)),
            "human_false_positive_evidence",
        )
        self.assertNotEqual(dim.state, "supported")
        self.assertEqual(dim.observed.get("fpr_ci_upper"), 0.9)

    def test_slice_without_ci_blocks_support(self):
        """A required slice with no FPR CI is missing evidence: it must
        block support, not be skipped in favour of the slices that do
        have a CI."""
        record = _v3_record_dict(
            fpr_slices=(
                {"slice_id": "slice-good", "value": 0.005, "ci": (0.0, 0.01), "worst_slice": False},
                {"slice_id": "slice-noci", "value": 0.02, "ci": None, "worst_slice": True},
            )
        )
        dim = _v3_dim(
            _v3_derive(_v3_conditions(), _v3_registry(record)),
            "human_false_positive_evidence",
        )
        self.assertNotEqual(dim.state, "supported")

    def test_all_slices_under_ceiling_supports_and_reports_worst(self):
        record = _v3_record_dict(
            fpr_slices=(
                {"slice_id": "slice-a", "value": 0.005, "ci": (0.0, 0.01), "worst_slice": False},
                {"slice_id": "slice-b", "value": 0.02, "ci": (0.0, 0.04), "worst_slice": True},
            )
        )
        dim = _v3_dim(
            _v3_derive(_v3_conditions(), _v3_registry(record)),
            "human_false_positive_evidence",
        )
        self.assertEqual(dim.state, "supported")
        self.assertEqual(dim.observed.get("fpr_ci_upper"), 0.04)

    def test_ceiling_boundary_is_inclusive(self):
        record = _v3_record_dict(
            fpr_slices=(
                {"slice_id": "slice-edge", "value": 0.04, "ci": (0.01, 0.05), "worst_slice": True},
            )
        )
        dim = _v3_dim(
            _v3_derive(_v3_conditions(), _v3_registry(record)),
            "human_false_positive_evidence",
        )
        self.assertEqual(dim.state, "supported")
        self.assertEqual(dim.observed.get("fpr_ci_upper"), 0.05)


class Core02V2Tests(unittest.TestCase):
    def _two_slice_record(self, uppers):
        slices = []
        for index, upper in enumerate(uppers):
            slices.append(
                ValidationSlice(
                    slice_id=f"s{index}",
                    conditions=SliceConditions(
                        languages=("en",),
                        domains=("general",),
                        editing_regimes=("human_only",),
                        min_words=100,
                        max_words=1000,
                        generators=("g1", "g2", "g3"),
                        generator_scope="multi",
                        human_populations=("pop_a", "pop_b"),
                    ),
                    n_human=200,
                    n_ai=200,
                    metrics={
                        "fpr": MetricEstimate(
                            value=upper / 2,
                            n=200,
                            ci_lower=0.0,
                            ci_upper=upper,
                            method="wilson",
                        ),
                    },
                    threshold=0.5,
                )
            )
        return EvidenceRecord(
            evidence_id="ev-a-1-test",
            detector_id="a",
            detector_version="1",
            detector_family="fam1",
            evaluated_at_utc="2026-11-01T00:00:00+00:00",
            benchmark=BenchmarkProvenance(
                name="raid",
                version="1.0",
                fingerprint_sha256=hex64(1),
                split="test",
                license="MIT",
                artifact_path="data/raid.jsonl",
                artifact_sha256=hex64(2),
                contamination_controls=["disjoint_sample_ids"],
            ),
            slices=tuple(slices),
            provenance=RunProvenance(
                git_sha="abc1234",
                command="textforensics benchmark",
                environment_sha256=hex64(3),
                executed_at_utc="2026-11-01T00:00:00+00:00",
                run_artifact_path="runs/1.json",
                run_artifact_sha256=hex64(4),
            ),
        )

    def test_v2_worst_slice_governs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fingerprint, bench_hash, run_hash = _write_artifacts(root)
            record = self._two_slice_record((0.01, 0.9))
            # Rebuild with the real artifact hashes/fingerprint so the
            # record is eligible on every axis except the FPR slices.
            record = EvidenceRecord(
                evidence_id=record.evidence_id,
                detector_id=record.detector_id,
                detector_version=record.detector_version,
                detector_family=record.detector_family,
                evaluated_at_utc=record.evaluated_at_utc,
                benchmark=BenchmarkProvenance(
                    name="raid",
                    version="1.0",
                    fingerprint_sha256=fingerprint,
                    split="test",
                    license="MIT",
                    artifact_path="data/raid.jsonl",
                    artifact_sha256=bench_hash,
                    contamination_controls=["disjoint_sample_ids"],
                ),
                slices=record.slices,
                provenance=RunProvenance(
                    git_sha="abc1234",
                    command="textforensics benchmark",
                    environment_sha256=hex64(3),
                    executed_at_utc=record.evaluated_at_utc,
                    run_artifact_path="runs/1.json",
                    run_artifact_sha256=run_hash,
                ),
            )
            registry = EvidenceRegistry([record])
            coverage = _v2_coverage(registry, **_eligible_inputs(registry, root))
            dim = coverage.dimensions["human_false_positive_evidence"]
            self.assertNotEqual(dim.state, "supported")
            self.assertEqual(dim.observed.get("fpr_ci_upper"), 0.9)


# ---------------------------------------------------------------------------
# CORE-07 — Failed benign probes can yield supported stability (W2 part)
# ---------------------------------------------------------------------------


class Core07Tests(unittest.TestCase):
    def test_two_failures_never_support_stability_v2(self):
        """Audit repro: 2 succeed, 2 fail. A row carrying the
        survivor-only stability 1.0 with failed=2 must not support."""
        from textforensics.trust import assess_trust_map

        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "verdict_stability_survivors": 1.0,
                "native_score_range": 0.05,
                "completeness": {
                    "selected": 4,
                    "attempted": 4,
                    "succeeded": 2,
                    "abstained": 0,
                    "failed": 2,
                },
            }
        ]
        trust_map = assess_trust_map(_v2_conditions(), [_prediction()], robustness=robustness)
        dim = next(item for item in trust_map.dimensions if item.dimension == "benign_stability")
        self.assertNotEqual(dim.state, "supported")
        self.assertEqual(dim.state, "unknown")

    def test_two_failures_never_support_stability_v3(self):
        """Same repro through the V3 helper (derive_trust_map live dims)."""
        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.05,
                "completeness": {
                    "selected": 4,
                    "attempted": 4,
                    "succeeded": 2,
                    "abstained": 0,
                    "failed": 2,
                },
            }
        ]
        trust_map = derive_trust_map(
            _v3_conditions(),
            _v3_registry(_v3_record_dict()),
            detector_id=V3_DETECTOR,
            detector_version=V3_VERSION,
            now=NOW,
            robustness=robustness,
        )
        dim = next(item for item in trust_map.dimensions if item.dimension == "benign_stability")
        self.assertNotEqual(dim.state, "supported")

    def test_malformed_completeness_row_never_supports(self):
        from textforensics.trust import assess_trust_map

        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.05,
                "completeness": {
                    "selected": "four",
                    "attempted": 4,
                    "succeeded": 4,
                    "abstained": 0,
                    "failed": 0,
                },
            }
        ]
        trust_map = assess_trust_map(_v2_conditions(), [_prediction()], robustness=robustness)
        dim = next(item for item in trust_map.dimensions if item.dimension == "benign_stability")
        self.assertNotEqual(dim.state, "supported")

    def test_all_abstentions_never_support(self):
        from textforensics.trust import assess_trust_map

        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": None,
                "native_score_range": 0.05,
                "completeness": {
                    "selected": 4,
                    "attempted": 4,
                    "succeeded": 0,
                    "abstained": 4,
                    "failed": 0,
                },
            }
        ]
        trust_map = assess_trust_map(_v2_conditions(), [_prediction()], robustness=robustness)
        dim = next(item for item in trust_map.dimensions if item.dimension == "benign_stability")
        self.assertNotEqual(dim.state, "supported")

    def test_complete_successful_control_supports(self):
        from textforensics.trust import assess_trust_map

        robustness = [
            {
                "detector_id": "a",
                "verdict_stability": 1.0,
                "native_score_range": 0.05,
                "completeness": {
                    "selected": 4,
                    "attempted": 4,
                    "succeeded": 4,
                    "abstained": 0,
                    "failed": 0,
                },
            }
        ]
        trust_map = assess_trust_map(_v2_conditions(), [_prediction()], robustness=robustness)
        dim = next(item for item in trust_map.dimensions if item.dimension == "benign_stability")
        self.assertEqual(dim.state, "supported")


# ---------------------------------------------------------------------------
# CORE-11 — Mixed-origin coverage ignores detector identity and eligibility
# ---------------------------------------------------------------------------


def _segment_record_dict(**overrides) -> dict:
    """A segment-level U1 record for the builtin heuristic detector."""
    params = {
        "status": "supported",
        "record_id": "evr-20261110-synthetic-segments-builtin-heuristic",
        "detector_id": V3_DETECTOR,
        "detector_version": V3_VERSION,
        "domain": ("news",),
        "editing_regime": "LLM-edited",
        "fpr_slices": (
            {
                "slice_id": "opai_bench_segments-builtin-heuristic",
                "value": 0.02,
                "ci": (0.0, 0.05),
                "worst_slice": True,
            },
        ),
    }
    params.update(overrides)
    return _v3_record_dict(**params)


def _fake_analyzer(name: str, score: float) -> AnalyzerResult:
    return AnalyzerResult(name=name, score=score, reliability=0.9)


def _fake_result(score: float):
    names = ("structural_uniformity", "formulaic_language", "lexical_profile")
    return SimpleNamespace(
        score=score,
        analyzers=[_fake_analyzer(n, 0.1) for n in names],
        diagnostic_reliability=0.9,
    )


def _sentence(marker: str, n_words: int = 25) -> str:
    return " ".join(["Filler"] + ["filler"] * (n_words - 2) + [marker]) + "."


class Core11Tests(unittest.TestCase):
    def _covered(self, *record_dicts, **kwargs):
        from textforensics.mixed_origin import segment_covered_regimes

        registry = _v3_registry(*record_dicts)
        return segment_covered_regimes(registry, **kwargs)

    def test_audit_repro_does_not_cover(self):
        """Partial record, unrelated detector, same version, expired
        revalidation, manual demotion, copying a known slice ID: no cover."""
        bad = _segment_record_dict(
            status="partial",
            detector_id="other/unrelated-detector",
            due="2020-01-01",
            demoted_by="manual-review",
        )
        self.assertEqual(self._covered(bad), set())

    def test_each_axis_alone_blocks_coverage(self):
        good = _segment_record_dict()
        self.assertEqual(self._covered(good), {("en", "news")})
        variants = {
            "wrong detector id": _segment_record_dict(detector_id="other/unrelated-detector"),
            "wrong version": _segment_record_dict(detector_version="9.9.9"),
            "stored partial": _segment_record_dict(status="partial"),
            "expired": _segment_record_dict(due="2020-01-01"),
            "demoted": _segment_record_dict(demoted_by="manual-review"),
            "contaminated": _segment_record_dict(contamination="yes"),
            "contamination unknown": _segment_record_dict(contamination="unknown"),
            "fit split role": _segment_record_dict(split_role="fit"),
            "thin samples": _segment_record_dict(n_human=10, n_ai=10),
        }
        for label, record in variants.items():
            with self.subTest(axis=label):
                self.assertEqual(self._covered(record), set(), f"{label} must not cover")

    def test_tampered_signature_does_not_cover(self):
        record = _segment_record_dict()
        record["data"]["n_human"] = 4786  # tamper, no re-sign (still valid)
        self.assertEqual(self._covered(record), set())

    def test_report_path_withholds_on_ineligible_record(self):
        """The actual report path (not only the helper) must withhold
        when the only segment record is the audit-style bad one."""
        import textforensics.mixed_origin as mo

        bad = _segment_record_dict(
            status="partial",
            detector_id="other/unrelated-detector",
            due="2020-01-01",
            demoted_by="manual-review",
        )
        covered = self._covered(bad)
        sentences = [_sentence(f"human{i}") for i in range(2)]
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(0.1)
            report = mo.build_mixed_origin_report(
                " ".join(sentences),
                language="en",
                domain="news",
                covered_regimes=covered,
            )
        finally:
            mo.analyze_text = original
        self.assertEqual(report["verdict"], "withheld")
        self.assertTrue(
            any(reason.startswith("no_validation_slice") for reason in report["withheld_reasons"])
        )
        self.assertFalse(report["regime"]["validation_slice_covered"])

    def test_report_path_lifts_withholding_on_eligible_record(self):
        import textforensics.mixed_origin as mo

        covered = self._covered(_segment_record_dict())
        self.assertEqual(covered, {("en", "news")})
        sentences = [_sentence(f"human{i}") for i in range(2)]
        original = mo.analyze_text
        try:
            mo.analyze_text = lambda text, *, include_robustness=True: _fake_result(0.1)
            report = mo.build_mixed_origin_report(
                " ".join(sentences),
                language="en",
                domain="news",
                covered_regimes=covered,
            )
        finally:
            mo.analyze_text = original
        self.assertNotIn("no_validation_slice", report["withheld_reasons"])
        self.assertTrue(report["regime"]["validation_slice_covered"])
        self.assertEqual(report["verdict"], "human")


# ---------------------------------------------------------------------------
# S04 — Invalid/expired capability evidence accepted as validated/supported
# ---------------------------------------------------------------------------


class S04Tests(unittest.TestCase):
    def _ledger(self, **claim_kwargs):
        from textforensics.policy import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceLabel,
            EvidenceRef,
            EvidenceTier,
        )

        claim_kwargs.setdefault("detector_id", "audit.example/detector")
        claim_kwargs.setdefault("capability", "language_coverage.en")
        claim_kwargs.setdefault("tier", EvidenceTier.VALIDATED)
        claim_kwargs.setdefault(
            "evidence",
            [
                EvidenceRef(
                    label=EvidenceLabel.CALCULATED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="calc-1",
                )
            ],
        )
        claim_kwargs.setdefault("valid_until", "2099-01-01")
        ledger = CapabilityLedger()
        ledger.register(CapabilityClaim(**claim_kwargs))
        return ledger

    def test_validated_without_executed_evidence_is_not_validated(self):
        from textforensics.policy import ledger_to_trust_dimension

        ledger = self._ledger()
        self.assertFalse(ledger.is_validated("audit.example/detector", "language_coverage.en"))
        self.assertIsNone(ledger.get("audit.example/detector", "language_coverage.en"))
        with self.assertRaises(ValueError):
            ledger.enforce("audit.example/detector", "language_coverage.en")
        dim = ledger_to_trust_dimension(ledger, "audit.example/detector", "language_coverage")
        self.assertNotEqual(dim.state, "supported")
        # The registry view stays honest: the claim is still listed.
        self.assertEqual(len(ledger.claims()["audit.example/detector"]), 1)

    def test_validated_reported_only_is_not_validated(self):
        from textforensics.policy import EvidenceLabel, EvidenceRef, EvidenceTier

        ledger = self._ledger(
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.REPORTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="report-1",
                )
            ]
        )
        self.assertFalse(ledger.is_validated("audit.example/detector", "language_coverage.en"))

    def test_validated_empty_evidence_is_not_validated(self):
        ledger = self._ledger(evidence=[])
        self.assertFalse(ledger.is_validated("audit.example/detector", "language_coverage.en"))

    def test_validated_with_executed_evidence_stays_validated(self):
        from textforensics.mcp_tools import capability_check
        from textforensics.policy import EvidenceLabel, EvidenceRef, EvidenceTier

        ledger = self._ledger(
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ]
        )
        self.assertTrue(ledger.is_validated("audit.example/detector", "language_coverage.en"))
        self.assertIsNotNone(ledger.enforce("audit.example/detector", "language_coverage.en"))
        result = capability_check(
            {
                "ledger": ledger.to_dict(),
                "detector_id": "audit.example/detector",
                "capability": "language_coverage.en",
            }
        )
        self.assertTrue(result["is_validated"])

    def test_expiry_boundaries_use_supplied_utc_clock(self):
        from textforensics.policy import EvidenceLabel, EvidenceRef, EvidenceTier

        executed = [
            EvidenceRef(
                label=EvidenceLabel.EXECUTED,
                tier=EvidenceTier.VALIDATED,
                artifact="run/en.json",
            )
        ]
        # Expired long ago.
        ledger = self._ledger(evidence=executed, valid_until="2000-01-01")
        self.assertFalse(
            ledger.is_validated(
                "audit.example/detector",
                "language_coverage.en",
                today=date(2026, 11, 11),
            )
        )
        # Expiring today is still effective: valid_until is the last day.
        ledger = self._ledger(evidence=executed, valid_until="2026-11-11")
        self.assertTrue(
            ledger.is_validated(
                "audit.example/detector",
                "language_coverage.en",
                today=date(2026, 11, 11),
            )
        )
        # Malformed date fails closed.
        ledger = self._ledger(evidence=executed, valid_until="not-a-date")
        self.assertFalse(
            ledger.is_validated(
                "audit.example/detector",
                "language_coverage.en",
                today=date(2026, 11, 11),
            )
        )

    def test_evidence_resolver_verifies_executed_artifacts(self):
        from textforensics.policy import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceLabel,
            EvidenceRef,
            EvidenceTier,
        )

        def ledger_with_resolver(resolver):
            ledger = CapabilityLedger(evidence_resolver=resolver)
            ledger.register(
                CapabilityClaim(
                    detector_id="audit.example/detector",
                    capability="language_coverage.en",
                    tier=EvidenceTier.VALIDATED,
                    evidence=[
                        EvidenceRef(
                            label=EvidenceLabel.EXECUTED,
                            tier=EvidenceTier.VALIDATED,
                            artifact="run/en.json",
                        )
                    ],
                    valid_until="2099-01-01",
                )
            )
            return ledger

        # Resolver says the artifact does not exist -> not validated.
        self.assertFalse(
            ledger_with_resolver({"run/en.json": False}).is_validated(
                "audit.example/detector", "language_coverage.en"
            )
        )
        # Resolver confirms it -> validated.
        self.assertTrue(
            ledger_with_resolver({"run/en.json": True}).is_validated(
                "audit.example/detector", "language_coverage.en"
            )
        )
        # No resolver: existence is unchecked (documented limitation),
        # the EXECUTED label alone carries the claim.
        self.assertTrue(
            ledger_with_resolver(None).is_validated(
                "audit.example/detector", "language_coverage.en"
            )
        )

    def test_duplicate_registration_latest_wins(self):
        from textforensics.policy import (
            CapabilityClaim,
            CapabilityLedger,
            EvidenceLabel,
            EvidenceRef,
            EvidenceTier,
        )

        executed = [
            EvidenceRef(
                label=EvidenceLabel.EXECUTED,
                tier=EvidenceTier.VALIDATED,
                artifact="run/en.json",
            )
        ]
        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="d",
                capability="c",
                tier=EvidenceTier.VALIDATED,
                evidence=executed,
                valid_until="2099-01-01",
            )
        )
        # A later expired registration replaces the current claim: the
        # old valid claim is NOT resurrected.
        ledger.register(
            CapabilityClaim(
                detector_id="d",
                capability="c",
                tier=EvidenceTier.VALIDATED,
                evidence=executed,
                valid_until="2000-01-01",
            )
        )
        self.assertIsNone(ledger.get("d", "c"))
        self.assertEqual(len(ledger.claims()["d"]), 2)  # history preserved
        # And the reverse order: a later valid claim replaces an expired one.
        ledger2 = CapabilityLedger()
        ledger2.register(
            CapabilityClaim(
                detector_id="d",
                capability="c",
                tier=EvidenceTier.VALIDATED,
                evidence=executed,
                valid_until="2000-01-01",
            )
        )
        ledger2.register(
            CapabilityClaim(
                detector_id="d",
                capability="c",
                tier=EvidenceTier.VALIDATED,
                evidence=executed,
                valid_until="2099-01-01",
            )
        )
        self.assertTrue(ledger2.is_validated("d", "c"))

    def test_policy_evaluation_agrees_with_effectiveness(self):
        from textforensics.policy import CapabilityPolicy, CapabilityPolicyEngine

        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="calibration-validated",
                description="Calibration requires validated claims.",
                required_capabilities=[("language_coverage.en", "validated")],
                action_on_failure="reject",
            )
        )
        # VALIDATED without EXECUTED evidence must fail the policy.
        results = engine.evaluate(self._ledger(), "audit.example/detector")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].passed)
        # VALIDATED with EXECUTED evidence passes.
        from textforensics.policy import EvidenceLabel, EvidenceRef

        good = self._ledger(
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=__import__(
                        "textforensics.policy", fromlist=["EvidenceTier"]
                    ).EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ]
        )
        results = engine.evaluate(good, "audit.example/detector")
        self.assertTrue(results[0].passed)

    def test_legacy_trust_map_view_agrees(self):
        from textforensics.policy import EvidenceLabel, EvidenceRef, EvidenceTier
        from textforensics.trust import trust_map_from_capability_ledger

        bad = self._ledger()
        trust_map = trust_map_from_capability_ledger(bad)
        dim = trust_map.dimension("language")
        self.assertIsNotNone(dim)
        self.assertNotEqual(dim.state, "supported")
        good = self._ledger(
            evidence=[
                EvidenceRef(
                    label=EvidenceLabel.EXECUTED,
                    tier=EvidenceTier.VALIDATED,
                    artifact="run/en.json",
                )
            ]
        )
        trust_map = trust_map_from_capability_ledger(good)
        dim = trust_map.dimension("language")
        self.assertEqual(dim.state, "supported")


class C10OverallTests(unittest.TestCase):
    """C10 (coordinator follow-up): overall ``strong`` requires EXACTLY
    the declared dimension set (name-set equality), never mere count
    equality — in both derivation paths (``trust._overall_state`` for
    v2, ``validation._overall_state_v3`` for v3).

    Note: ``TrustDimension`` itself rejects undeclared names at
    construction, so rogue-name cases are exercised with duck-typed
    dimensions (the derivation functions only read ``.dimension`` and
    ``.state``) — exactly the shape untrusted/map-level data takes
    before it is validated. The one-dimension case uses a real
    ``TrustDimension``: a single declared dimension, supported, is
    not the declared SET and must never derive ``strong``."""

    def _dim(self, name: str, state: str = "supported"):
        from textforensics.trust import TrustDimension

        return TrustDimension(dimension=name, state=state, reason="synthetic")

    def _rogue(self, name: str, state: str = "supported"):
        return SimpleNamespace(dimension=name, state=state)

    def _declared(self):
        from textforensics.schema import DECLARED_TRUST_MAP_DIMENSIONS

        return DECLARED_TRUST_MAP_DIMENSIONS

    def test_one_dimension_map_never_strong(self):
        from textforensics.trust import _overall_state
        from textforensics.validation import _overall_state_v3

        one = [self._dim("language")]
        self.assertNotEqual(_overall_state(one), "strong")
        self.assertNotEqual(_overall_state_v3(one), "strong")

    def test_ten_rogue_dimensions_never_strong(self):
        from textforensics.trust import _overall_state
        from textforensics.validation import _overall_state_v3

        rogue = [self._rogue(f"rogue_dimension_{i}") for i in range(10)]
        self.assertNotEqual(_overall_state(rogue), "strong")
        self.assertNotEqual(_overall_state_v3(rogue), "strong")

    def test_nine_declared_plus_one_rogue_never_strong(self):
        from textforensics.trust import _overall_state
        from textforensics.validation import _overall_state_v3

        declared = sorted(self._declared())
        dims = [self._dim(name) for name in declared[:9]]
        dims.append(self._rogue("rogue_dimension"))
        self.assertNotEqual(_overall_state(dims), "strong")
        self.assertNotEqual(_overall_state_v3(dims), "strong")

    def test_exact_declared_set_all_supported_is_strong(self):
        from textforensics.trust import _overall_state
        from textforensics.validation import _overall_state_v3

        dims = [self._dim(name) for name in sorted(self._declared())]
        self.assertEqual(_overall_state(dims), "strong")
        self.assertEqual(_overall_state_v3(dims), "strong")

    def test_declared_set_constant_is_the_trust_dimensions_alias(self):
        from textforensics.schema import DECLARED_TRUST_MAP_DIMENSIONS
        from textforensics.trust import TRUST_DIMENSIONS

        self.assertEqual(DECLARED_TRUST_MAP_DIMENSIONS, frozenset(TRUST_DIMENSIONS))
        self.assertEqual(len(DECLARED_TRUST_MAP_DIMENSIONS), 10)


# ---------------------------------------------------------------------------
# W2 defect fix — duplicate identity/proof types + sample-only proof
# ---------------------------------------------------------------------------
# Parent review (2026-11-11) found InferenceIdentity / DisjointnessProof
# each defined twice (evidence.py vs calibration.py / benchmark.py) and a
# sample-only proof (status "verified", group_overlap_count == -1, i.e.
# group disjointness never evaluated) conferring held-out eligibility.
# These tests are RED on the integrated audit-w2 head (597bfdd) and must
# turn green only via the unification + predicate fix.
# ---------------------------------------------------------------------------


class DefectFixTypesTests(unittest.TestCase):
    def _eligible_setup(self, tmp: str):
        """An otherwise-eligible record + inputs; returns (record, inputs, fingerprint)."""
        from textforensics.evidence import EvidenceRegistry

        root = Path(tmp)
        fingerprint, bench_hash, run_hash = _write_artifacts(root)
        record = _v2_record(
            detector_id="a",
            detector_version="1",
            benchmark_fingerprint=fingerprint,
            benchmark_hash=bench_hash,
            run_hash=run_hash,
        )
        registry = EvidenceRegistry(records=[record])
        return record, _eligible_inputs(registry, root), fingerprint

    def _proof(self, *, group_overlap_count: int, fingerprint: str):
        from textforensics.benchmark import DisjointnessProof

        return DisjointnessProof(
            status="verified",
            overlap_count=0,
            group_overlap_count=group_overlap_count,
            training_count=100,
            evaluation_count=200,
            training_hash=hex64(10),
            evaluation_hash=fingerprint,
            errors=(),
        )

    def test_sample_only_proof_is_ineligible(self):
        """A 'verified' proof that never evaluated group overlap must not
        confer held-out eligibility."""
        from textforensics.evidence import check_record_eligibility

        with tempfile.TemporaryDirectory() as tmp:
            record, inputs, fingerprint = self._eligible_setup(tmp)
            verdict = check_record_eligibility(
                record,
                identity=inputs["identity"],
                disjointness=self._proof(group_overlap_count=-1, fingerprint=fingerprint),
                artifact_verification=inputs["artifact_verification"],
                now=NOW,
            )
            self.assertFalse(verdict.eligible)
            self.assertTrue(
                any("group overlap" in reason for reason in verdict.reasons),
                f"a reason must name the unevaluated group overlap: {verdict.reasons}",
            )

    def test_full_proof_is_eligible(self):
        """Control: the same record with group overlap evaluated and zero
        stays eligible — the contrast the sample-only test pins."""
        from textforensics.evidence import check_record_eligibility

        with tempfile.TemporaryDirectory() as tmp:
            record, inputs, fingerprint = self._eligible_setup(tmp)
            verdict = check_record_eligibility(
                record,
                identity=inputs["identity"],
                disjointness=self._proof(group_overlap_count=0, fingerprint=fingerprint),
                artifact_verification=inputs["artifact_verification"],
                now=NOW,
            )
            self.assertTrue(verdict.eligible, f"full proof must stay eligible: {verdict.reasons}")
            self.assertEqual(verdict.reasons, ())

    def test_empty_training_hash_is_ineligible(self):
        """Compensation for the unification dropping evidence.py's old
        empty-hash constructor rejection (``""`` is benchmark.py's
        'could not hash' sentinel): the predicate itself refuses a
        proof whose training hash is missing or empty."""
        from textforensics.benchmark import DisjointnessProof
        from textforensics.evidence import check_record_eligibility

        with tempfile.TemporaryDirectory() as tmp:
            record, inputs, fingerprint = self._eligible_setup(tmp)
            proof = DisjointnessProof(
                status="verified",
                overlap_count=0,
                group_overlap_count=0,
                training_count=100,
                evaluation_count=200,
                training_hash="",
                evaluation_hash=fingerprint,
                errors=(),
            )
            verdict = check_record_eligibility(
                record,
                identity=inputs["identity"],
                disjointness=proof,
                artifact_verification=inputs["artifact_verification"],
                now=NOW,
            )
            self.assertFalse(verdict.eligible)
            self.assertIn(
                "disjointness training and evaluation hashes are not distinct",
                verdict.reasons,
            )

    def test_types_are_the_same_object(self):
        """The canonical types are one class object in every module that
        imports them, so the duplication can never silently return."""
        import textforensics
        from textforensics import benchmark, calibration, evidence

        self.assertIs(evidence.InferenceIdentity, calibration.InferenceIdentity)
        self.assertIs(evidence.DisjointnessProof, benchmark.DisjointnessProof)
        self.assertIs(calibration.DisjointnessProof, benchmark.DisjointnessProof)
        self.assertIs(textforensics.InferenceIdentity, evidence.InferenceIdentity)
        self.assertIs(textforensics.DisjointnessProof, evidence.DisjointnessProof)

    def test_identity_contracts_reconciled(self):
        """A fully-bound identity (all 8 fields, SHA-256 config_hash) is
        accepted by the CalibrationManager; a partially-bound identity is
        reported as unbound by the eligibility predicate (not silently
        accepted as fully bound) and refused by the manager's
        identity-selection path."""
        from textforensics.calibration import (
            CalibrationCurve,
            CalibrationError,
            CalibrationManager,
            DatasetReference,
        )
        from textforensics.evidence import InferenceIdentity, check_record_eligibility

        full = InferenceIdentity(
            detector_id="det1",
            detector_version="1.0",
            provider="local",
            model="builtin-heuristic-0.1.0",
            config_hash=hex64(5),
            native_score_semantics="probability_higher_means_ai",
            calibration_id="cal1",
            regime="unedited",
        )
        self.assertTrue(full.is_fully_bound)
        with tempfile.TemporaryDirectory() as tmp:
            manager = CalibrationManager(tmp)
            stored = manager.store(
                detector_id="det1",
                detector_version="1.0",
                curve=CalibrationCurve(
                    method="platt",
                    parameters={"A": 1.0, "B": 0.0},
                    reference_dataset_hash=hex64(1),
                    reference_dataset_name="test",
                    calibrated_at="2024-01-01T00:00:00Z",
                    sample_count=200,
                ),
                calibration_id="cal1",
                created_at="2024-01-01T00:00:00+00:00",
                identity=full,
                fit_dataset=DatasetReference(
                    name="fit", fingerprint_sha256=hex64(2), split="train", sample_count=200
                ),
                evaluation_dataset=DatasetReference(
                    name="eval", fingerprint_sha256=hex64(3), split="test", sample_count=200
                ),
                disjointness={"strategy": "disjoint_sample_ids", "evidence": "ids differ"},
                metrics={"brier": 0.10, "ece": 0.05, "log_loss": 0.30},
                code_version="abc123",
                run_artifact_sha256=hex64(4),
            )
            found = manager.get_for_identity(full)
            self.assertIsNotNone(found)
            self.assertEqual(found.artifact_id, stored.artifact_id)
            self.assertTrue(found.matches_identity(full))

            partial = InferenceIdentity(
                detector_id="det1",
                detector_version="1.0",
                provider="local",
            )
            self.assertFalse(partial.is_fully_bound)
            self.assertFalse(found.matches_identity(partial))
            with self.assertRaises(CalibrationError):
                manager.get_for_identity(partial)

        with tempfile.TemporaryDirectory() as tmp:
            record, inputs, fingerprint = self._eligible_setup(tmp)
            partial_identity = InferenceIdentity(
                detector_id="a",
                detector_version="1",
                provider="prov",
                regime="human_only",
            )
            self.assertFalse(partial_identity.is_fully_bound)
            verdict = check_record_eligibility(
                record,
                identity=partial_identity,
                disjointness=self._proof(group_overlap_count=0, fingerprint=fingerprint),
                artifact_verification=inputs["artifact_verification"],
                now=NOW,
            )
            self.assertIn("provider", verdict.unbound_identity_fields)

    def test_sample_only_proof_is_not_held_out_in_evaluate_threshold(self):
        """Same gap in the calibration evaluation entry point: a verified
        sample-only proof must not yield a held_out evaluation."""
        from textforensics.benchmark import prove_disjointness
        from textforensics.calibration import evaluate_threshold

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cal_path = root / "cal.jsonl"
            eval_path = root / "eval.jsonl"
            cal_path.write_text(
                '{"label": "human", "text": "A calibration sentence."}\n'
                '{"label": "ai", "text": "A calibration machine sentence."}\n',
                encoding="utf-8",
            )
            eval_path.write_text(
                '{"label": "human", "text": "A completely different human sentence."}\n'
                '{"label": "ai", "text": "A completely different machine sentence."}\n',
                encoding="utf-8",
            )
            full = prove_disjointness(cal_path, eval_path)
            self.assertEqual(full.status, "verified")
            self.assertEqual(full.group_overlap_count, 0)
            result = evaluate_threshold(eval_path, 0.5, disjointness_proof=full)
            self.assertEqual(result.evaluation_mode, "held_out")
            # Rebind the sample-only proof to these files: same hashes as
            # the full proof, only the group overlap is unevaluated.
            from textforensics.benchmark import DisjointnessProof

            sample_only = DisjointnessProof(
                status="verified",
                overlap_count=0,
                group_overlap_count=-1,
                training_count=full.training_count,
                evaluation_count=full.evaluation_count,
                training_hash=full.training_hash,
                evaluation_hash=full.evaluation_hash,
                errors=(),
            )
            with self.assertRaises(ValueError, msg="sample-only proof must not be held out"):
                evaluate_threshold(eval_path, 0.5, disjointness_proof=sample_only)
            diagnostic = evaluate_threshold(
                eval_path, 0.5, disjointness_proof=sample_only, diagnostic=True
            )
            self.assertEqual(diagnostic.evaluation_mode, "diagnostic")

    def test_sample_only_proof_is_not_held_out_in_benchmark(self):
        """Same gap in benchmark_with_calibration_jsonl: a verified
        sample-only proof must not yield held_out_evaluation."""
        from textforensics.benchmark import (
            benchmark_with_calibration_jsonl,
            calibrate_threshold_jsonl,
            prove_disjointness,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cal_path = root / "cal.jsonl"
            eval_path = root / "eval.jsonl"
            rows = (
                '{"label": "human", "text": "Calibration human one."}\n'
                '{"label": "ai", "text": "Calibration machine one."}\n'
            )
            cal_path.write_text(rows, encoding="utf-8")
            eval_path.write_text(
                '{"label": "human", "text": "Evaluation human one."}\n'
                '{"label": "ai", "text": "Evaluation machine one."}\n',
                encoding="utf-8",
            )
            artifact = calibrate_threshold_jsonl(cal_path, target_fpr=0.0)
            full = prove_disjointness(cal_path, eval_path)
            held_out = benchmark_with_calibration_jsonl(
                eval_path, artifact, disjointness_proof=full
            )
            self.assertEqual(held_out["mode"], "held_out_evaluation")
            from textforensics.benchmark import DisjointnessProof

            sample_only = DisjointnessProof(
                status="verified",
                overlap_count=0,
                group_overlap_count=-1,
                training_count=full.training_count,
                evaluation_count=full.evaluation_count,
                training_hash=full.training_hash,
                evaluation_hash=full.evaluation_hash,
                errors=(),
            )
            with self.assertRaises(ValueError, msg="sample-only proof must not be held out"):
                benchmark_with_calibration_jsonl(
                    eval_path, artifact, disjointness_proof=sample_only
                )
            diagnostic = benchmark_with_calibration_jsonl(
                eval_path, artifact, disjointness_proof=sample_only, diagnostic=True
            )
            self.assertEqual(diagnostic["mode"], "diagnostic")


class DefectFixKillTests(unittest.TestCase):
    """Kill tests for the 11 changed-function mutants the targeted
    cosmic-ray proof (2026-11-12, 683 mutants) could not kill with the
    F probes + DefectFixTypesTests alone. Each method pins a real
    contract of the changed code and was verified RED on its mutant by
    hand-applying the mutant with cosmic-ray's mutate_code. The 16
    other proof survivors are proven equivalent on closed domains (see
    the fix report) and need no test. ``test_retracted_record_is_
    ineligible`` is a behaviour pin, not a kill: the ``record.status
    != 'active'`` -> ``>`` mutant is equivalent because 'active' is
    the minimum of the {'active', 'retracted'} domain."""

    def _eligible_setup(self, tmp: str):
        """An otherwise-eligible record + inputs (mirrors
        DefectFixTypesTests._eligible_setup)."""
        from textforensics.evidence import EvidenceRegistry

        root = Path(tmp)
        fingerprint, bench_hash, run_hash = _write_artifacts(root)
        record = _v2_record(
            detector_id="a",
            detector_version="1",
            benchmark_fingerprint=fingerprint,
            benchmark_hash=bench_hash,
            run_hash=run_hash,
        )
        registry = EvidenceRegistry(records=[record])
        return record, _eligible_inputs(registry, root), fingerprint

    def _retracted_setup(self, tmp: str):
        """An otherwise-eligible record whose status is 'retracted'."""
        from textforensics.evidence import EvidenceRegistry

        root = Path(tmp)
        fingerprint, bench_hash, run_hash = _write_artifacts(root)
        record = _v2_record(
            detector_id="a",
            detector_version="1",
            benchmark_fingerprint=fingerprint,
            benchmark_hash=bench_hash,
            run_hash=run_hash,
            status="retracted",
        )
        registry = EvidenceRegistry(records=[record])
        return record, _eligible_inputs(registry, root)

    def _eval_files(self, root: Path):
        """(cal_path, eval_path) with disjoint synthetic rows."""
        cal_path = root / "cal.jsonl"
        eval_path = root / "eval.jsonl"
        cal_path.write_text(
            '{"label": "human", "text": "A calibration sentence."}\n'
            '{"label": "ai", "text": "A calibration machine sentence."}\n',
            encoding="utf-8",
        )
        eval_path.write_text(
            '{"label": "human", "text": "A completely different human sentence."}\n'
            '{"label": "ai", "text": "A completely different machine sentence."}\n',
            encoding="utf-8",
        )
        return cal_path, eval_path

    def test_retracted_record_is_ineligible(self):
        """A retracted record is ineligible even when everything else
        passes: the status check must fire for the only non-active
        status the constructor allows. Behaviour pin for the
        ``record.status != 'active'`` check (the ``!=`` -> ``>``
        mutant is equivalent: 'active' is the minimum of the
        {'active', 'retracted'} domain, so ``>`` agrees with ``!=``)."""
        from textforensics.evidence import check_record_eligibility

        with tempfile.TemporaryDirectory() as tmp:
            record, inputs = self._retracted_setup(tmp)
            verdict = check_record_eligibility(
                record,
                identity=inputs["identity"],
                disjointness=inputs["disjointness"],
                artifact_verification=inputs["artifact_verification"],
                now=NOW,
            )
            self.assertFalse(verdict.eligible)
            self.assertTrue(
                any("record status is 'retracted'" in reason for reason in verdict.reasons),
                f"retracted status must be reported: {verdict.reasons}",
            )

    def test_check_record_eligibility_params_are_keyword_only(self):
        """The eligibility inputs after the record are keyword-only:
        passing the identity positionally must raise TypeError. Kills
        the ``*,`` -> ``/,`` mutant in the signature."""
        from textforensics.evidence import check_record_eligibility

        with tempfile.TemporaryDirectory() as tmp:
            record, inputs, _fingerprint = self._eligible_setup(tmp)
            with self.assertRaises(TypeError):
                check_record_eligibility(record, inputs["identity"])

    def test_evaluate_threshold_params_are_keyword_only(self):
        """Same keyword-only contract for evaluate_threshold: the
        calibration hash must not be passable positionally. Kills the
        ``*,`` -> ``/,`` mutant in the signature."""
        from textforensics.calibration import evaluate_threshold

        with tempfile.TemporaryDirectory() as tmp:
            _cal_path, eval_path = self._eval_files(Path(tmp))
            with self.assertRaises(TypeError):
                evaluate_threshold(eval_path, 0.5, "abc123")

    def test_benchmark_jsonl_params_are_keyword_only(self):
        """Same keyword-only contract for benchmark_with_calibration_
        jsonl: the strict flag must not be passable positionally. Kills
        the ``*,`` -> ``/,`` mutant in the signature."""
        from textforensics.benchmark import (
            benchmark_with_calibration_jsonl,
            calibrate_threshold_jsonl,
        )

        with tempfile.TemporaryDirectory() as tmp:
            cal_path, eval_path = self._eval_files(Path(tmp))
            artifact = calibrate_threshold_jsonl(cal_path, target_fpr=0.0)
            with self.assertRaises(TypeError):
                benchmark_with_calibration_jsonl(eval_path, artifact, True)

    def test_evaluate_threshold_same_dataset_hash_identity(self):
        """The same-dataset guard compares hash VALUES, not object
        identity: a calibration hash equal to the test hash but a
        distinct string object must still raise. Kills the
        ``test_hash == calibration_dataset_hash`` -> ``is`` mutant."""
        from textforensics.benchmark import dataset_sha256
        from textforensics.calibration import evaluate_threshold

        with tempfile.TemporaryDirectory() as tmp:
            _cal_path, eval_path = self._eval_files(Path(tmp))
            test_hash = dataset_sha256(eval_path)
            fresh = "".join(test_hash)
            self.assertEqual(fresh, test_hash)
            self.assertIsNot(fresh, test_hash, "test setup: hashes must be distinct objects")
            with self.assertRaises(ValueError):
                evaluate_threshold(eval_path, 0.5, calibration_dataset_hash=fresh)

    def test_evaluate_threshold_overlap_count_is_zero(self):
        """Both held-out and sample-only-diagnostic results report a
        zero overlap count and no contamination detected: the
        ``overlap_count = 0`` and ``contamination_detected = False``
        assignments are returned values, not dead initialisations.
        Kills both NumberReplacer mutants on the ``0`` literal and the
        ``contamination_detected = False`` -> ``True`` mutant in the
        sample-only branch."""
        from textforensics.benchmark import DisjointnessProof, prove_disjointness
        from textforensics.calibration import evaluate_threshold

        with tempfile.TemporaryDirectory() as tmp:
            cal_path, eval_path = self._eval_files(Path(tmp))
            full = prove_disjointness(cal_path, eval_path)
            held_out = evaluate_threshold(eval_path, 0.5, disjointness_proof=full)
            self.assertEqual(held_out.evaluation_mode, "held_out")
            self.assertEqual(held_out.overlap_count, 0)
            self.assertIs(held_out.contamination_detected, False)
            sample_only = DisjointnessProof(
                status="verified",
                overlap_count=0,
                group_overlap_count=-1,
                training_count=full.training_count,
                evaluation_count=full.evaluation_count,
                training_hash=full.training_hash,
                evaluation_hash=full.evaluation_hash,
                errors=(),
            )
            diagnostic = evaluate_threshold(
                eval_path, 0.5, disjointness_proof=sample_only, diagnostic=True
            )
            self.assertEqual(diagnostic.evaluation_mode, "diagnostic")
            self.assertEqual(diagnostic.overlap_count, 0)
            self.assertIs(diagnostic.contamination_detected, False)

    def test_evaluate_threshold_no_proof_contamination_is_false(self):
        """Evaluating with no proof at all is diagnostic with no
        contamination detected. Kills the ``contamination_detected =
        False`` -> ``True`` mutant in the no-proof branch."""
        from textforensics.calibration import evaluate_threshold

        with tempfile.TemporaryDirectory() as tmp:
            _cal_path, eval_path = self._eval_files(Path(tmp))
            result = evaluate_threshold(eval_path, 0.5)
            self.assertEqual(result.evaluation_mode, "diagnostic")
            self.assertEqual(result.disjointness_status, "unknown")
            self.assertEqual(result.overlap_count, -1)
            self.assertIs(result.contamination_detected, False)

    def test_evaluate_threshold_strict_default(self):
        """The strict default is True: calling evaluate_threshold
        without ``strict`` on a file with an invalid JSON line must
        raise DatasetFormatError instead of silently skipping the line.
        Kills the ``strict: bool = True`` -> ``False`` mutant."""
        from textforensics.benchmark import DatasetFormatError
        from textforensics.calibration import evaluate_threshold

        with tempfile.TemporaryDirectory() as tmp:
            eval_path = Path(tmp) / "eval.jsonl"
            eval_path.write_text(
                '{"label": "human", "text": "A valid human sentence."}\n'
                "this is not json\n"
                '{"label": "ai", "text": "A valid machine sentence."}\n',
                encoding="utf-8",
            )
            with self.assertRaises(DatasetFormatError):
                evaluate_threshold(eval_path, 0.5)

    def test_benchmark_jsonl_strict_default(self):
        """Same strict default for benchmark_with_calibration_jsonl:
        an invalid JSON line must raise DatasetFormatError when
        ``strict`` is not passed. Kills the ``strict: bool = True`` ->
        ``False`` mutant."""
        from textforensics.benchmark import (
            DatasetFormatError,
            benchmark_with_calibration_jsonl,
            calibrate_threshold_jsonl,
        )

        with tempfile.TemporaryDirectory() as tmp:
            cal_path, eval_path = self._eval_files(Path(tmp))
            eval_path.write_text(
                '{"label": "human", "text": "A completely different human sentence."}\n'
                "this is not json\n"
                '{"label": "ai", "text": "A completely different machine sentence."}\n',
                encoding="utf-8",
            )
            artifact = calibrate_threshold_jsonl(cal_path, target_fpr=0.0)
            with self.assertRaises(DatasetFormatError):
                benchmark_with_calibration_jsonl(eval_path, artifact)

    def test_benchmark_jsonl_overlap_count_is_zero(self):
        """Both held-out and sample-only-diagnostic benchmark runs
        report a zero overlap count. Kills both NumberReplacer mutants
        on the ``overlap = 0`` literal."""
        from textforensics.benchmark import (
            DisjointnessProof,
            benchmark_with_calibration_jsonl,
            calibrate_threshold_jsonl,
            prove_disjointness,
        )

        with tempfile.TemporaryDirectory() as tmp:
            cal_path, eval_path = self._eval_files(Path(tmp))
            artifact = calibrate_threshold_jsonl(cal_path, target_fpr=0.0)
            full = prove_disjointness(cal_path, eval_path)
            held_out = benchmark_with_calibration_jsonl(
                eval_path, artifact, disjointness_proof=full
            )
            self.assertEqual(held_out["mode"], "held_out_evaluation")
            self.assertEqual(held_out["overlap_count"], 0)
            sample_only = DisjointnessProof(
                status="verified",
                overlap_count=0,
                group_overlap_count=-1,
                training_count=full.training_count,
                evaluation_count=full.evaluation_count,
                training_hash=full.training_hash,
                evaluation_hash=full.evaluation_hash,
                errors=(),
            )
            diagnostic = benchmark_with_calibration_jsonl(
                eval_path, artifact, disjointness_proof=sample_only, diagnostic=True
            )
            self.assertEqual(diagnostic["mode"], "diagnostic")
            self.assertEqual(diagnostic["overlap_count"], 0)


if __name__ == "__main__":
    unittest.main()
