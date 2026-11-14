"""Audit W4 worker C — regression tests for S04, S05, S09, S10, S21, S22, CORE-04.

Every test states its expectation from the audit report / plan, not from
current output (red-tests-first). Synthetic data only; no real user text.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
import tempfile
from datetime import date
from io import StringIO
from pathlib import Path

import pytest

from textforensics.calibration import (
    CalibrationArtifact,
    CalibrationCurve,
    CalibrationError,
)
from textforensics.model_card import ModelCard
from textforensics.observatory import DriftObservatory
from textforensics.policy import (
    CapabilityClaim,
    CapabilityLedger,
    CapabilityPolicy,
    CapabilityPolicyEngine,
    EnterprisePolicy,
    EnterprisePolicyEngine,
    EvidenceLabel,
    EvidenceRef,
    EvidenceTier,
    compute_policy_digest,
    create_calibration_policy,
    ledger_to_trust_dimension,
)
from textforensics.probe_metrics import fpr_at_threshold, ks_statistic
from textforensics.probe_runs import (
    ProbeRunError,
    compute_run_metrics,
    load_run,
    validate_run_manifest,
)
from textforensics.result_codec import ResultCodec, decode_result

TODAY = date(2026, 11, 14)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _corpus() -> dict:
    return {
        "schema": "textforensics.drift-corpus/v1",
        "samples": [
            {"id": "s1", "text": "human probe sentence one.", "metadata": {"origin": "human"}},
            {"id": "s2", "text": "human probe sentence two.", "metadata": {"origin": "human"}},
        ],
    }


def _record(sample_id, *, score, verdict, text_sha=None, direction="higher_means_ai",
            threshold=0.5, detector_id="det-a"):
    return {
        "sample_id": sample_id,
        "text_sha256": text_sha if text_sha is not None else _sha(
            "human probe sentence one." if sample_id == "s1" else "human probe sentence two."
        ),
        "detector_id": detector_id,
        "detector_version": "1.0",
        "detector_family": "test",
        "execution": "local",
        "observed_at": "2026-01-01T00:00:00+00:00",
        "score": score,
        "score_semantics": "test",
        "native_score_direction": direction,
        "verdict": verdict,
        "threshold": threshold,
    }


def _snapshot(obs, records, *, snapshot_id="snap", failures=None):
    return {
        "schema": "textforensics.drift-snapshot/v1",
        "snapshot_id": snapshot_id,
        "taken_at": "2026-01-01T00:00:00+00:00",
        "corpus_sha256": obs.corpus_sha256,
        "detector_ids": sorted({r["detector_id"] for r in records}),
        "record_count": len(records),
        "failure_count": len(failures or []),
        "records": records,
        "failures": failures or [],
    }


def _hex64(n: int) -> str:
    return (f"{n:064x}")[-64:]


def _eligible_artifact() -> CalibrationArtifact:
    """A probability-eligible calibration artifact (same shape as the
    W2 fixture in tests/test_calibration.py)."""
    from textforensics.calibration import DatasetReference

    return CalibrationArtifact(
        artifact_id="det1:cal1",
        detector_id="det1",
        detector_version="1.0",
        curve=CalibrationCurve(method="platt", parameters={"A": 1.0, "B": 0.0}),
        calibration_id="cal1",
        created_at="2024-01-01T00:00:00+00:00",
        fit_dataset=DatasetReference(
            name="fit", fingerprint_sha256=_hex64(2), split="train", sample_count=200
        ),
        evaluation_dataset=DatasetReference(
            name="eval", fingerprint_sha256=_hex64(3), split="test", sample_count=200
        ),
        disjointness={"strategy": "disjoint_sample_ids", "evidence": "ids differ"},
        metrics={"brier": 0.10, "ece": 0.05, "log_loss": 0.30},
        code_version="abc123",
        run_artifact_sha256=_hex64(4),
        provider="local",
        model="builtin-heuristic-0.1.0",
        config_hash=_hex64(5),
        native_score_semantics="probability_higher_means_ai",
        regime="unedited",
    )


def _valid_card_dict() -> dict:
    return {
        "schema_version": "1.0.0",
        "metadata": {
            "version": "1.0.0",
            "generated_at": "2026-11-07T00:00:00+00:00",
            "generated_by": "test",
        },
        "model_details": {
            "name": "T",
            "version": "0.1.0",
            "detector_id": "d",
            "detector_family": "f",
            "architecture": "a",
            "framework": "f",
            "license": "AGPL-3.0-or-later",
            "owner": "o",
            "contact": "c",
        },
        "intended_use": {
            "primary_use_cases": ["u"],
            "out_of_scope": ["x"],
            "target_users": ["t"],
        },
        "metrics": [{"name": "acc", "value": 0.5, "unit": "x"}],
        "quantitative_analysis": {
            "metrics": [],
            "roc_auc": 0.9,
            "pr_auc": 0.8,
            "calibration_error": 0.02,
        },
    }


# --------------------------------------------------------------------- S04


class TestS04CapabilityEvidence:
    def test_expired_validated_claim_without_evidence_is_not_supported(self):
        """Audit repro /state_primary/capability_invalid_expired."""
        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="d",
                capability="probability_calibration",
                tier=EvidenceTier.VALIDATED,
                evidence=[],
                valid_until="2000-01-01",
            )
        )
        (result,) = create_calibration_policy().evaluate(ledger, "d", today=TODAY)
        assert result.passed is False
        dim = ledger_to_trust_dimension(ledger, "d", "probability_calibration", today=TODAY)
        assert dim.state == "unknown"

    def test_superseded_claim_does_not_lift_trust_dimension(self):
        """A newer ineffective claim replaces the old one as current:
        get(), policy evaluation and the Trust Map must agree."""
        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="d",
                capability="language_coverage.en",
                tier=EvidenceTier.VALIDATED,
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel.EXECUTED,
                        tier=EvidenceTier.VALIDATED,
                        artifact="art://ev1",
                    )
                ],
                valid_until="2030-01-01",
            )
        )
        ledger.register(
            CapabilityClaim(
                detector_id="d",
                capability="language_coverage.en",
                tier=EvidenceTier.VALIDATED,
                evidence=[],
                valid_until="2000-01-01",
            )
        )
        assert ledger.get("d", "language_coverage.en", today=TODAY) is None
        dim = ledger_to_trust_dimension(ledger, "d", "language_coverage", today=TODAY)
        assert dim.state == "unknown"
        # And a newer effective claim re-lifts it.
        ledger.register(
            CapabilityClaim(
                detector_id="d",
                capability="language_coverage.en",
                tier=EvidenceTier.VALIDATED,
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel.EXECUTED,
                        tier=EvidenceTier.VALIDATED,
                        artifact="art://ev2",
                    )
                ],
                valid_until="2030-01-01",
            )
        )
        assert ledger.get("d", "language_coverage.en", today=TODAY) is not None
        assert (
            ledger_to_trust_dimension(ledger, "d", "language_coverage", today=TODAY).state
            == "supported"
        )

    def test_reported_only_validated_claim_is_not_effective(self):
        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="d",
                capability="probability_calibration",
                tier=EvidenceTier.VALIDATED,
                evidence=[
                    EvidenceRef(
                        label=EvidenceLabel.REPORTED,
                        tier=EvidenceTier.VALIDATED,
                        artifact="art://x",
                    )
                ],
                valid_until="2030-01-01",
            )
        )
        assert ledger.get("d", "probability_calibration", today=TODAY) is None
        assert (
            ledger_to_trust_dimension(ledger, "d", "probability_calibration", today=TODAY).state
            == "unknown"
        )

    def test_cli_register_surfaces_validation_issues(self, tmp_path):
        """CLI registration must not present an invalid claim as validated:
        the issues are printed and carried in the payload."""
        from textforensics.cli import main

        ledger_path = tmp_path / "capability_ledger.json"
        argv = [
            "textforensics",
            "capability",
            "register",
            "det-a",
            "probability_calibration",
            "--tier",
            "validated",
            "--label",
            "reported",
            "--artifact",
            "art://x",
            "--valid-until",
            "2000-01-01",
            "--ledger",
            str(ledger_path),
        ]
        old_argv, old_out, old_err = sys.argv, sys.stdout, sys.stderr
        try:
            sys.argv = argv
            sys.stdout, sys.stderr = StringIO(), StringIO()
            main()
            out, err = sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_out, old_err
        payload = json.loads(out.split("Registered:")[0])
        assert payload["registered"] is True
        assert payload["issues"], "ineffective claim must carry its validation issues"
        assert payload["effective"] is False
        assert "expired" in " ".join(payload["issues"]).lower()
        assert "warning" in err.lower()

    def test_cli_register_effective_claim_reports_effective(self, tmp_path):
        from textforensics.cli import main

        ledger_path = tmp_path / "capability_ledger.json"
        argv = [
            "textforensics",
            "capability",
            "register",
            "det-a",
            "probability_calibration",
            "--tier",
            "validated",
            "--label",
            "executed",
            "--artifact",
            "art://x",
            "--valid-until",
            "2030-01-01",
            "--ledger",
            str(ledger_path),
        ]
        old_argv, old_out, old_err = sys.argv, sys.stdout, sys.stderr
        try:
            sys.argv = argv
            sys.stdout, sys.stderr = StringIO(), StringIO()
            main()
            out = sys.stdout.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_out, old_err
        payload = json.loads(out.split("Registered:")[0])
        assert payload["issues"] == []
        assert payload["effective"] is True


# --------------------------------------------------------------------- S05


class TestS05ImportedSnapshots:
    def test_add_snapshot_rejects_foreign_sample_ids(self):
        """Audit repro /state_primary/imported_snapshot_unlinked."""
        obs = DriftObservatory(corpus=_corpus())
        records = [
            _record("foreign-1", score=0.9, verdict="human_like", text_sha="0" * 64),
            _record("foreign-2", score=0.1, verdict="ai_like", text_sha="0" * 64),
        ]
        with pytest.raises(ValueError, match="Unknown probe sample"):
            obs.add_snapshot(_snapshot(obs, records))

    def test_add_snapshot_rejects_changed_text_hash(self):
        obs = DriftObservatory(corpus=_corpus())
        records = [_record("s1", score=0.9, verdict="human_like", text_sha="0" * 64)]
        with pytest.raises(ValueError, match="does not match the probe corpus"):
            obs.add_snapshot(_snapshot(obs, records))

    def test_compare_rejects_unlinked_snapshots(self):
        obs = DriftObservatory(corpus=_corpus())
        records = [
            _record("foreign-1", score=0.9, verdict="human_like", text_sha="0" * 64),
            _record("foreign-2", score=0.1, verdict="ai_like", text_sha="0" * 64),
        ]
        snap = _snapshot(obs, records, snapshot_id="base")
        other = _snapshot(obs, records, snapshot_id="cur")
        with pytest.raises(ValueError, match="Unknown probe sample"):
            obs.compare_snapshots(snap, other)

    def test_compare_rejects_duplicate_records_and_bad_counts(self):
        obs = DriftObservatory(corpus=_corpus())
        snap = _snapshot(obs, [_record("s1", score=0.5, verdict="human_like")])
        dup = _snapshot(obs, [
            _record("s1", score=0.5, verdict="human_like"),
            _record("s1", score=0.6, verdict="ai_like"),
        ])
        dup["record_count"] = 2
        with pytest.raises(ValueError, match="uplicate"):
            obs.compare_snapshots(snap, dup)
        bad_count = _snapshot(obs, [_record("s1", score=0.5, verdict="human_like")])
        bad_count["record_count"] = 7
        with pytest.raises(ValueError, match="record_count"):
            obs.add_snapshot(bad_count)

    def test_compare_rejects_malformed_timestamps_and_bad_verdict(self):
        obs = DriftObservatory(corpus=_corpus())
        snap = _snapshot(obs, [_record("s1", score=0.5, verdict="human_like")])
        bad_ts = json.loads(json.dumps(snap))
        bad_ts["records"][0]["observed_at"] = "not-a-date"
        with pytest.raises(ValueError, match="observed_at"):
            obs.add_snapshot(bad_ts)
        bad_verdict = json.loads(json.dumps(snap))
        bad_verdict["records"][0]["verdict"] = "maybe_ai"
        with pytest.raises(ValueError, match="verdict"):
            obs.add_snapshot(bad_verdict)

    def test_load_snapshots_rejects_unlinked_file(self, tmp_path):
        obs = DriftObservatory(corpus=_corpus())
        records = [_record("foreign-1", score=0.9, verdict="human_like", text_sha="0" * 64)]
        path = tmp_path / "store.json"
        path.write_text(
            json.dumps(
                {"schema": "textforensics.drift-snapshot-store/v1",
                 "snapshots": [_snapshot(obs, records)]},
                allow_nan=False,
            ),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Unknown probe sample"):
            obs.load_snapshots(path)
        assert obs.snapshots == []

    def test_failure_only_detector_is_compared_not_dropped(self):
        """A detector with only failures must appear in the comparison
        with claim_allowed False, not vanish from the detector universe."""
        obs = DriftObservatory(corpus=_corpus())
        base = _snapshot(
            obs,
            [_record("s1", score=0.5, verdict="human_like")],
            snapshot_id="base",
            failures=[{"sample_id": "s2", "detector_id": "det-failed",
                       "detector_version": "1.0", "error_type": "timeout",
                       "observed_at": "2026-01-01T00:00:00+00:00"}],
        )
        cur = _snapshot(
            obs,
            [_record("s1", score=0.5, verdict="human_like")],
            snapshot_id="cur",
            failures=[{"sample_id": "s2", "detector_id": "det-failed",
                       "detector_version": "1.0", "error_type": "timeout",
                       "observed_at": "2026-01-01T00:00:00+00:00"}],
        )
        report = obs.compare_snapshots(base, cur)
        ids = [d["detector_id"] for d in report["detectors"]]
        assert "det-failed" in ids
        failed = next(d for d in report["detectors"] if d["detector_id"] == "det-failed")
        assert failed["drift_claim_allowed"] is False
        assert failed["comparable_samples"] == 0

    def test_read_snapshot_file_rejects_bad_direction_and_nan(self, tmp_path):
        obs = DriftObservatory(corpus=_corpus())
        snap = _snapshot(obs, [_record("s1", score=0.5, verdict="human_like")])
        bad = json.loads(json.dumps(snap))
        bad["records"][0]["native_score_direction"] = "sideways"
        path = tmp_path / "snap.json"
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError):
            DriftObservatory.read_snapshot_file(path)
        nan_path = tmp_path / "nan.json"
        nan_path.write_text(json.dumps(snap).replace('"score": 0.5', '"score": NaN'),
                            encoding="utf-8")
        with pytest.raises(ValueError):
            DriftObservatory.read_snapshot_file(nan_path)


# --------------------------------------------------------------------- S09


class TestS09ScoreDirection:
    def test_attacked_slice_tpr_lower_means_ai_audit_repro(self):
        """Audit repro /state_followup/lower_score_direction_ignored:
        human 0.9, AI 0.1, lower-means-AI must yield TPR 1 at FPR 0."""
        records = [
            {"sample_id": "h1", "score": 0.9, "verdict": "human_like",
             "native_score_direction": "lower_means_ai", "threshold": 0.5},
            {"sample_id": "h2", "score": 0.9, "verdict": "human_like",
             "native_score_direction": "lower_means_ai", "threshold": 0.5},
            {"sample_id": "a1", "score": 0.1, "verdict": "ai_like",
             "native_score_direction": "lower_means_ai", "threshold": 0.5},
            {"sample_id": "a2", "score": 0.1, "verdict": "ai_like",
             "native_score_direction": "lower_means_ai", "threshold": 0.5},
        ]
        labels = {"h1": 0, "h2": 0, "a1": 1, "a2": 1}
        slices = {"h1": "human-native", "h2": "human-native",
                  "a1": "ai-paraphrased", "a2": "ai-paraphrased"}
        out = compute_run_metrics(
            current_records=records, baseline_records=None, previous_records=None,
            labels=labels, slices=slices, detector_id="det-a",
        )
        attacked = out["slices"]["ai-paraphrased"]["attacked_tpr"]
        assert attacked["tpr_at_1pct_fpr"] == pytest.approx(1.0)
        assert attacked["achieved_fpr"] == pytest.approx(0.0)
        assert 0.1 <= attacked["threshold"] <= 0.9
        assert attacked["score_direction"] == "lower_means_ai"

    def test_higher_and_lower_affine_equivalent_detectors_agree(self):
        def _run(direction, h_score, a_score):
            records = [
                {"sample_id": "h1", "score": h_score, "verdict": "human_like",
                 "native_score_direction": direction, "threshold": 0.5},
                {"sample_id": "a1", "score": a_score, "verdict": "ai_like",
                 "native_score_direction": direction, "threshold": 0.5},
            ]
            return compute_run_metrics(
                current_records=records, baseline_records=None, previous_records=None,
                labels={"h1": 0, "a1": 1},
                slices={"h1": "human-native", "a1": "ai-paraphrased"},
                detector_id="det-a",
            )["slices"]["ai-paraphrased"]["attacked_tpr"]

        higher = _run("higher_means_ai", 0.1, 0.9)
        lower = _run("lower_means_ai", 0.9, 0.1)
        assert higher["tpr_at_1pct_fpr"] == pytest.approx(lower["tpr_at_1pct_fpr"])
        assert higher["achieved_fpr"] == pytest.approx(lower["achieved_fpr"])

    def test_mixed_known_and_unknown_direction_fails_closed(self):
        records = [
            {"sample_id": "h1", "score": 0.9, "verdict": "human_like",
             "native_score_direction": "lower_means_ai"},
            {"sample_id": "h2", "score": 0.9, "verdict": "human_like"},
        ]
        with pytest.raises(ProbeRunError, match="direction"):
            compute_run_metrics(
                current_records=records, baseline_records=None, previous_records=None,
                labels={"h1": 0, "h2": 0},
                slices={"h1": "human-native", "h2": "human-native"},
                detector_id="det-a",
            )


# --------------------------------------------------------------------- S10


class TestS10Nonfinite:
    def test_ks_statistic_rejects_nan_boundedly(self):
        with pytest.raises(ValueError, match="finite"):
            ks_statistic([float("nan")], [0.0])
        with pytest.raises(ValueError, match="finite"):
            ks_statistic([0.0], [float("inf")])

    def test_fpr_at_threshold_rejects_nan_threshold(self):
        """Audit repro /state_primary/nan_fpr: NaN threshold must not
        fabricate FPR 0.0 for a human score 0.9."""
        with pytest.raises(ValueError, match="finite"):
            fpr_at_threshold([0.9], [0], float("nan"))

    def test_validate_run_manifest_rejects_nan_score(self):
        manifest = _valid_manifest()
        manifest["score_series"] = {"s1": {"score": float("nan"), "verdict": "ai_like"}}
        with pytest.raises(ProbeRunError, match="finite"):
            validate_run_manifest(manifest)

    def test_validate_run_manifest_rejects_nonfinite_metric(self):
        manifest = _valid_manifest()
        manifest["metrics"] = {"slices": {"human-native": {"human_fpr": {"fpr": float("inf")}}}}
        with pytest.raises(ProbeRunError, match="non-finite"):
            validate_run_manifest(manifest)

    def test_load_run_rejects_nan_token(self, tmp_path):
        # The file must actually contain a NaN token: json.dumps with
        # allow_nan=True only emits one when a value is non-finite.
        manifest = _valid_manifest()
        path = tmp_path / "run-r1.json"
        raw = json.dumps(manifest, allow_nan=True).replace('"score": 0.5', '"score": NaN')
        path.write_text(raw, encoding="utf-8")
        with pytest.raises((ProbeRunError, ValueError), match="non-finite|NaN"):
            load_run(path)

    def test_load_snapshots_rejects_nan_token(self, tmp_path):
        obs = DriftObservatory(corpus=_corpus())
        snap = _snapshot(obs, [_record("s1", score=0.5, verdict="human_like")])
        path = tmp_path / "store.json"
        raw = json.dumps({"schema": "textforensics.drift-snapshot-store/v1",
                          "snapshots": [snap]})
        path.write_text(raw.replace('"score": 0.5', '"score": NaN'), encoding="utf-8")
        with pytest.raises(ValueError):
            obs.load_snapshots(path)


def _valid_manifest() -> dict:
    return {
        "schema": "textforensics.probe-run/v1",
        "run_id": "r1",
        "run_at_utc": "2026-01-01T00:00:00Z",
        "corpus_version": "1.0.0",
        "detector_id": "det-a",
        "detector_version": "1.0",
        "scope": "full",
        "corpus_fingerprint": "a" * 64,
        "metrics": {},
        "alerts": [],
        "breaches": [],
        "score_series": {"s1": {"score": 0.5, "verdict": "ai_like"}},
        "scope_statement": "probe run: integrity of the scored corpus only — origin of a verdict "
        "is the detector run recorded here; a clean run does not prove the "
        "detector is correct on unseen text.",
    }


# --------------------------------------------------------------------- S21


class TestS21PartialCalibratedBaseline:
    def test_partial_baseline_withholds_and_records_missing_calibration(self):
        """Audit repro /state_primary/partial_calibrated_baseline: two
        current calibrated items, one baseline item — no KeyError, and
        the missing calibration is recorded as structured evidence."""
        current = [
            {"sample_id": "s", "score": 0.2, "verdict": "human_like",
             "calibrated_ai_probability": 0.2, "calibration_id": "c1"},
            {"sample_id": "t", "score": 0.8, "verdict": "ai_like",
             "calibrated_ai_probability": 0.8, "calibration_id": "c1"},
        ]
        baseline = [
            {"sample_id": "s", "score": 0.2, "verdict": "human_like",
             "calibrated_ai_probability": 0.2, "calibration_id": "c1"},
        ]
        out = compute_run_metrics(
            current_records=current, baseline_records=baseline, previous_records=None,
            labels={"s": 0, "t": 1},
            slices={"s": "human-native", "t": "ai-paraphrased"},
            detector_id="det-a",
        )
        cal = out["overall"]["calibration"]
        assert cal["baseline_ece"] is None
        assert cal["baseline_ece_reason"]
        missing = cal["missing_calibration"]
        assert missing["n_matched"] == 1
        assert missing["n_labelled"] == 2
        assert missing["missing_item_ids"] == ["t"]
        assert "t" in missing["reason"]

    def test_complete_baseline_has_no_missing_calibration(self):
        current = [
            {"sample_id": "s", "score": 0.2, "verdict": "human_like",
             "calibrated_ai_probability": 0.2, "calibration_id": "c1"},
        ]
        baseline = [
            {"sample_id": "s", "score": 0.2, "verdict": "human_like",
             "calibrated_ai_probability": 0.2, "calibration_id": "c1"},
        ]
        out = compute_run_metrics(
            current_records=current, baseline_records=baseline, previous_records=None,
            labels={"s": 0}, slices={"s": "human-native"}, detector_id="det-a",
        )
        cal = out["overall"]["calibration"]
        assert cal["baseline_ece"] is not None
        assert cal["missing_calibration"] is None


# --------------------------------------------------------------------- S22


class TestS22PolicyTiersAndGlob:
    def test_unknown_min_tier_rejected_at_construction(self):
        with pytest.raises(ValueError, match="min_tier|tier"):
            CapabilityPolicy(
                rule_id="r",
                description="d",
                required_capabilities=[("language_coverage", "misspelled-tier")],
            )

    def test_unknown_claim_tier_rejected_at_construction(self):
        """Unsupported tiers are rejected at ingestion (audit §4.2.2 item 1):
        a READABLE claim cannot satisfy a misspelled-tier requirement."""
        with pytest.raises(ValueError, match="tier"):
            CapabilityClaim(
                detector_id="det-a",
                capability="language_coverage",
                tier="bogus",  # type: ignore[arg-type]
                evidence=[],
            )

    def test_string_tier_is_coerced_to_enum(self):
        claim = CapabilityClaim(
            detector_id="det-a",
            capability="language_coverage",
            tier="readable",  # type: ignore[arg-type]
            evidence=[],
        )
        assert claim.tier == EvidenceTier.READABLE

    def test_evaluate_fails_closed_on_unknown_tier_bypassing_construction(self):
        """Defence in depth: even a claim object that bypassed the
        constructor (object.__new__) must not satisfy a policy."""
        claim = object.__new__(CapabilityClaim)
        object.__setattr__(claim, "detector_id", "det-a")
        object.__setattr__(claim, "capability", "language_coverage")
        object.__setattr__(claim, "tier", "bogus")
        object.__setattr__(claim, "evidence", [])
        object.__setattr__(claim, "valid_until", None)
        ledger = CapabilityLedger()
        ledger._claims.setdefault("det-a", []).append(claim)
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="r",
                description="d",
                required_capabilities=[("language_coverage", "readable")],
            )
        )
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is False
        assert result.missing_claims or result.evidence_gaps

    def test_interior_glob_matches(self):
        engine = CapabilityPolicyEngine()
        assert engine._matches_pattern("vendor/model-v1", "vendor/*-v1") is True
        assert engine._matches_pattern("vendor/model-v2", "vendor/*-v1") is False
        assert engine._matches_pattern("vendor/model-v1", "vendor/*") is True
        assert engine._matches_pattern("a/b/c", "a/*/c") is True
        assert engine._matches_pattern("abc", "a?c") is True

    def test_known_tiers_still_evaluate(self):
        ledger = CapabilityLedger()
        ledger.register(
            CapabilityClaim(
                detector_id="det-a",
                capability="language_coverage",
                tier=EvidenceTier.READABLE,
                evidence=[],
            )
        )
        engine = CapabilityPolicyEngine()
        engine.add_policy(
            CapabilityPolicy(
                rule_id="r",
                description="d",
                required_capabilities=[("language_coverage", "validated")],
            )
        )
        (result,) = engine.evaluate(ledger, "det-a")
        assert result.passed is False
        assert "claim tier=readable, required=validated+" in result.evidence_gaps[0]


class TestS22EnterpriseDigestAndFrozenPolicy:
    def _policy(self, conditions):
        return EnterprisePolicy(
            revision=1,
            digest="",
            settings={},
            rules=[{"id": "r1", "description": "d", "action": "log", "scope": "all",
                    "conditions": conditions}],
        )

    def test_conditions_change_the_digest(self):
        assert compute_policy_digest(self._policy({"env": "prod"})) != compute_policy_digest(
            self._policy({"env": "dev"})
        )

    def test_absent_and_empty_conditions_digest_the_same(self):
        no_cond = EnterprisePolicy(
            revision=1, digest="", settings={},
            rules=[{"id": "r1", "description": "d", "action": "log", "scope": "all"}],
        )
        empty_cond = self._policy({})
        assert compute_policy_digest(no_cond) == compute_policy_digest(empty_cond)

    def test_load_policy_rejects_nonempty_conditions(self):
        engine = EnterprisePolicyEngine()
        errors = engine.load_policy(
            {"revision": 1, "settings": {},
             "rules": [{"id": "r1", "description": "d", "action": "log", "scope": "all",
                        "conditions": {"env": "prod"}}]}
        )
        assert errors
        assert "condition" in " ".join(errors).lower()
        assert engine.policy is None

    def test_frozen_policy_is_deeply_immutable(self):
        engine = EnterprisePolicyEngine()
        assert engine.load_policy(
            {"revision": 1, "settings": {"nested": {"flag": True}},
             "rules": [{"id": "r1", "description": "d", "action": "log", "scope": "all"}]}
        ) == []
        policy = engine.policy
        assert policy is not None
        with pytest.raises(TypeError):
            policy.rules[0]["action"] = "disable"  # type: ignore[index]
        with pytest.raises(TypeError):
            policy.settings["nested"]["flag"] = False  # type: ignore[index]
        with pytest.raises((TypeError, AttributeError)):
            policy.rules.append({"id": "r2", "description": "d", "action": "log", "scope": "all"})
        assert engine.evaluate("analysis")["status"] == "ok"
        assert policy.digest == compute_policy_digest(policy)

    def test_to_dict_mutation_cannot_change_policy(self):
        engine = EnterprisePolicyEngine()
        engine.load_policy(
            {"revision": 1, "settings": {},
             "rules": [{"id": "r1", "description": "d", "action": "log", "scope": "all"}]}
        )
        policy = engine.policy
        assert policy is not None
        exported = policy.to_dict()
        exported["rules"][0]["action"] = "disable"
        exported["settings"]["injected"] = True
        assert engine.evaluate("analysis")["status"] == "ok"
        assert policy.digest == compute_policy_digest(policy)

    def test_unknown_action_rejected_at_construction(self):
        with pytest.raises(ValueError, match="action"):
            EnterprisePolicy(
                revision=1, digest="", settings={},
                rules=[{"id": "r1", "description": "d", "action": "explode", "scope": "all"}],
            )

    def test_engine_setter_rejects_unvalidated_policy(self):
        engine = EnterprisePolicyEngine()
        bad = EnterprisePolicy(
            revision=1, digest="", settings={},
            rules=[{"id": "r1", "description": "d", "action": "log", "scope": "all",
                    "conditions": {"env": "prod"}}],
        )
        with pytest.raises(ValueError, match="condition"):
            engine.policy = bad
        assert engine.policy is None

    def test_evaluate_treats_unknown_action_as_violation(self):
        """Defence in depth: a policy that bypassed construction-time
        validation (e.g. admitted before it existed) must not report
        "ok" for an unknown action."""
        policy = object.__new__(EnterprisePolicy)
        object.__setattr__(policy, "revision", 1)
        object.__setattr__(policy, "digest", "a" * 64)
        object.__setattr__(policy, "settings", {})
        object.__setattr__(
            policy,
            "rules",
            [{"id": "r1", "description": "d", "action": "explode", "scope": "all"}],
        )
        engine = EnterprisePolicyEngine()
        object.__setattr__(engine, "_policy", policy)
        result = engine.evaluate("all")
        assert result["status"] == "violation"
        assert result["violations"]
        assert "explode" in result["violations"][0]["description"]


class TestS22ModelCardCodecOracles:
    def test_zero_metrics_display_as_zero_not_na(self):
        card = _valid_card_dict()
        card["quantitative_analysis"] = {
            "metrics": [],
            "roc_auc": 0.0,
            "pr_auc": 0.0,
            "calibration_error": 0.0,
        }
        md = ModelCard.from_dict(card).to_markdown()
        assert "ROC AUC: 0.0" in md
        assert "PR AUC: 0.0" in md
        assert "Calibration Error: 0.0" in md

    def test_codec_decode_rejects_nan_token(self):
        codec = ResultCodec()
        payload = (
            b'{"schema": "textforensics.enterprise-policy/v1", '
            b'"settings": {"x": NaN}}'
        )
        with pytest.raises(Exception, match="NaN|non-finite"):
            codec.decode(payload, "enterprise-policy", validate=False)

    def test_math_oracles_match_definitions(self):
        # Independent oracles from the audit (STATEFUL_RELIABILITY.md):
        # Wilson k=0/n=50/z=1.96 upper = z^2/(n+z^2); PSI, ECE, Brier, Holm.
        from textforensics.probe_metrics import (
            brier,
            ece,
            holm_adjusted,
            ks_statistic,
            psi,
            wilson_ci,
        )

        assert wilson_ci(0, 50)[1] == pytest.approx(0.07135003417431873)
        # Two-bin PSI: reference proportions (0.5, 0.5), actual (0.25, 0.75).
        assert psi([0, 0, 1, 1], [0, 1, 1, 1], bins=2) == pytest.approx(0.2746530721670274)
        assert ece([0.2, 0.2], [0, 1], n_bins=1) == pytest.approx(0.3)
        assert brier([0.2, 0.2], [0, 1]) == pytest.approx(0.3400000000000001)
        assert list(holm_adjusted([0.01, 0.04, 0.03])) == pytest.approx([0.03, 0.06, 0.06])
        assert ks_statistic([0, 0, 1, 1], [0, 0, 0, 1]) == pytest.approx(0.25)

    def test_ks_exhaustive_oracle_225_pairs(self):
        # Audit /state_followup/ks_exhaustive_oracle: 225 length-four
        # discrete pairs, zero mismatches against the definition
        # max_t |count(a<=t)/n - count(b<=t)/m|.
        samples = [
            (0.0, 0.0, 0.0, 0.0),
            (0.0, 0.0, 0.0, 1.0),
            (0.0, 0.0, 1.0, 1.0),
            (0.0, 1.0, 1.0, 1.0),
            (1.0, 1.0, 1.0, 1.0),
            (0.0, 0.0, 0.0, 2.0),
            (0.0, 0.0, 2.0, 2.0),
            (0.0, 2.0, 2.0, 2.0),
            (2.0, 2.0, 2.0, 2.0),
            (1.0, 1.0, 1.0, 2.0),
            (1.0, 1.0, 2.0, 2.0),
            (1.0, 2.0, 2.0, 2.0),
            (0.0, 1.0, 2.0, 2.0),
            (0.0, 0.0, 1.0, 2.0),
            (0.0, 1.0, 1.0, 2.0),
        ]
        assert len(samples) == 15
        pairs = 0
        for a in samples:
            for b in samples:
                pairs += 1
                expected = max(
                    abs(sum(1 for x in a if x <= t) / 4 - sum(1 for y in b if y <= t) / 4)
                    for t in sorted(set(a) | set(b))
                )
                assert ks_statistic(list(a), list(b)) == pytest.approx(expected)
        assert pairs == 225


# ------------------------------------------------------------------- CORE-04


class TestCore04FrozenCalibration:
    def test_tampered_artifact_is_not_eligible(self):
        """Audit repro /core/mutable_calibration: content mutated after
        hashing must not remain eligible under the old hash."""
        artifact = _eligible_artifact()
        assert artifact.eligible_for_probability is True
        object.__setattr__(
            artifact, "metrics", {"brier": 0.0, "ece": 0.0, "log_loss": 0.0}
        )
        assert artifact.check_content_hash() is False
        assert artifact.eligible_for_probability is False
        assert any("content_hash" in issue for issue in artifact.validation_issues())

    def test_mutating_constructor_inputs_cannot_change_output(self):
        params = {"T": 2.0}
        curve = CalibrationCurve(method="temperature", parameters=params)
        before = curve.calibrate(0.7)
        params["T"] = 0.01
        assert curve.calibrate(0.7) == pytest.approx(before)

    def test_tampered_artifact_cannot_be_applied(self):
        artifact = _eligible_artifact()
        object.__setattr__(
            artifact, "metrics", {"brier": 0.0, "ece": 0.0, "log_loss": 0.0}
        )
        with pytest.raises(CalibrationError):
            artifact.calibrate(0.5)
