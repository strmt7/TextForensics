"""W2 Worker E regression tests: IF-19 (explanation scored count).

Written from the stated expected results (plan rule 3) before the source
fix. Every test uses disposable synthetic data; no real user text,
accounts or keys.

Audit vector reproduced here:
- IF-19 ``explanation_scored_count``: a score function returning 0.4
  for the full two-sentence document but ``None`` for both removals
  must NOT report ``n_scored=2`` with zero attributions.

Expected contract after the fix:
- Attempted, scored (succeeded), abstained and failed perturbations
  are tracked separately through W1's ``CompletenessAccounting``
  (``execution_policy``); ``n_scored`` counts only perturbations that
  returned a valid score, incremented after the valid score arrives.
- Partial/absent explanation coverage is stated in the limitations
  and summary; unknowns are preserved, never relabelled as zero
  contribution.
- Progress totals may count attempts but must not be serialized as a
  completed successful attribution count.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from textforensics.explain import (
    CounterfactualExplainer,
    explain_verdict,
    load_explanation_report,
    save_explanation_report,
)

TEXT_TWO = "First sentence here. Second sentence here."
TEXT_THREE = "Alpha sentence here. Beta sentence here. Gamma sentence here."


def _audit_score_fn(text: str):
    """Audit case: 0.4 for the full document, abstain on every removal."""
    if text.count(".") >= 2:
        return 0.4
    return None


class TestIF19AuditCase:
    def test_all_abstention_reports_zero_scored(self):
        explainer = CounterfactualExplainer(
            _audit_score_fn, detector_id="d", detector_version="1.0"
        )
        report = explainer.explain(TEXT_TWO)
        assert report.n_segments == 2
        assert report.n_scored == 0
        assert len(report.segment_attribution) == 0
        # n_scored must equal the successful attributions, never the
        # attempted count.
        assert report.n_scored == len(report.segment_attribution)

    def test_all_abstention_completeness_split(self):
        explainer = CounterfactualExplainer(
            _audit_score_fn, detector_id="d", detector_version="1.0"
        )
        report = explainer.explain(TEXT_TWO)
        completeness = report.completeness
        assert completeness is not None
        assert completeness.to_dict() == {
            "selected": 2,
            "attempted": 2,
            "succeeded": 0,
            "abstained": 2,
            "failed": 0,
            "is_complete": True,
            "support_eligible": False,
        }
        data = report.to_dict()
        assert data["n_attempted"] == 2
        assert data["n_scored"] == 0
        assert data["n_abstained"] == 2
        assert data["n_failed"] == 0
        assert data["completeness"]["abstained"] == 2

    def test_all_abstention_states_absent_coverage_with_reasons(self):
        explainer = CounterfactualExplainer(
            _audit_score_fn, detector_id="d", detector_version="1.0"
        )
        report = explainer.explain(TEXT_TWO)
        assert len(report.unscored_segments) == 2
        assert {u["segment_index"] for u in report.unscored_segments} == {0, 1}
        assert all(u["outcome"] == "abstained" for u in report.unscored_segments)
        assert all(u["reason"] for u in report.unscored_segments)
        assert any(
            "absent" in lim.lower() or "no segment attribution" in lim.lower()
            for lim in report.limitations
        )
        summary = report.summary()
        assert summary["explanation_coverage"] == "absent"
        assert summary["n_scored"] == 0
        assert summary["n_abstained"] == 2


class TestIF19AllSuccess:
    def test_all_success_counts_match(self):
        def score_fn(text: str):
            return 0.9 if "Alpha" in text else 0.2

        explainer = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1.0")
        report = explainer.explain(TEXT_THREE)
        assert report.n_segments == 3
        assert report.n_scored == 3
        assert len(report.segment_attribution) == 3
        assert report.completeness is not None
        assert report.completeness.to_dict()["succeeded"] == 3
        assert report.completeness.to_dict()["abstained"] == 0
        assert report.completeness.to_dict()["failed"] == 0
        assert report.completeness.support_eligible is True
        assert report.unscored_segments == []
        assert report.summary()["explanation_coverage"] == "complete"


class TestIF19PartialAbstention:
    def test_partial_abstention_reports_exact_split(self):
        def score_fn(text: str):
            # Abstain only when the Beta sentence is removed.
            if "Beta" not in text:
                return None
            return 0.5

        explainer = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1.0")
        report = explainer.explain(TEXT_THREE)
        assert report.n_scored == 2
        assert len(report.segment_attribution) == 2
        assert report.completeness is not None
        assert report.completeness.to_dict() == {
            "selected": 3,
            "attempted": 3,
            "succeeded": 2,
            "abstained": 1,
            "failed": 0,
            "is_complete": True,
            "support_eligible": False,
        }
        assert len(report.unscored_segments) == 1
        assert report.unscored_segments[0]["segment_index"] == 1
        assert report.unscored_segments[0]["outcome"] == "abstained"
        assert any("partial" in lim.lower() for lim in report.limitations)
        assert report.summary()["explanation_coverage"] == "partial"


class TestIF19Exception:
    def test_exception_on_one_perturbation_is_failed_not_lost(self):
        def score_fn(text: str):
            if "Gamma" not in text:
                raise ValueError("synthetic scorer failure")
            return 0.5

        explainer = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1.0")
        report = explainer.explain(TEXT_THREE)
        assert report.n_scored == 2
        assert len(report.segment_attribution) == 2
        assert report.completeness is not None
        assert report.completeness.failed == 1
        assert report.completeness.abstained == 0
        assert report.completeness.succeeded == 2
        assert len(report.unscored_segments) == 1
        failed = report.unscored_segments[0]
        assert failed["segment_index"] == 2
        assert failed["outcome"] == "failed"
        assert "ValueError" in failed["reason"]
        assert any("partial" in lim.lower() for lim in report.limitations)

    def test_exception_on_full_text_still_propagates(self):
        def score_fn(text: str):
            raise RuntimeError("synthetic full-text failure")

        explainer = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1.0")
        try:
            explainer.explain(TEXT_THREE)
        except RuntimeError:
            pass
        else:
            raise AssertionError("full-text scorer failure must propagate, not become a report")


class TestIF19SingletonAndOriginalAbstain:
    def test_singleton_reports_zero_selected(self):
        explainer = CounterfactualExplainer(
            lambda text: 0.5, detector_id="d", detector_version="1.0"
        )
        report = explainer.explain("Only one sentence.")
        assert report.n_segments == 1
        assert report.n_scored == 0
        assert report.segment_attribution == []
        assert report.completeness is not None
        assert report.completeness.selected == 0
        assert report.completeness.attempted == 0
        assert any("one segment" in lim.lower() for lim in report.limitations)
        assert report.summary()["explanation_coverage"] == "absent"

    def test_original_abstain_attempts_nothing(self):
        explainer = CounterfactualExplainer(
            lambda text: None, detector_id="d", detector_version="1.0"
        )
        report = explainer.explain(TEXT_TWO)
        assert report.original_score is None
        assert report.n_scored == 0
        assert report.segment_attribution == []
        assert report.completeness is not None
        assert report.completeness.selected == 2
        assert report.completeness.attempted == 0
        assert report.completeness.is_complete is False
        assert any("abstain" in lim.lower() for lim in report.limitations)


class TestIF19ProgressAndSerialization:
    def test_progress_totals_count_attempts_not_successes(self):
        seen: list[tuple[int, int]] = []
        explainer = CounterfactualExplainer(
            _audit_score_fn, detector_id="d", detector_version="1.0"
        )
        explainer.explain(TEXT_TWO, progress=lambda done, total: seen.append((done, total)))
        # Both perturbations were attempted (total 2) even though none
        # scored; the total is attempts, never a success count.
        assert seen == [(1, 2), (2, 2)]

    def test_n_scored_never_exceeds_attributions(self):
        def score_fn(text: str):
            if "Beta" not in text:
                return None
            return 0.5

        explainer = CounterfactualExplainer(score_fn, detector_id="d", detector_version="1.0")
        report = explainer.explain(TEXT_THREE)
        assert report.n_scored == len(report.segment_attribution)
        assert report.to_dict()["n_scored"] == len(report.to_dict()["segment_attribution"])

    def test_round_trip_preserves_completeness(self):
        report = explain_verdict(TEXT_TWO, _audit_score_fn, detector_id="d", detector_version="1.0")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "explanation.json"
            save_explanation_report(report, str(path))
            data = json.loads(path.read_text(encoding="utf-8"))
            assert data["completeness"]["abstained"] == 2
            assert data["n_scored"] == 0
            loaded = load_explanation_report(str(path))
        assert loaded.n_scored == 0
        assert loaded.completeness is not None
        assert loaded.completeness.abstained == 2
        assert loaded.completeness.succeeded == 0
        assert [u["segment_index"] for u in loaded.unscored_segments] == [0, 1]

    def test_legacy_file_without_completeness_loads(self):
        report = explain_verdict(
            TEXT_THREE, lambda text: 0.5, detector_id="d", detector_version="1.0"
        )
        data = report.to_dict()
        del data["completeness"]
        del data["n_attempted"]
        del data["n_abstained"]
        del data["n_failed"]
        del data["unscored_segments"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            loaded = load_explanation_report(str(path))
        assert loaded.n_scored == 3
        assert loaded.completeness is None
