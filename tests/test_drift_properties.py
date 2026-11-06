"""Property-based tests for drift module."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from textforensics.observatory import (
    DriftAlert,
    DriftObservatory,
    _distribution_summary,
    _percentile,
    _round,
    filter_alerts,
    generate_drift_alerts,
    summarize_alerts,
)


class TestDriftProperties:
    """Property-based tests for drift module invariants."""

    @given(
        st.lists(
            st.floats(min_value=-100.0, max_value=100.0, allow_nan=False, allow_infinity=False),
            min_size=0,
            max_size=100,
        )
    )
    @settings(deadline=None)
    def test_distribution_summary_never_crashes(self, values: list[float]):
        """_distribution_summary should never raise for any float list."""
        result = _distribution_summary(values)
        assert isinstance(result, dict)
        assert "n" in result
        assert isinstance(result["n"], int)
        assert result["n"] >= 0

    @given(
        st.lists(
            st.floats(min_value=-100.0, max_value=100.0, allow_nan=False, allow_infinity=False),
            min_size=1,
            max_size=50,
        ),
        st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(deadline=None)
    def test_percentile_bounds(self, values: list[float], q: float):
        """_percentile should return a value within the data range."""
        values_sorted = sorted(values)
        result = _percentile(values_sorted, q)
        if result is not None:
            # Use small epsilon for floating-point precision
            eps = 1e-12
            assert values_sorted[0] - eps <= result <= values_sorted[-1] + eps

    @given(
        st.floats(min_value=-100.0, max_value=100.0, allow_nan=False, allow_infinity=False),
        st.integers(
            min_value=0, max_value=6
        ),  # Limit digits to avoid extreme floating-point issues
    )
    @settings(deadline=None)
    def test_round_precision(self, value: float, digits: int):
        """_round should match Python's built-in round behavior."""
        result = _round(value, digits)
        if result is not None:
            # _round should match Python's round
            expected = round(value, digits)
            assert result == expected

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        )
    )
    @settings(deadline=None)
    def test_filter_alerts_preserves_order(self, alerts_data: list[tuple[str, str, str, str, str]]):
        """filter_alerts should preserve order of matching alerts."""
        alerts = [
            DriftAlert(
                detector_id=det_id,
                severity=sev,
                category=cat,
                message=msg,
                recommended_action=action,
            )
            for det_id, sev, cat, msg, action in alerts_data
        ]
        # Filter with no criteria should return all in same order
        filtered = filter_alerts(alerts)
        assert [a.detector_id for a in filtered] == [a.detector_id for a in alerts]

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        ),
        st.sampled_from(["critical", "warning", "info"]),
    )
    @settings(deadline=None)
    def test_filter_alerts_by_severity(self, alerts_data: list[tuple], severity: str):
        """filter_alerts by severity should only return matching severity."""
        alerts = [
            DriftAlert(
                detector_id=det_id,
                severity=sev,
                category=cat,
                message=msg,
                recommended_action=action,
            )
            for det_id, sev, cat, msg, action in alerts_data
        ]
        filtered = filter_alerts(alerts, severity=severity)
        for alert in filtered:
            assert alert.severity == severity

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        ),
        st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
    )
    @settings(deadline=None)
    def test_filter_alerts_by_category(self, alerts_data: list[tuple], category: str):
        """filter_alerts by category should only return matching category."""
        alerts = [
            DriftAlert(
                detector_id=det_id,
                severity=sev,
                category=cat,
                message=msg,
                recommended_action=action,
            )
            for det_id, sev, cat, msg, action in alerts_data
        ]
        filtered = filter_alerts(alerts, category=category)
        for alert in filtered:
            assert alert.category == category

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        ),
        st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))),
    )
    @settings(deadline=None)
    def test_filter_alerts_by_detector_id(self, alerts_data: list[tuple], detector_id: str):
        """filter_alerts by detector_id should only return matching detector."""
        alerts = [
            DriftAlert(
                detector_id=det_id,
                severity=sev,
                category=cat,
                message=msg,
                recommended_action=action,
            )
            for det_id, sev, cat, msg, action in alerts_data
        ]
        filtered = filter_alerts(alerts, detector_id=detector_id)
        for alert in filtered:
            assert alert.detector_id == detector_id

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        )
    )
    @settings(deadline=None)
    def test_summarize_alerts_counts(self, alerts_data: list[tuple]):
        """summarize_alerts should correctly count alerts."""
        alerts = [
            DriftAlert(
                detector_id=det_id,
                severity=sev,
                category=cat,
                message=msg,
                recommended_action=action,
            )
            for det_id, sev, cat, msg, action in alerts_data
        ]
        summary = summarize_alerts(alerts)

        # Total count
        assert summary["total"] == len(alerts)

        # Severity counts
        critical_count = sum(1 for a in alerts if a.severity == "critical")
        warning_count = sum(1 for a in alerts if a.severity == "warning")
        info_count = sum(1 for a in alerts if a.severity == "info")

        assert summary["critical_count"] == critical_count
        assert summary["warning_count"] == warning_count
        assert summary["info_count"] == info_count

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        )
    )
    @settings(deadline=None)
    def test_summarize_alerts_categories(self, alerts_data: list[tuple]):
        """summarize_alerts should count by category correctly."""
        alerts = [
            DriftAlert(
                detector_id=det_id,
                severity=sev,
                category=cat,
                message=msg,
                recommended_action=action,
            )
            for det_id, sev, cat, msg, action in alerts_data
        ]
        summary = summarize_alerts(alerts)

        for cat in ["behavioral", "configuration", "calibration", "human_fpr"]:
            expected = sum(1 for a in alerts if a.category == cat)
            assert summary["by_category"].get(cat, 0) == expected

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        )
    )
    @settings(deadline=None)
    def test_generate_alerts_deterministic(self, reports_data: list[tuple]):
        """generate_drift_alerts should be deterministic for same input."""
        # Create mock reports from the data
        reports = []
        for i, (det_id, _sev, cat, _msg, _action) in enumerate(reports_data):
            reports.append(
                {
                    "detector_id": det_id,
                    "status": "drift_detected",
                    "snapshot_id": f"snap-{i}",
                    "score_distribution": {"significant": cat == "behavioral"},
                    "verdict_flips": {"significant": False},
                    "calibration_drift": {"probability_shift_significant": cat == "calibration"},
                    "human_slice_fpr": {"significant_increase": cat == "human_fpr"},
                    "threshold_changes": {"threshold_changed": cat == "configuration"},
                    "provider_metadata": {"provider_metadata_changed": False},
                }
            )

        alerts1 = generate_drift_alerts(reports)
        alerts2 = generate_drift_alerts(reports)

        assert len(alerts1) == len(alerts2)
        for a1, a2 in zip(alerts1, alerts2, strict=False):
            assert a1.detector_id == a2.detector_id
            assert a1.severity == a2.severity
            assert a1.category == a2.category
            assert a1.message == a2.message

    @given(
        st.lists(
            st.tuples(
                st.text(
                    min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"))
                ),
                st.sampled_from(["critical", "warning", "info"]),
                st.sampled_from(["behavioral", "configuration", "calibration", "human_fpr"]),
                st.text(min_size=1, max_size=50),
                st.text(min_size=1, max_size=50),
            ),
            min_size=0,
            max_size=20,
        )
    )
    @settings(deadline=None)
    def test_drift_alert_to_dict(self, alerts_data: list[tuple]):
        """DriftAlert.to_dict should serialize all fields."""
        alerts = [
            DriftAlert(
                detector_id=det_id,
                severity=sev,
                category=cat,
                message=msg,
                recommended_action=action,
                snapshot_id=f"snap-{i}",
            )
            for i, (det_id, sev, cat, msg, action) in enumerate(alerts_data)
        ]

        for alert in alerts:
            d = alert.to_dict()
            assert d["detector_id"] == alert.detector_id
            assert d["severity"] == alert.severity
            assert d["category"] == alert.category
            assert d["message"] == alert.message
            assert d["recommended_action"] == alert.recommended_action
            assert d["snapshot_id"] == alert.snapshot_id


class TestDriftObservatoryProperties:
    """Property-based tests for DriftObservatory invariants."""

    def test_observatory_creation_with_valid_corpus(self):
        """DriftObservatory should accept valid corpus configurations."""
        corpus = {
            "schema": "textforensics.drift-corpus/v1",
            "samples": [
                {"id": "s1", "text_sha256": "a" * 64, "metadata": {"label": "human"}},
                {"id": "s2", "text_sha256": "b" * 64, "metadata": {"label": "ai"}},
            ],
        }
        obs = DriftObservatory(corpus=corpus)
        assert len(obs.samples) == 2
        assert obs.corpus_sha256 is not None

    def test_observatory_corpus_hash_deterministic(self):
        """Corpus SHA256 should be deterministic."""
        corpus = {
            "schema": "textforensics.drift-corpus/v1",
            "samples": [
                {"id": "s1", "text_sha256": "a" * 64, "metadata": {"label": "human"}},
                {"id": "s2", "text_sha256": "b" * 64, "metadata": {"label": "ai"}},
            ],
        }
        obs1 = DriftObservatory(corpus=corpus)
        obs2 = DriftObservatory(corpus=corpus)
        assert obs1.corpus_sha256 == obs2.corpus_sha256


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
