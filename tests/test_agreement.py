"""Tests for inter-detector agreement statistics."""

from __future__ import annotations

import math

import pytest

from textforensics.agreement import (
    _interpret_kappa,
    build_agreement_matrix,
    cohens_kappa,
    fleiss_kappa,
    percent_agreement,
)


class TestInterpretKappa:
    def test_negative(self):
        assert _interpret_kappa(-0.1) == "poor (less than chance)"

    def test_slight(self):
        assert _interpret_kappa(0.1) == "slight"

    def test_fair(self):
        assert _interpret_kappa(0.3) == "fair"

    def test_moderate(self):
        assert _interpret_kappa(0.5) == "moderate"

    def test_substantial(self):
        assert _interpret_kappa(0.7) == "substantial"

    def test_almost_perfect(self):
        assert _interpret_kappa(0.9) == "almost perfect"


class TestPercentAgreement:
    def test_basic(self):
        a = ["ai", "human", "ai", "human"]
        b = ["ai", "human", "ai", "ai"]
        p, n = percent_agreement(a, b)
        assert n == 4
        assert p == 0.75  # 3/4 agree

    def test_excludes_abstain_a(self):
        a = ["ai", None, "ai", "human"]
        b = ["ai", "human", "ai", "human"]
        p, n = percent_agreement(a, b)
        assert n == 3  # 2nd pair excluded
        assert p == 1.0  # all remaining agree

    def test_excludes_abstain_both(self):
        a = [None, "ai"]
        b = [None, "human"]
        p, n = percent_agreement(a, b)
        assert n == 1
        assert p == 0.0

    def test_all_abstain(self):
        a = [None, None]
        b = [None, "human"]
        p, n = percent_agreement(a, b)
        assert n == 0
        assert p == 0.0

    def test_case_insensitive(self):
        a = ["AI", "Human"]
        b = ["ai", "human"]
        p, n = percent_agreement(a, b)
        assert p == 1.0

    def test_insufficient_evidence_as_abstain(self):
        a = ["ai", "insufficient_evidence"]
        b = ["ai", "human"]
        p, n = percent_agreement(a, b)
        assert n == 1
        assert p == 1.0


class TestCohensKappa:
    def test_perfect_agreement(self):
        a = ["ai", "human", "ai", "human"]
        b = ["ai", "human", "ai", "human"]
        kappa, p_o, n, conf = cohens_kappa(a, b)
        assert kappa == 1.0
        assert p_o == 1.0
        assert n == 4

    def test_perfect_disagreement(self):
        a = ["ai", "human"]
        b = ["human", "ai"]
        kappa, p_o, n, conf = cohens_kappa(a, b)
        # kappa = (0 - 0.5) / (1 - 0.5) = -1
        assert math.isclose(kappa, -1.0, abs_tol=1e-9)
        assert p_o == 0.0
        assert n == 2

    def test_chance_level(self):
        # 50/50 marginals, random agreement ~50%
        a = ["ai", "ai", "human", "human"]
        b = ["ai", "human", "ai", "human"]
        kappa, p_o, n, conf = cohens_kappa(a, b)
        # Observed = 0.5, expected by chance = 0.5, kappa = 0
        assert math.isclose(kappa, 0.0, abs_tol=1e-9)
        assert p_o == 0.5

    def test_abstain_excluded(self):
        a = ["ai", None, "human"]
        b = ["ai", "human", "human"]
        kappa, p_o, n, conf = cohens_kappa(a, b)
        # Only 2 pairs counted: (ai,ai) and (human,human)
        assert kappa == 1.0
        assert n == 2

    def test_all_abstain_returns_none(self):
        a = [None, None]
        b = [None, None]
        kappa, p_o, n, conf = cohens_kappa(a, b)
        assert kappa is None
        assert n == 0

    def test_confusion_matrix(self):
        a = ["ai", "human", "ai"]
        b = ["ai", "ai", "human"]
        kappa, p_o, n, conf = cohens_kappa(a, b)
        assert conf["ai|ai"] == 1
        assert conf["human|ai"] == 1
        assert conf["ai|human"] == 1

    def test_constant_raters_returns_none(self):
        # Both always "ai" -> chance agreement = 1 -> kappa undefined
        a = ["ai", "ai", "ai"]
        b = ["ai", "ai", "ai"]
        kappa, p_o, n, conf = cohens_kappa(a, b)
        assert kappa is None
        assert p_o == 1.0


class TestFleissKappa:
    def test_perfect_agreement(self):
        # 3 raters, 3 items, perfect agreement
        matrix = [
            ["ai", "ai", "ai"],
            ["human", "human", "human"],
            ["ai", "ai", "ai"],
        ]
        kappa, n_items, n_raters, warns = fleiss_kappa(matrix)
        assert kappa == 1.0
        assert n_items == 3
        assert n_raters == 3

    def test_with_abstentions(self):
        # 3 raters, 1 abstains per item
        matrix = [
            ["ai", "ai", None],
            ["human", "human", None],
            ["ai", "ai", None],
        ]
        kappa, n_items, n_raters, warns = fleiss_kappa(matrix)
        # Each item has 2 non-abstaining raters, perfect agreement
        assert kappa == 1.0
        assert n_items == 3

    def test_mixed_agreement(self):
        matrix = [
            ["ai", "ai", "ai"],
            ["human", "human", "human"],
            ["ai", "human", "human"],
        ]
        kappa, n_items, n_raters, warns = fleiss_kappa(matrix)
        # Item 1: 3/3 agree -> P=1
        # Item 2: 3/3 agree -> P=1
        # Item 3: 2 "human", 1 "ai" -> P = (2*1 + 1*0)/(3*2) = 2/6 = 0.333
        # p_bar = (1 + 1 + 0.333)/3 = 0.778
        # p_e = (2/3)^2 + (1/3)^2 = 0.555
        # kappa = (0.778 - 0.555) / (1 - 0.555) = 0.5
        assert math.isclose(kappa, 0.55, abs_tol=0.05)
        assert n_items == 3

    def test_insufficient_raters_returns_none(self):
        matrix = [["ai", None], ["human", None]]
        kappa, n_items, n_raters, warns = fleiss_kappa(matrix)
        assert kappa is None
        assert n_items == 0

    def test_insufficient_items(self):
        matrix = [["ai", "ai", "ai"]]
        kappa, n_items, n_raters, warns = fleiss_kappa(matrix)
        assert kappa is None
        assert len(warns) > 0

    def test_varying_raters_per_row_raises(self):
        with pytest.raises(ValueError):
            fleiss_kappa([["ai", "ai"], ["human"]])


class TestBuildAgreementMatrix:
    def test_minimal_two_detectors(self):
        det_verdicts = {
            "det_a": ["ai", "human", "ai"],
            "det_b": ["ai", "human", "human"],
        }
        matrix = build_agreement_matrix(det_verdicts)
        assert matrix.detectors == ["det_a", "det_b"]
        assert len(matrix.pairwise) == 1
        pair = matrix.pairwise[0]
        assert pair.detector_a == "det_a"
        assert pair.detector_b == "det_b"
        assert pair.paired_n == 3
        # 2/3 agreement: (ai,ai) and (human,human) agree; (ai,human) disagree
        # p_o = 2/3 = 0.667
        # Marginals: a=[2 ai, 1 human], b=[1 ai, 2 human] -> p_e = (2/3)*(1/3) + (1/3)*(2/3) = 4/9 = 0.444
        # kappa = (0.667 - 0.444) / (1 - 0.444) = 0.222 / 0.556 = 0.4
        assert math.isclose(pair.cohens_kappa, 0.4, abs_tol=0.1)

    def test_three_detectors(self):
        det_verdicts = {
            "a": ["ai", "human", "ai", "human"],
            "b": ["ai", "human", "human", "human"],
            "c": ["human", "human", "ai", "ai"],
        }
        matrix = build_agreement_matrix(det_verdicts)
        assert len(matrix.detectors) == 3
        assert len(matrix.pairwise) == 3  # 3 pairs
        # Should have Fleiss' kappa
        assert matrix.fleiss_n_raters == 3

    def test_abstentions_handled(self):
        det_verdicts = {
            "a": ["ai", None, "human"],
            "b": ["ai", "human", "human"],
        }
        matrix = build_agreement_matrix(det_verdicts)
        pair = matrix.pairwise[0]
        assert pair.paired_n == 2  # 2nd pair excluded (a abstained)
        assert pair.cohens_kappa == 1.0

    def test_warning_for_few_detectors(self):
        det_verdicts = {"a": ["ai", "human"]}
        matrix = build_agreement_matrix(det_verdicts)
        assert any("fewer than 2 detectors" in w for w in matrix.warnings)

    def test_mismatched_lengths_raises(self):
        det_verdicts = {"a": ["ai"], "b": ["ai", "human"]}
        with pytest.raises(ValueError):
            build_agreement_matrix(det_verdicts)

    def test_summary_independence_hint(self):
        # High agreement -> highly_correlated
        det_verdicts = {
            "a": ["ai"] * 10 + ["human"] * 10,
            "b": ["ai"] * 10 + ["human"] * 10,
        }
        matrix = build_agreement_matrix(det_verdicts)
        summary = matrix.summary()
        assert summary["independence_hint"] == "highly_correlated"

        # Low agreement -> weakly_correlated
        det_verdicts2 = {
            "a": ["ai"] * 10 + ["human"] * 10,
            "b": ["human"] * 10 + ["ai"] * 10,
        }
        matrix2 = build_agreement_matrix(det_verdicts2)
        summary2 = matrix2.summary()
        assert summary2["independence_hint"] in {"weakly_correlated", "moderate_agreement"}

    def test_roundtrip_serialization(self):
        det_verdicts = {
            "a": ["ai", "human", "ai"],
            "b": ["ai", "human", "human"],
        }
        matrix = build_agreement_matrix(det_verdicts)
        d = matrix.to_dict()
        assert "detectors" in d
        assert "pairwise" in d
        assert "fleiss_kappa" in d
        assert len(d["pairwise"]) == 1
        assert d["pairwise"][0]["detector_a"] == "a"

    def test_pairwise_kappa_interpretation(self):
        det_verdicts = {
            "a": ["ai", "ai", "human"],
            "b": ["ai", "ai", "human"],
        }
        matrix = build_agreement_matrix(det_verdicts)
        pair = matrix.pairwise[0]
        assert pair.kappa_interpretation == "almost perfect"  # kappa=1.0

        det_verdicts2 = {
            "a": ["ai", "human"],
            "b": ["human", "ai"],
        }
        matrix2 = build_agreement_matrix(det_verdicts2)
        pair2 = matrix2.pairwise[0]
        assert pair2.kappa_interpretation == "poor (less than chance)"  # kappa=-1

    def test_empty_input(self):
        matrix = build_agreement_matrix({})
        assert matrix.detectors == []
        assert matrix.fleiss_kappa is None
        assert "no detectors provided" in matrix.warnings


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
