"""W2 Worker E regression tests: IF-04 (UI fabricates probabilities).

Written from the stated expected results (plan rule 3) before the source
fix. The behavioral tests drive the REAL shipped ``app.js`` through a
minimal-DOM + recording-Chart Node harness (no browser is opened, no
network is used); the guard test pins the source against reintroducing
unsupported probability fallbacks.

Audit vectors reproduced here:
- IF-04 ``gauge_ai_like`` / ``gauge_human_like`` / ``gauge_abstain``:
  uncalibrated bundles must not display 85% / 15% / 50% "AI
  Probability". The family chart must not substitute 50 for missing
  calibration. The bundle exposes ``consensus.calibrated_ai_probability``;
  the UI looked for ``consensus.ai_probability`` instead.

Expected contract after the fix:
- A numerical authorship probability is displayed ONLY from the
  canonical ``consensus.calibrated_ai_probability`` field together
  with ``consensus.ensemble_calibration_id``, showing the exact value
  and the calibration identity. Anything else renders as
  unavailable / not calibrated -- never a verdict-derived number.
- Missing family calibration is N/A (a gap in the chart), not 50%.
- Raw native detector scores are shown with native semantics only,
  never as a probability percentage.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

REPO_ROOT = Path(__file__).parent.parent
APP_JS = REPO_ROOT / "src" / "textforensics" / "web_ui" / "static" / "app.js"
HARNESS_JS = Path(__file__).parent / "w2e_if04_harness.js"

CALIBRATION_ID = "ens-cal-2026-11-01"


def _bundle(verdict, prob=None, cal_id=None, votes=None):
    return {
        "consensus": {
            "verdict": verdict,
            "calibrated_ai_probability": prob,
            "ensemble_calibration_id": cal_id,
            "independent_families": 2,
            "family_agreement": 1.0,
            "calibrated_families": 0,
            "family_votes": (
                votes
                if votes is not None
                else [
                    {
                        "detector_family": "statistical",
                        "verdict": verdict,
                        "calibrated_ai_probability": None,
                    },
                    {
                        "detector_family": "perplexity",
                        "verdict": verdict,
                        "calibrated_ai_probability": None,
                    },
                ]
            ),
            "warnings": [],
        },
        "trust_map": {"overall": "partial", "dimensions": []},
        "detector_results": [],
        "input": {"word_count": 42, "sentence_count": 3, "paragraph_count": 1},
        "content_sha256": "ab" * 32,
        "generated_at_utc": "2026-11-11T00:00:00Z",
    }


def _run(case: dict) -> dict:
    if shutil.which("node") is None:
        pytest.skip("node is not available for the JS UI test")
    proc = subprocess.run(
        ["node", str(HARNESS_JS), str(APP_JS), json.dumps(case)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def _gauge_texts(out: dict) -> list[str]:
    return out["fillTexts"]


def _assert_no_numerical_probability(out: dict) -> None:
    """No rendered text may carry a numerical authorship probability."""
    for text in _gauge_texts(out):
        assert not re.search(r"\d+(\.\d+)?%", text), f"numerical probability shown: {text!r}"
    for text in out["texts"].values():
        assert "AI Probability: " not in text or "not calibrated" in text.lower(), text


class TestIF04GaugeNoFabrication:
    @pytest.mark.parametrize("verdict", ["ai_like", "human_like", "abstain", "failed"])
    def test_uncalibrated_verdict_shows_no_numerical_probability(self, verdict):
        out = _run({"fn": "gauge", "bundle": _bundle(verdict)})
        assert out["charts"][0]["datasets"] == [[0, 100]]
        assert _gauge_texts(out)[0] == "N/A"
        assert "not calibrated" in _gauge_texts(out)[1].lower()
        _assert_no_numerical_probability(out)

    def test_calibrated_value_without_calibration_id_is_unavailable(self):
        out = _run({"fn": "gauge", "bundle": _bundle("ai_like", prob=0.734, cal_id=None)})
        assert out["charts"][0]["datasets"] == [[0, 100]]
        assert _gauge_texts(out)[0] == "N/A"
        _assert_no_numerical_probability(out)

    def test_calibrated_value_out_of_range_is_unavailable(self):
        out = _run({"fn": "gauge", "bundle": _bundle("ai_like", prob=1.4, cal_id=CALIBRATION_ID)})
        assert _gauge_texts(out)[0] == "N/A"
        _assert_no_numerical_probability(out)

    def test_valid_canonical_calibrated_field_displays_exact_value_and_identity(self):
        out = _run({"fn": "gauge", "bundle": _bundle("ai_like", prob=0.734, cal_id=CALIBRATION_ID)})
        # The complement is a float subtraction; compare approximately.
        assert out["charts"][0]["datasets"][0][0] == pytest.approx(73.4)
        assert out["charts"][0]["datasets"][0][1] == pytest.approx(26.6)
        assert _gauge_texts(out)[0] == "73.4%"
        assert CALIBRATION_ID in _gauge_texts(out)[1]

    def test_metrics_uncalibrated_shows_no_probability(self):
        out = _run({"fn": "metrics", "bundle": _bundle("ai_like")})
        text = out["texts"]["consensusConfidence"]
        assert "%" not in text
        assert "Families agreeing" in text

    def test_metrics_calibrated_shows_exact_value_and_identity(self):
        out = _run(
            {"fn": "metrics", "bundle": _bundle("ai_like", prob=0.734, cal_id=CALIBRATION_ID)}
        )
        text = out["texts"]["consensusConfidence"]
        assert "73.4%" in text
        assert CALIBRATION_ID in text


class TestIF04FamilyChart:
    def test_missing_family_calibration_is_gap_not_fifty(self):
        out = _run({"fn": "detector_chart", "bundle": _bundle("abstain")})
        assert out["charts"][0]["datasets"] == [[None, None]]

    def test_calibrated_family_displays_exact_value(self):
        votes = [
            {
                "detector_family": "statistical",
                "verdict": "ai_like",
                "calibrated_ai_probability": 0.62,
            },
            {
                "detector_family": "perplexity",
                "verdict": "abstain",
                "calibrated_ai_probability": None,
            },
        ]
        out = _run({"fn": "detector_chart", "bundle": _bundle("ai_like", votes=votes)})
        assert out["charts"][0]["datasets"] == [[62.0, None]]


class TestIF04OtherSurfaces:
    def test_verdict_display_uncalibrated_is_not_calibrated_never_nan(self):
        out = _run({"fn": "verdict", "bundle": _bundle("ai_like")})
        html = out["html"]["verdictDisplay"]
        assert "Not calibrated" in html
        assert "NaN" not in html
        assert not re.search(r"\d+(\.\d+)?%", html.split("AI Probability")[1])

    def test_verdict_display_calibrated_shows_exact_value_and_identity(self):
        out = _run(
            {"fn": "verdict", "bundle": _bundle("ai_like", prob=0.734, cal_id=CALIBRATION_ID)}
        )
        html = out["html"]["verdictDisplay"]
        assert "73.4%" in html
        assert CALIBRATION_ID in html

    def test_detector_list_native_score_is_not_a_percentage(self):
        bundle = _bundle("abstain")
        bundle["detector_results"] = [
            {
                "detector_id": "builtin-heuristic",
                "detector_version": "1.0",
                "detector_family": "statistical",
                "execution": "local",
                "score": 0.723,
                "calibrated_ai_probability": None,
                "verdict": "human_like",
            }
        ]
        out = _run({"fn": "detector_list", "bundle": bundle})
        html = out["html"]["detectorList"]
        assert "native 0.723" in html
        assert "72.3%" not in html

    def test_detector_list_calibrated_probability_keeps_exact_value(self):
        bundle = _bundle("ai_like")
        bundle["detector_results"] = [
            {
                "detector_id": "builtin-heuristic",
                "detector_version": "1.0",
                "detector_family": "statistical",
                "execution": "local",
                "score": 0.723,
                "calibrated_ai_probability": 0.81,
                "verdict": "ai_like",
            }
        ]
        out = _run({"fn": "detector_list", "bundle": bundle})
        assert "81.0%" in out["html"]["detectorList"]

    def test_compare_view_uncalibrated_is_not_calibrated(self):
        out = _run(
            {
                "fn": "compare",
                "bundle": _bundle("ai_like"),
                "extra": {"second": _bundle("human_like")},
            }
        )
        for key in ("compareASummary", "compareBSummary"):
            assert "Not calibrated" in out["html"][key]

    def test_compare_view_calibrated_shows_exact_values(self):
        out = _run(
            {
                "fn": "compare",
                "bundle": _bundle("ai_like", prob=0.734, cal_id=CALIBRATION_ID),
                "extra": {"second": _bundle("human_like", prob=0.21, cal_id=CALIBRATION_ID)},
            }
        )
        assert "73.4%" in out["html"]["compareASummary"]
        assert "21.0%" in out["html"]["compareBSummary"]

    def test_history_uncalibrated_shows_no_percentage(self):
        out = _run(
            {"fn": "history", "bundle": _bundle("ai_like"), "extra": {"text": "sample text"}}
        )
        html = out["html"]["historyList"]
        assert "%" not in html

    def test_history_calibrated_shows_exact_value_and_identity(self):
        out = _run(
            {
                "fn": "history",
                "bundle": _bundle("ai_like", prob=0.734, cal_id=CALIBRATION_ID),
                "extra": {"text": "sample text"},
            }
        )
        html = out["html"]["historyList"]
        assert "73.4%" in html
        assert CALIBRATION_ID in html


class TestIF04SourceGuard:
    def test_no_bare_ai_probability_field_and_no_verdict_fallbacks(self):
        source = APP_JS.read_text(encoding="utf-8")
        # The canonical field is `calibrated_ai_probability`; a bare
        # `ai_probability` read (not preceded by a word character, so
        # `calibrated_ai_probability` does not match) must not exist.
        assert re.search(r"(?<![\w])ai_probability", source) is None
        # No verdict-derived probability substitutes in the gauge.
        assert re.search(r"aiProb\s*=\s*(85|15|50)\b", source) is None
        # No 50% substitute for a missing family calibration.
        assert re.search(r"calibrated_ai_probability[^;]{0,160}:\s*50\b", source) is None
