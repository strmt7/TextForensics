"""U3 drift observatory: probe runs, persistence-gated alerts, demotion.

This module is the *run* half of U3 (research §7.6). It builds on two
things that already exist and does not rebuild them:

* ``observatory.py`` — ``DriftObservatory`` snapshots are the per-run
  score records. A probe run scores the frozen probe corpus with
  ``take_snapshot`` and stores the snapshot; this module reads the
  snapshot records back, never raw probe text.
* ``probe_metrics`` (``textforensics.probe_metrics``, built on the
  ``u3-corpus`` branch) — the pure statistical functions for §7.6
  metrics 1–7 (KS, PSI, Wilson CIs, flip summaries, ECE/Brier, FPR/TPR,
  abstention rate, metadata diff, Holm). This module *aggregates* those
  functions per slice and per run; it does not reimplement them. The
  import is lazy (``load_probe_metrics``) so this module loads and its
  alert/demotion logic is testable before that branch merges; the
  metric functions accept an injected ``primitives`` object for tests.

What this module owns:

* The pre-registered alert thresholds (research §7.5/§7.6). They are
  module constants and are recorded in every run manifest, so a run's
  verdicts are reproducible from the manifest alone.
* The probe-run record (``textforensics.probe-run/v1``): corpus
  version + freeze fingerprint, detector/provider metadata, code SHA,
  baseline + previous run linkage, per-slice + overall metrics, the
  three-tier alerts, demotions applied/cleared, watches, and gap
  declarations. Run history is a directory of one file per run
  (append-only: runs are never edited; a correction is a new run).
* Baseline management: the first genuinely complete run after a corpus
  freeze is the baseline; a detector/provider version change
  re-baselines explicitly (the old baseline is retained in history,
  never silently replaced). An incomplete run never becomes a baseline.
* The three-tier, persistence-gated alert engine (``evaluate_tiers``)
  and the demotion hook into the U1 registry (``apply_demotions`` /
  ``clear_demotions`` via ``limits.demoted_by`` — see ``validation.py``).
* The longitudinal summary (``summarize_longitudinal``) that feeds
  ``validation.derive_trust_map(longitudinal=...)`` — the evidence that
  lets a v3 Trust Map's ``temporal_version_stability`` exceed
  ``partial``.

Iron rules (research §7.5/§7.6, enforced in code, never merely in docs):

* Never demote on a drift statistic alone. Drift statistics (KS/PSI)
  can only ever produce Tier 3 (record) or Tier 2 (investigate, on 2
  consecutive runs). Tier 1 (demote) requires a measured performance
  breach: a human-slice FPR above its declared cap (CI-aware), a flip
  rate above 5%, a conformal coverage shortfall above 10pp, or a
  detector/provider version change with no probe run within 7 days on
  an adequately sampled run (n>=50 scored observations; a below-floor
  run records the change as a Tier-2 watch, never a demotion — audit
  W4/S07).
* Never claim drift from one sample or one run. Slices below n=50
  carry no drift signal; human-FPR claims need n>=100 per slice.
  The sample floor applies to the ACTUAL comparison denominator
  (audit W2/S07): paired n for flips and score shift, matched
  calibrated n for calibration drift, human-labelled paired n for
  the human->AI flip rate — never total current records. A
  below-floor comparison is recorded in the metrics, never escalated.
* A single run never demotes on a drift statistic. It CAN demote on
  a measured performance breach at its declared floor — this is the
  deliberate first-run policy, reconciled explicitly (audit W2/S07)
  against the old blanket "single run never demotes" wording, which
  the FPR-cap and flip rules always contradicted: (a) the absolute
  human-slice FPR rule demotes on the first run when n_human >= 100
  and the Wilson CI lower bound is above the cap; (b) the
  human->AI flip rule demotes on the first run when the paired
  human-labelled n >= 50 and the human->AI flip rate is above 5%.
  No other single-run demotion exists.
* An alert may demote a Trust Map tier and require human review, but
  must never silently change a verdict on a user's text. Demotion
  marks U1 registry records ``stale`` (via ``limits.demoted_by``);
  the Trust Map then shows ``stale`` for the affected dimensions and
  the operator withholds binary verdicts on the affected slices until
  a full re-run passes. No verdict is ever rewritten by an alert.
* Run completeness is an invariant against the selected item set
  (audit W4/S01): failed/missing/abstained observations are retained
  on the run manifest, and an incomplete run never clears demotions,
  never becomes a baseline, and never advances temporal support.
* Demotions are source-scoped (audit W4/S03): a U3 demotion is one
  segment of ``limits.demoted_by``; a foreign/manual demotion is an
  independent segment that a U3 demotion never overwrites and a later
  clean run never erases.
* Detector/provider/model/config/corpus identity defines an evidence
  epoch (audit W4/S06): the longitudinal summary evaluates chronology
  before filtering, so intervening versions, partial-run breaches and
  provider changes break the streak; only genuinely complete clean
  full runs in the current epoch count toward temporal support.

Deliberate gaps in v1.0 (recorded in every run manifest's ``gaps``,
never silently omitted):

* MMD (Tier 3 trigger in the research) is unavailable: it needs
  ~500+ samples per set and quadratic cost; per-slice n=50 is far
  below that, and no implementation ships. Tier 3 fires on PSI/KS.
* Conformal coverage is unavailable: no conformal machinery exists
  anywhere in the repo (zero mentions of "conformal" in ``src/``).
  Coverage-dependent tier rules (shortfall >5pp Tier 2, >10pp Tier 1)
  are therefore inactive and recorded as such. U5 (full Mondrian
  conformal) is deferred to v1.1; U3 measures coverage of whatever
  conformal machinery exists, and none exists yet.
* ECE/Brier are unavailable for detectors that emit no calibrated
  probability. A native detector score is never relabelled as a
  probability (AGENTS.md rule 2).
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .execution_policy import CancellationToken, ExecutionPolicy

from .datasets import default_cache_dir
from .execution_policy import CompletenessAccounting
from .probe_metrics import (
    normalize_score_direction,
    oriented_scores,
    reject_nonfinite_value,
    require_finite_number,
    strict_json_loads,
)
from .validation import (
    MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT,
    ValidationRecord,
    ValidationRegistry,
    compute_signature,
    load_validation_registry,
)

__all__ = [
    "PROBE_RUN_SCHEMA",
    "ALPHA_PER_RUN",
    "PSI_STABLE",
    "PSI_ACTION",
    "KS_EFFECT_SIZE",
    "KS_P_THRESHOLD",
    "FLIP_RATE_TIER2",
    "FLIP_RATE_TIER1",
    "ECE_INCREASE_TIER2",
    "COVERAGE_SHORTFALL_TIER2_PP",
    "COVERAGE_SHORTFALL_TIER1_PP",
    "VERSION_CHANGE_STALE_DAYS",
    "MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT",
    "MIN_SLICE_N",
    "MIN_SLICE_N_FOR_FPR_CLAIM",
    "HUMAN_SLICES",
    "ATTACKED_SLICES",
    "ProbeMetricsUnavailable",
    "ProbeRunError",
    "compute_run_completeness",
    "has_u3_demotion",
    "load_probe_metrics",
    "compute_run_metrics",
    "evaluate_tiers",
    "apply_demotions",
    "clear_demotions",
    "resolve_baseline",
    "summarize_longitudinal",
    "build_run_manifest",
    "validate_run_manifest",
    "perform_probe_run",
    "save_run",
    "load_run",
    "load_run_history",
    "default_probe_runs_dir",
]

PROBE_RUN_SCHEMA = "textforensics.probe-run/v1"

# ---------------------------------------------------------------------------
# Pre-registered thresholds (research §7.5/§7.6). These are design choices
# recorded in every run manifest; changing one is a deliberate, documented
# act, not a silent tweak.
# ---------------------------------------------------------------------------

ALPHA_PER_RUN = 0.05  # Pre-registered per-run alpha; Holm-corrected across slices.
PSI_STABLE = 0.1  # Evidently band: PSI < 0.1 stable.
PSI_ACTION = 0.2  # Evidently band: PSI > 0.2 investigate/act (Tier 3 trigger).
KS_EFFECT_SIZE = 0.10  # Pre-registered effect size for the KS Tier-3 rule
# (matches the §7.2 0.1 convention for normed Wasserstein / Jensen-Shannon).
KS_P_THRESHOLD = 0.05  # KS p-value gate, always paired with the effect size.
FLIP_RATE_TIER2 = 0.01  # >1% flips with Wilson CI excluding 0 -> investigate.
FLIP_RATE_TIER1 = 0.05  # >5% human->AI flips on a human slice -> demote (FPR event).
ECE_INCREASE_TIER2 = 0.05  # ECE increase > 0.05 -> investigate.
COVERAGE_SHORTFALL_TIER2_PP = 5.0  # Conformal coverage shortfall > 5pp -> investigate.
COVERAGE_SHORTFALL_TIER1_PP = 10.0  # Conformal coverage shortfall > 10pp -> demote.
VERSION_CHANGE_STALE_DAYS = 7  # Version change with no probe run within 7 days -> demote.
# Consecutive clean full-corpus runs at one detector version before
# temporal_version_stability may exceed partial. Owned by validation.py
# (the Trust Map owns the rule); imported here for the run manifest.
MIN_SLICE_N = 50  # Per-slice minimum for drift-signal purposes (§7.6).
MIN_SLICE_N_FOR_FPR_CLAIM = 100  # Per-slice minimum before any human-FPR claim.
FPR_CAP_DEFAULT = 0.05  # Declared human-FPR cap; same value as the Trust Map ceiling.

# Slice roles. The corpus half defines the slice names
# (``probe_corpus.SLICES``); these two subsets are the U3 policy view of
# them. Unknown slices are measured like any other slice; only these two
# subsets carry extra rules.
HUMAN_SLICES = ("human-native", "human-short")
ATTACKED_SLICES = ("ai-paraphrased", "ai-humanized")

RUN_SCOPES = ("full", "monthly-attacked", "monthly-current-generator", "event-driven")

RUN_LIMITATIONS = [
    "Probe-run metrics describe detector behaviour on the frozen probe corpus; they do not prove authorship for real-world documents.",
    "A drift statistic alone never demotes a detector; demotion requires a measured performance breach on the probe corpus.",
    "A single run never demotes on a drift statistic (Tier 3 only; Tier 2 on 2 consecutive runs). A single run CAN demote on a measured performance breach at its declared floor: the absolute human-slice FPR rule (n_human >= 100, Wilson CI lower bound above the cap) or the human->AI flip rule (paired human-labelled n >= 50, flip rate above 5%). No other single-run demotion exists.",
    "Sample floors apply to the actual comparison denominator (paired n for flips and score shift, matched calibrated n for calibration drift, human-labelled paired n for the human->AI flip rate), never to total current records. Below-floor comparisons are recorded, never escalated as adequately sampled drift.",
    "A version/provider change with no probe run within 7 days demotes only on an adequately sampled run (n>=50 scored observations); a below-floor run records the change as a Tier-2 watch for investigation, never as a demotion.",
    "An alert never silently changes a verdict on a user's text; demotion marks U1 registry records stale and the operator withholds binary verdicts on affected slices until a full re-run passes.",
    "Conformal coverage is unavailable: no conformal machinery exists in the repo (U5 is deferred to v1.1). Coverage-dependent tier rules are inactive.",
    "MMD is unavailable in v1.0 (needs ~500+ samples per set; per-slice n=50 is far below that). Tier 3 fires on PSI/KS.",
    "Raw probe text is intentionally omitted from run manifests; items are cited by ID + hash only.",
]

_SCOPE_STATEMENT = (
    "probe run: integrity of the scored corpus only — origin of a verdict "
    "is the detector run recorded here; a clean run does not prove the "
    "detector is correct on unseen text."
)


class ProbeRunError(ValueError):
    """A probe-run record, history, or tier evaluation is malformed."""


class ProbeMetricsUnavailable(ProbeRunError):
    """The ``textforensics.probe_metrics`` primitives are not importable.

    They ship on the ``u3-corpus`` branch; until that branch merges,
    metric computation needs an injected ``primitives`` object (tests do
    this) and the ``drift run`` CLI refuses with this error.
    """


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_hex64(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def _round(value: float | None, digits: int = 6) -> float | None:
    if value is None:
        return None
    return round(float(value), digits)


def _require_nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProbeRunError(f"{field_name} must be a non-empty string.")
    return value


def _require_hex64(value: Any, field_name: str) -> str:
    if not _is_hex64(value):
        raise ProbeRunError(f"{field_name} must be a 64-character hex digest.")
    return str(value)


def default_probe_runs_dir(*, corpus_version: str = "1.0.0") -> Path:
    """Local run-history directory for one corpus version (never in the repo).

    Sits next to the probe corpus itself (``~/.cache/textforensics/``):
    corpus text lives under ``probe-corpus/<version>/``, run manifests
    (IDs + hashes + metrics, no raw text) under ``probe-runs/<version>/``.
    """
    return default_cache_dir().parent / "probe-runs" / corpus_version


def git_code_sha(*, repo_root: Path | None = None) -> str:
    """Best-effort git SHA for the code that produced a run, else ``unknown``."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root) if repo_root is not None else None,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    sha = (result.stdout or "").strip()
    return sha if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha) else "unknown"


# ---------------------------------------------------------------------------
# Statistical primitives seam
# ---------------------------------------------------------------------------

_PRIMITIVE_NAMES = (
    "wilson_ci",
    "ks_statistic",
    "ks_pvalue",
    "psi",
    "flip_summary",
    "ece",
    "brier",
    "set_coverage",
    "coverage_shortfall_pp",
    "fpr_at_threshold",
    "worst_slice_fpr",
    "tpr_at_fpr",
    "abstention_rate",
    "metadata_diff",
    "holm_adjusted",
)


def load_probe_metrics(primitives: Any = None) -> Any:
    """Return the ``probe_metrics`` primitives module (or an injected stub).

    The real module is ``textforensics.probe_metrics`` (merged with the
    frozen probe corpus). Callers that need metric computation must
    inject a ``primitives`` object exposing the same function names
    (tests do this); otherwise :class:`ProbeMetricsUnavailable` is
    raised with a clear message.
    """
    if primitives is not None:
        missing = [name for name in _PRIMITIVE_NAMES if not hasattr(primitives, name)]
        if missing:
            raise ProbeRunError(
                f"injected probe-metrics primitives lack: {', '.join(sorted(missing))}"
            )
        return primitives
    try:
        from . import probe_metrics
    except ImportError as exc:
        raise ProbeMetricsUnavailable(
            "textforensics.probe_metrics is not available: metric "
            "computation needs the probe-metrics module; alert/demotion "
            "logic does not."
        ) from exc
    missing = [name for name in _PRIMITIVE_NAMES if not hasattr(probe_metrics, name)]
    if missing:  # pragma: no cover - defensive; the module defines all of them
        raise ProbeRunError(f"probe_metrics lacks: {', '.join(sorted(missing))}")
    return probe_metrics


# ---------------------------------------------------------------------------
# Per-run metrics (§7.6 metrics 1–7)
# ---------------------------------------------------------------------------


def _records_by_item(records: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    by_item: dict[str, Mapping[str, Any]] = {}
    for record in records:
        sample_id = record.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            raise ProbeRunError("snapshot records need a non-empty sample_id.")
        if sample_id in by_item:
            raise ProbeRunError(f"duplicate snapshot record for sample {sample_id!r}.")
        by_item[sample_id] = record
    return by_item


def _records_from_series(series: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Rebuild the minimal snapshot records a stored score series stands for.

    The metrics only ever read ``score``, ``verdict``,
    ``calibrated_ai_probability`` and ``calibration_id`` from baseline /
    previous records, so the series (numbers + IDs, never raw text) is
    sufficient for KS/PSI/flip/calibration comparisons. The series
    also carries the shared score-direction contract (S09):
    ``native_score_direction`` and ``score_range`` round-trip here so
    a stored run orients its ROC exactly like the live run did.
    Legacy series without a direction rebuild as ``"unknown"``.
    """
    records: list[dict[str, Any]] = []
    for item_id in sorted(series):
        entry = series[item_id]
        records.append(
            {
                "sample_id": item_id,
                "score": entry.get("score"),
                "verdict": entry.get("verdict"),
                "calibrated_ai_probability": entry.get("calibrated_ai_probability"),
                "calibration_id": entry.get("calibration_id"),
                "native_score_direction": normalize_score_direction(
                    entry.get("native_score_direction")
                ),
                "score_range": entry.get("score_range"),
            }
        )
    return records


def _series_from_records(records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Reduce snapshot records to the stored score series (no raw text)."""
    series: dict[str, dict[str, Any]] = {}
    for record in records:
        sample_id = record.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            raise ProbeRunError("snapshot records need a non-empty sample_id.")
        score = _score(record)
        if score is None:
            raise ProbeRunError(f"snapshot record for {sample_id!r} has no score.")
        series[sample_id] = {
            "score": score,
            "verdict": _verdict(record),
            "calibrated_ai_probability": _calibrated_probability(record),
            "calibration_id": record.get("calibration_id"),
            "native_score_direction": normalize_score_direction(
                record.get("native_score_direction")
            ),
            "score_range": record.get("score_range"),
        }
    return series


def _score(record: Mapping[str, Any]) -> float | None:
    value = record.get("score")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProbeRunError(f"snapshot record score must be a number, got {value!r}.")
    try:
        return require_finite_number(value, "snapshot record score")
    except ValueError as exc:
        raise ProbeRunError(str(exc)) from exc


def _calibrated_probability(record: Mapping[str, Any]) -> float | None:
    value = record.get("calibrated_ai_probability")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProbeRunError(f"calibrated_ai_probability must be a number, got {value!r}.")
    if not 0.0 <= float(value) <= 1.0:
        raise ProbeRunError(f"calibrated_ai_probability must be in [0, 1], got {value!r}.")
    return float(value)


def _verdict(record: Mapping[str, Any]) -> str:
    verdict = record.get("verdict")
    if verdict not in ("ai_like", "human_like", "abstain"):
        raise ProbeRunError(f"unknown verdict {verdict!r}.")
    return str(verdict)


def _score_shift_status(shift: Mapping[str, Any]) -> tuple[str, str]:
    """Status + reason for a score-shift dict, from the Tier-3 rule.

    ``breach`` iff PSI > 0.2, or KS effect >= 0.10 with Holm-adjusted
    p < 0.05 — exactly the rule :func:`_drift_breaches_for_slice`
    applies, so the label can never disagree with the breach list.
    Before the Holm fill the adjusted p is None and the KS branch
    cannot fire (same as the breach rule); the caller recomputes the
    status after the fill.
    """
    psi = shift.get("psi")
    ks = shift.get("ks_statistic")
    ks_p_adj = shift.get("ks_pvalue_holm_adjusted")
    if psi is not None and psi > PSI_ACTION:
        return "breach", f"PSI {psi} > {PSI_ACTION}"
    if (
        ks is not None
        and ks_p_adj is not None
        and ks_p_adj < KS_P_THRESHOLD
        and ks >= KS_EFFECT_SIZE
    ):
        return (
            "breach",
            f"KS statistic {ks} >= {KS_EFFECT_SIZE} with Holm-adjusted p "
            f"{ks_p_adj} < {KS_P_THRESHOLD}",
        )
    if psi is None and ks is None:
        return "unavailable", "no baseline run to compare against"
    return "stable", "PSI <= 0.2 and KS within bounds"


def _slice_metrics(
    *,
    item_ids: list[str],
    current: dict[str, Mapping[str, Any]],
    baseline: dict[str, Mapping[str, Any]] | None,
    previous: dict[str, Mapping[str, Any]] | None,
    labels: Mapping[str, int | None],
    primitives: Any,
    is_human_slice: bool,
    is_attacked_slice: bool,
    human_scores_all: list[float],
    human_labels_all: list[int],
    calibration_created_at: Mapping[str, str] | None,
    now: datetime,
    score_direction: str = "unknown",
) -> dict[str, Any]:
    """The §7.6 metrics for one slice (or the overall population)."""
    present = [item for item in item_ids if item in current]
    n = len(present)
    scores = [_score(current[item]) for item in present]
    scores = [s for s in scores if s is not None]
    verdicts = [_verdict(current[item]) for item in present]
    # Items with label None (mixed-origin: no binary label exists) are
    # scored and counted, but excluded from every label-dependent
    # metric (FPR, TPR, ECE/Brier). They are never treated as human or
    # machine by assumption.
    labelled = [item for item in present if labels[item] is not None]
    item_labels = [int(labels[item]) for item in labelled]
    n_human = sum(1 for y in item_labels if y == 0)
    n_ai = sum(1 for y in item_labels if y == 1)

    # Metric 1: score-distribution shift vs the baseline run (KS + PSI).
    score_shift: dict[str, Any] = {
        "ks_statistic": None,
        "ks_pvalue": None,
        "ks_pvalue_holm_adjusted": None,
        "psi": None,
        "n_paired": None,
        "status": "unavailable",
        "reason": "no baseline run to compare against",
    }
    if baseline is not None:
        baseline_scores = [
            s for item in present if item in baseline and (s := _score(baseline[item])) is not None
        ]
        # The comparison denominator is the matched (paired) score
        # count — items present in both runs with a score — not the
        # total current n (S07). The tier engine gates on it.
        score_shift["n_paired"] = len(baseline_scores)
        if scores and baseline_scores:
            ks = primitives.ks_statistic(baseline_scores, scores)
            ks_p = primitives.ks_pvalue(ks, len(baseline_scores), len(scores))
            psi_value = primitives.psi(baseline_scores, scores)
            # Status is preliminary here (no Holm-adjusted p yet); the
            # caller recomputes it after the Holm fill.
            status, reason = _score_shift_status(
                {
                    "psi": _round(psi_value),
                    "ks_statistic": _round(ks),
                    "ks_pvalue_holm_adjusted": None,
                }
            )
            score_shift = {
                "ks_statistic": _round(ks),
                "ks_pvalue": _round(ks_p),
                "ks_pvalue_holm_adjusted": None,  # Filled in by the caller (family = slices).
                "psi": _round(psi_value),
                "n_paired": len(baseline_scores),
                "status": status,
                "reason": reason,
            }
        else:
            score_shift["reason"] = "no paired scores against the baseline run"

    # Metric 2: verdict-flip rate vs the previous run (directional, Wilson CI).
    flips: dict[str, Any] | None = None
    if previous is not None:
        prev_verdicts: list[str] = []
        curr_verdicts: list[str] = []
        for item in present:
            if item in previous:
                prev_verdicts.append(_verdict(previous[item]))
                curr_verdicts.append(_verdict(current[item]))
        if prev_verdicts:
            summary = primitives.flip_summary(prev_verdicts, curr_verdicts)
            # S07: the Tier-1 human->AI rate is a rate over HUMAN-labelled
            # paired items only. A verdict flip on an AI-labelled (or
            # mixed-origin) item is not a human false-positive event,
            # and the denominator is the paired human count, never the
            # total current n or the all-labels paired n.
            n_human_paired = 0
            human_to_ai_human = 0
            for item in present:
                if item in previous and labels[item] == 0:
                    n_human_paired += 1
                    if (
                        _verdict(previous[item]) == "human_like"
                        and _verdict(current[item]) == "ai_like"
                    ):
                        human_to_ai_human += 1
            flips = {
                "n": summary["n"],
                "flips": summary["flips"],
                "flip_rate": _round(summary["flip_rate"]),
                "flip_rate_ci": [
                    _round(summary["flip_rate_ci"][0]),
                    _round(summary["flip_rate_ci"][1]),
                ],
                "human_to_ai": summary["human_to_ai"],
                "ai_to_human": summary["ai_to_human"],
                "to_abstain": summary["to_abstain"],
                "from_abstain": summary["from_abstain"],
                "n_human_paired": n_human_paired,
                "human_to_ai_human": human_to_ai_human,
            }

    # Metric 3: calibration drift — ECE + Brier where calibrated
    # probabilities are emitted; conformal coverage is unavailable
    # (no conformal machinery exists in the repo; U5 is v1.1).
    probs = [_calibrated_probability(current[item]) for item in labelled]
    current_prob_by_item = {item: _calibrated_probability(current[item]) for item in labelled}
    n_calibrated_current = sum(1 for p in probs if p is not None)
    # S21: the baseline comparison uses an explicitly matched item set
    # — labelled items present in BOTH runs with a calibrated
    # probability in each. A partial baseline used to raise KeyError
    # here (direct ``baseline[item]`` indexing); the aggregate is now
    # computed only over the matched set when it covers every
    # labelled item, and withheld with disclosed counts otherwise.
    # Surviving inputs are never silently averaged as the slice ECE.
    matched_items: list[str] = []
    n_calibrated_baseline = 0
    if baseline is not None:
        for item in labelled:
            if item in baseline:
                baseline_prob = _calibrated_probability(baseline[item])
                if baseline_prob is not None:
                    n_calibrated_baseline += 1
                    if current_prob_by_item[item] is not None:
                        matched_items.append(item)
    calibration: dict[str, Any] = {
        "ece": None,
        "brier": None,
        "baseline_ece": None,
        "baseline_ece_reason": None,
        # S21: structured missing-calibration evidence (None when the
        # baseline covers every labelled item). A partial baseline
        # withholds the aggregate AND records exactly which items are
        # missing, instead of a bare reason string a reader must
        # parse — or the KeyError the audit repro hit.
        "missing_calibration": None,
        "n_calibrated_current": n_calibrated_current,
        "n_calibrated_paired": len(matched_items),
        "n_calibrated_baseline": n_calibrated_baseline,
        "conformal_coverage": None,
        "conformal_status": "unavailable",
        "conformal_reason": (
            "no conformal machinery exists in the repo; conformal coverage "
            "cannot be measured until U5 lands (v1.1)"
        ),
        "calibration_id_changed": None,
        "calibration_staleness_days": None,
    }
    if probs and all(p is not None for p in probs):
        calibration["ece"] = _round(primitives.ece([float(p) for p in probs], item_labels))
        calibration["brier"] = _round(primitives.brier([float(p) for p in probs], item_labels))
        # Baseline ECE for the Tier-2 calibration-drift rule (ECE increase
        # > 0.05): the matched set only, and only when it covers every
        # labelled item. A partial match withholds the aggregate.
        if baseline is not None:
            if matched_items and len(matched_items) == len(labelled):
                matched_labels = [int(labels[item]) for item in matched_items]
                matched_baseline_probs = [
                    float(_calibrated_probability(baseline[item]))  # type: ignore[arg-type]
                    for item in matched_items
                ]
                calibration["baseline_ece"] = _round(
                    primitives.ece(matched_baseline_probs, matched_labels)
                )
            else:
                missing_item_ids = [item for item in labelled if item not in matched_items]
                calibration["baseline_ece_reason"] = (
                    f"baseline_ece unavailable: only {len(matched_items)} of "
                    f"{len(labelled)} labelled items have a matched baseline "
                    "calibrated probability; the aggregate is withheld, not "
                    "averaged over the surviving inputs."
                )
                calibration["missing_calibration"] = {
                    "reason": (
                        f"baseline_ece unavailable: only {len(matched_items)} of "
                        f"{len(labelled)} labelled items have a matched baseline "
                        "calibrated probability; missing calibrated baseline "
                        f"probability for items {missing_item_ids}; the aggregate "
                        "is withheld, not averaged over the surviving inputs."
                    ),
                    "n_matched": len(matched_items),
                    "n_labelled": len(labelled),
                    "missing_item_ids": missing_item_ids,
                }
    elif probs and any(p is not None for p in probs):
        calibration["conformal_reason"] = (
            "calibrated probabilities are present for only some items; "
            "ECE/Brier need all items (mixed availability is recorded, not averaged)"
        )
    else:
        calibration["conformal_reason"] = (
            "detector emits no calibrated probability; ECE/Brier need "
            "calibrated probabilities, never a relabelled native score. "
            "Conformal coverage is unavailable: no conformal machinery "
            "exists in the repo (U5 is v1.1)."
        )
    if baseline is not None:
        baseline_ids = {
            str(baseline[item].get("calibration_id"))
            for item in present
            if item in baseline and baseline[item].get("calibration_id") is not None
        }
        current_ids = {
            str(current[item].get("calibration_id"))
            for item in present
            if current[item].get("calibration_id") is not None
        }
        if baseline_ids or current_ids:
            calibration["calibration_id_changed"] = baseline_ids != current_ids
    if calibration_created_at:
        ages: list[int] = []
        for item in present:
            cal_id = current[item].get("calibration_id")
            if cal_id is not None and str(cal_id) in calibration_created_at:
                created = datetime.fromisoformat(str(calibration_created_at[str(cal_id)]))
                ages.append((now - created).days)
        if ages:
            calibration["calibration_staleness_days"] = max(ages)

    # Metric 4: human-slice FPR at the declared operating point (verdicts)
    # + Wilson CI. A claim needs n_human >= 100; below that the rate is
    # reported but flagged as not claimable.
    human_fpr: dict[str, Any] | None = None
    if is_human_slice and n_human > 0:
        false_positives = sum(
            1
            for item, y in zip(labelled, item_labels, strict=True)
            if y == 0 and _verdict(current[item]) == "ai_like"
        )
        lo, hi = primitives.wilson_ci(false_positives, n_human)
        human_fpr = {
            "n_human": n_human,
            "false_positives": false_positives,
            "fpr": _round(false_positives / n_human),
            "fpr_ci": [_round(lo), _round(hi)],
            "fpr_claim_allowed": n_human >= MIN_SLICE_N_FOR_FPR_CLAIM,
            "cap": FPR_CAP_DEFAULT,
        }

    # Metric 5: attacked-slice TPR@1% FPR. The FPR axis needs human items,
    # which an attacked slice does not contain, so the negative class is
    # the human slices' scores (the detector's human population). The
    # operating point is threshold-free (empirical ROC); the result is a
    # measurement, not a fitted threshold.
    #
    # S09: the ROC is oriented through the shared score-direction
    # contract. The primitive is direction-agnostic (higher tail), so
    # the combined native scores are oriented first
    # (``oriented_scores``: negation for lower-means-AI, affine
    # equivalent) and the returned threshold is mapped back to native
    # score units. For unknown / not-applicable direction the metric
    # is unavailable — never computed under a guessed orientation.
    attacked_tpr: dict[str, Any] | None = None
    if is_attacked_slice:
        machine_scores = [
            float(s)
            for item, y in zip(labelled, item_labels, strict=True)
            if y == 1 and (s := _score(current[item])) is not None
        ]
        if score_direction in ("unknown", "not_applicable"):
            attacked_tpr = {
                "tpr_at_1pct_fpr": None,
                "achieved_fpr": None,
                "threshold": None,
                "n_machine": len(machine_scores),
                "n_human_reference": len(human_scores_all),
                "score_direction": score_direction,
                "reason": (
                    "score direction is "
                    f"{score_direction!r}; TPR at a target FPR is unavailable "
                    "without a known score direction."
                ),
            }
        elif machine_scores and human_scores_all:
            combined_scores = human_scores_all + machine_scores
            combined_labels = human_labels_all + [1] * len(machine_scores)
            oriented = oriented_scores(combined_scores, direction=score_direction)
            result = primitives.tpr_at_fpr(oriented, combined_labels, target_fpr=0.01)
            native_threshold = (
                -result["threshold"] if score_direction == "lower_means_ai" else result["threshold"]
            )
            attacked_tpr = {
                "tpr_at_1pct_fpr": _round(result["tpr"]),
                "achieved_fpr": _round(result["achieved_fpr"]),
                "threshold": _round(native_threshold),
                "n_machine": len(machine_scores),
                "n_human_reference": len(human_scores_all),
                "score_direction": score_direction,
            }
        else:
            attacked_tpr = {
                "tpr_at_1pct_fpr": None,
                "achieved_fpr": None,
                "threshold": None,
                "n_machine": len(machine_scores),
                "n_human_reference": len(human_scores_all),
                "score_direction": score_direction,
                "reason": "no human reference scores or no machine scores in slice",
            }

    # Metric 7: abstention/coverage rate.
    abstention = (
        primitives.abstention_rate(verdicts)
        if verdicts
        else {
            "n": 0,
            "abstained": 0,
            "rate": None,
        }
    )

    return {
        "n": n,
        "n_human": n_human,
        "n_ai": n_ai,
        "is_human_slice": is_human_slice,
        "drift_signal_allowed": n >= MIN_SLICE_N,
        "score_shift": score_shift,
        "flips": flips,
        "calibration": calibration,
        "human_fpr": human_fpr,
        "attacked_tpr": attacked_tpr,
        "abstention_rate": _round(abstention["rate"]) if abstention["rate"] is not None else None,
        "abstained": abstention["abstained"],
    }


def compute_run_completeness(
    *,
    selected_item_ids: Sequence[str],
    records: Sequence[Mapping[str, Any]],
    failures: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute the run-completeness accounting for one probe run.

    The accounting is an invariant against the *selected* item set
    (audit W4/S01): every selected item is accounted for exactly once
    as succeeded, abstained, failed, or missing. The counts use the
    shared :class:`CompletenessAccounting` type (W1/CORE-07), so the
    semantics are the ones ``trust.py``/``validation.py`` already
    enforce: ``is_complete`` iff every selected item was attempted;
    ``support_eligible`` iff the run is complete AND every selected
    item succeeded — no failures, no abstentions. Failed, missing and
    abstained item IDs are retained on the manifest; an incomplete run
    is never a clean full-corpus revalidation, never clears demotions,
    never becomes a baseline, and never advances temporal support.
    """
    selected = list(dict.fromkeys(str(item_id) for item_id in selected_item_ids))
    selected_set = set(selected)
    succeeded_ids: list[str] = []
    abstained_ids: list[str] = []
    seen_records: set[str] = set()
    for record in records:
        sample_id = record.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            raise ProbeRunError("snapshot records need a non-empty sample_id.")
        if sample_id in seen_records:
            raise ProbeRunError(f"duplicate snapshot record for sample {sample_id!r}.")
        seen_records.add(sample_id)
        if record.get("verdict") == "abstain":
            abstained_ids.append(sample_id)
        else:
            succeeded_ids.append(sample_id)
    failed_ids: list[str] = []
    seen_failures: set[str] = set()
    for failure in failures or []:
        sample_id = failure.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id:
            continue
        if sample_id in seen_records or sample_id in seen_failures:
            continue
        seen_failures.add(sample_id)
        failed_ids.append(sample_id)
    attempted_ids = seen_records | seen_failures
    missing_ids = sorted(selected_set - attempted_ids)
    # Outcomes outside the selected set are attempted work, not
    # selected work: they count toward attempted but cannot make the
    # run complete for the selected set.
    try:
        accounting = CompletenessAccounting(
            selected=len(selected),
            attempted=len(attempted_ids),
            succeeded=len(succeeded_ids),
            abstained=len(abstained_ids),
            failed=len(failed_ids),
        )
    except ValueError as exc:
        raise ProbeRunError(f"run completeness accounting is inconsistent: {exc}") from exc
    return {
        **accounting.to_dict(),
        "failed_item_ids": sorted(failed_ids),
        "missing_item_ids": missing_ids,
        "abstained_item_ids": sorted(abstained_ids),
    }


def _completeness_is_support_eligible(manifest: Mapping[str, Any]) -> bool:
    """Return ``True`` iff a run manifest proves a complete clean run.

    Only a manifest whose ``completeness`` accounting is present AND
    ``support_eligible`` counts. A manifest without completeness
    accounting (legacy, pre-W4) is NOT eligible: its coverage was
    never verified, so it cannot clear demotions, serve as a baseline,
    or advance temporal support (fail closed, S01).
    """
    completeness = manifest.get("completeness")
    if not isinstance(completeness, Mapping):
        return False
    return bool(completeness.get("support_eligible"))


def compute_run_metrics(
    *,
    current_records: Sequence[Mapping[str, Any]],
    baseline_records: Sequence[Mapping[str, Any]] | None,
    previous_records: Sequence[Mapping[str, Any]] | None,
    labels: Mapping[str, int | None],
    slices: Mapping[str, str],
    detector_id: str,
    primitives: Any = None,
    calibration_created_at: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compute the §7.6 per-run metrics (per slice + overall).

    ``current_records`` are this run's snapshot records,
    ``baseline_records`` the baseline run's (None for the baseline run
    itself), ``previous_records`` the previous run's (None on the first
    run). ``labels`` maps item_id -> 0 (human) / 1 (machine) / None
    (mixed-origin: no binary label exists) and is read from the
    holdback file only after scoring. ``slices`` maps
    item_id -> slice name from the corpus manifest. Scores are native
    detector scores; only ``calibrated_ai_probability`` (when the
    detector emits it) feeds ECE/Brier. The return value is JSON-safe.
    """
    primitives = load_probe_metrics(primitives)
    detector_id = _require_nonempty_string(detector_id, "detector_id")
    now = now or datetime.now(UTC)
    current = _records_by_item(current_records)
    baseline = _records_by_item(baseline_records) if baseline_records is not None else None
    previous = _records_by_item(previous_records) if previous_records is not None else None

    # S09: one score direction per run, from the shared contract.
    # Records that never declared one are "unknown" (never guessed);
    # two different known directions in one run cannot be aggregated
    # — their scores are not comparable — and fail closed. The same
    # holds for a run that mixes a known direction with undeclared
    # records: silently orienting the undeclared records by the known
    # direction would reverse a valid detector exactly as the audit
    # repro shows (lower_score_direction_ignored), so that mix fails
    # closed too. A run that is uniformly "unknown" stays computable:
    # direction-dependent metrics are then withheld, not guessed.
    directions = {
        normalize_score_direction(record.get("native_score_direction"))
        for record in current.values()
    }
    known_directions = directions - {"unknown"}
    if len(known_directions) > 1 or (known_directions and "unknown" in directions):
        raise ProbeRunError(
            "mixed native_score_direction values in one run: "
            f"{sorted(directions)}; records with an undeclared direction "
            "cannot be aggregated with records that declared one — "
            "their scores are not comparable."
        )
    score_direction = known_directions.pop() if known_directions else "unknown"

    for item_id, label in labels.items():
        if label is not None and label not in (0, 1):
            raise ProbeRunError(f"label for {item_id!r} must be 0, 1, or None, got {label!r}.")
    for item_id in current:
        if item_id not in labels:
            raise ProbeRunError(
                f"scored item {item_id!r} has no holdback label; labels are read "
                "only after scoring and must cover every scored item."
            )
        if item_id not in slices:
            raise ProbeRunError(f"scored item {item_id!r} has no slice in the manifest.")

    by_slice: dict[str, list[str]] = {}
    for item_id in sorted(current):
        by_slice.setdefault(str(slices[item_id]), []).append(item_id)

    human_scores_all: list[float] = []
    human_labels_all: list[int] = []
    for item_id, record in current.items():
        if labels[item_id] == 0 and (s := _score(record)) is not None:
            human_scores_all.append(float(s))
            human_labels_all.append(0)

    slice_metrics: dict[str, Any] = {}
    ks_pvalues: list[tuple[str, float]] = []
    for slice_name in sorted(by_slice):
        result = _slice_metrics(
            item_ids=by_slice[slice_name],
            current=current,
            baseline=baseline,
            previous=previous,
            labels=labels,
            primitives=primitives,
            is_human_slice=slice_name in HUMAN_SLICES,
            is_attacked_slice=slice_name in ATTACKED_SLICES,
            human_scores_all=human_scores_all,
            human_labels_all=human_labels_all,
            calibration_created_at=calibration_created_at,
            now=now,
            score_direction=score_direction,
        )
        slice_metrics[slice_name] = result
        ks_p = result["score_shift"].get("ks_pvalue")
        if ks_p is not None:
            ks_pvalues.append((slice_name, float(ks_p)))

    # Multiple-testing control (§7.5 rule 4): the family is the per-slice
    # KS tests in this run. Holm-adjusted p-values are recorded; the Tier-3
    # KS rule uses the adjusted p-value.
    holm_adjusted: dict[str, float] = {}
    if ks_pvalues:
        adjusted = primitives.holm_adjusted([p for _, p in ks_pvalues])
        for (slice_name, _), adj in zip(ks_pvalues, adjusted, strict=True):
            holm_adjusted[slice_name] = _round(adj)
            slice_metrics[slice_name]["score_shift"]["ks_pvalue_holm_adjusted"] = _round(adj)
    # The score-shift status follows the Tier-3 rule (PSI or KS with
    # Holm-adjusted p); recompute it now the adjusted p-values exist,
    # so the label can never disagree with the breach list.
    for slice_name in slice_metrics:
        shift = slice_metrics[slice_name]["score_shift"]
        if shift.get("ks_statistic") is not None or shift.get("psi") is not None:
            status, reason = _score_shift_status(shift)
            shift["status"] = status
            shift["reason"] = reason

    overall = _slice_metrics(
        item_ids=sorted(current),
        current=current,
        baseline=baseline,
        previous=previous,
        labels=labels,
        primitives=primitives,
        is_human_slice=True,  # Overall FPR is over all human items.
        is_attacked_slice=False,
        human_scores_all=human_scores_all,
        human_labels_all=human_labels_all,
        calibration_created_at=calibration_created_at,
        now=now,
        score_direction=score_direction,
    )

    # Worst human-slice FPR (never the mean) across claimable human slices.
    claimable = {
        name: result["human_fpr"]
        for name, result in slice_metrics.items()
        if result["human_fpr"] is not None and result["human_fpr"]["fpr_claim_allowed"]
    }
    worst_fpr: dict[str, Any] | None = None
    if claimable:
        worst = primitives.worst_slice_fpr(claimable)
        worst_fpr = {
            "slice": worst["slice"],
            "fpr": _round(worst["fpr"]),
            "fpr_ci": [_round(worst["fpr_ci"][0]), _round(worst["fpr_ci"][1])],
            "n_human": worst["n_human"],
        }

    return {
        "detector_id": detector_id,
        "score_direction": score_direction,
        "slices": slice_metrics,
        "overall": overall,
        "worst_slice_fpr": worst_fpr,
        "holm": {
            "alpha_per_run": ALPHA_PER_RUN,
            "family": "per-slice KS tests",
            "adjusted_pvalues": holm_adjusted,
        },
    }


# ---------------------------------------------------------------------------
# Three-tier, persistence-gated alerts (§7.5/§7.6)
# ---------------------------------------------------------------------------

# Rule identifiers, stable across runs (persistence keys on rule+slice).
RULE_DRIFT_STATISTIC = "drift_statistic"
RULE_FLIP_RATE = "flip_rate"
RULE_CALIBRATION_DRIFT = "calibration_drift"
RULE_FPR_CAP = "human_fpr_cap"
RULE_COVERAGE_SHORTFALL = "conformal_coverage_shortfall"
RULE_VERSION_CHANGE_NO_RUN = "version_change_no_probe_run"


def _breach_key(rule: str, slice_name: str) -> str:
    return f"{rule}:{slice_name}"


def _drift_breaches_for_slice(
    slice_metrics: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Tier-3 drift-statistic breaches for one slice (PSI/KS only).

    MMD is unavailable in v1.0 (see the module docstring); the gap is
    recorded on the run manifest, not silently skipped.
    """
    breaches: list[dict[str, Any]] = []
    shift = slice_metrics.get("score_shift") or {}
    psi_value = shift.get("psi")
    if psi_value is not None and psi_value > PSI_ACTION:
        breaches.append(
            {
                "rule": RULE_DRIFT_STATISTIC,
                "statistic": "psi",
                "value": psi_value,
                "threshold": PSI_ACTION,
                "detail": f"PSI {psi_value} > {PSI_ACTION}",
            }
        )
    ks_stat = shift.get("ks_statistic")
    ks_p_adj = shift.get("ks_pvalue_holm_adjusted")
    ks_p = shift.get("ks_pvalue")
    if (
        ks_stat is not None
        and ks_p_adj is not None
        and ks_p_adj < KS_P_THRESHOLD
        and ks_stat >= KS_EFFECT_SIZE
    ):
        breaches.append(
            {
                "rule": RULE_DRIFT_STATISTIC,
                "statistic": "ks",
                "value": ks_stat,
                "pvalue_holm_adjusted": ks_p_adj,
                "pvalue_raw": ks_p,
                "threshold": KS_EFFECT_SIZE,
                "detail": (
                    f"KS statistic {ks_stat} >= {KS_EFFECT_SIZE} with "
                    f"Holm-adjusted p {ks_p_adj} < {KS_P_THRESHOLD}"
                ),
            }
        )
    return breaches


def _run_scored_count(metrics: Mapping[str, Any]) -> int | None:
    """Return the run's total scored-observation count, or ``None``.

    The overall ``n`` when present, else the sum of the per-slice
    ``n`` values. ``None`` means the metrics carry no usable count —
    the caller must treat that as below floor (fail closed, S07).
    """
    overall = metrics.get("overall")
    if isinstance(overall, Mapping):
        n = overall.get("n")
        if isinstance(n, int) and not isinstance(n, bool):
            return n
    total = 0
    seen_any = False
    slices = metrics.get("slices")
    if isinstance(slices, Mapping):
        for slice_metrics in slices.values():
            if isinstance(slice_metrics, Mapping):
                n = slice_metrics.get("n")
                if isinstance(n, int) and not isinstance(n, bool):
                    total += n
                    seen_any = True
    return total if seen_any else None


def evaluate_tiers(
    *,
    metrics: Mapping[str, Any],
    previous_breaches: Sequence[Mapping[str, Any]] | None = None,
    previous_run_at: str | None = None,
    detector_version: str,
    previous_detector_version: str | None = None,
    previous_provider_metadata: Mapping[str, Any] | None = None,
    provider_metadata: Mapping[str, Any] | None = None,
    run_at: str | None = None,
    fpr_cap: float = FPR_CAP_DEFAULT,
) -> dict[str, Any]:
    """Evaluate the three-tier alerts for one probe run.

    ``metrics`` is a :func:`compute_run_metrics` result.
    ``previous_breaches`` are the previous run's Tier-3 drift breaches
    (``rule`` + ``slice`` pairs) — persistence is evaluated against
    them. Version-change inputs drive the event-driven Tier-1 rule.
    Returns ``{"alerts": [...], "breaches": [...], "demote": bool,
    "watch": bool}``. ``breaches`` is the Tier-3 breach list the *next*
    run needs for persistence; it is stored on the run manifest.

    Iron rule, enforced here: a drift statistic alone can only ever
    produce Tier 3 (single run) or Tier 2 (2 consecutive runs). Tier 1
    requires a measured performance breach.
    """
    detector_version = _require_nonempty_string(detector_version, "detector_version")
    previous_breaches = list(previous_breaches or [])
    previous_keys = {
        _breach_key(str(b.get("rule", "")), str(b.get("slice", ""))) for b in previous_breaches
    }
    slices = metrics.get("slices") or {}
    overall = metrics.get("overall") or {}

    alerts: list[dict[str, Any]] = []
    breaches: list[dict[str, Any]] = []
    demote = False
    watch = False

    def _alert(
        *,
        tier: int,
        rule: str,
        slice_name: str,
        statistic: Mapping[str, Any],
        threshold: Any,
        consecutive_runs: int,
        action: str,
        detail: str,
    ) -> None:
        alerts.append(
            {
                "tier": tier,
                "rule": rule,
                "slice": slice_name,
                "statistic": dict(statistic),
                "threshold": threshold,
                "consecutive_runs": consecutive_runs,
                "action": action,
                "detail": detail,
            }
        )

    # --- Drift statistics (Tier 3 single run; Tier 2 on 2 consecutive runs).
    # One alert per (rule, slice): several statistics may breach at once
    # (PSI and KS on the same slice) and they are one drift event, not
    # two. The per-statistic breach records stay in ``breaches`` as the
    # detailed evidence the next run needs for persistence.
    for slice_name in sorted(slices):
        slice_metrics = slices[slice_name]
        if not slice_metrics.get("drift_signal_allowed"):
            continue
        # S07: the drift floor applies to the ACTUAL comparison
        # denominator — the paired score count — not total current
        # records. A below-floor comparison is recorded in the
        # metrics, never escalated (no alert, no breach for the next
        # run's persistence). Legacy metrics dicts predate the paired
        # count and fall back to the slice n.
        shift = slice_metrics.get("score_shift") or {}
        n_paired = shift.get("n_paired")
        if n_paired is None:
            n_paired = slice_metrics.get("n")
        if n_paired is None or n_paired < MIN_SLICE_N:
            continue
        slice_breaches = _drift_breaches_for_slice(slice_metrics)
        if not slice_breaches:
            continue
        for breach in slice_breaches:
            record = {"rule": breach["rule"], "slice": slice_name, **breach}
            breaches.append(record)
        key = _breach_key(RULE_DRIFT_STATISTIC, slice_name)
        consecutive = 2 if key in previous_keys else 1
        detail = "; ".join(b["detail"] for b in slice_breaches)
        statistic = {
            "statistics": [
                {"statistic": b["statistic"], "value": b["value"]} for b in slice_breaches
            ]
        }
        if consecutive >= 2:
            watch = True
            _alert(
                tier=2,
                rule=RULE_DRIFT_STATISTIC,
                slice_name=slice_name,
                statistic=statistic,
                threshold={
                    "psi_action": PSI_ACTION,
                    "ks_effect_size": KS_EFFECT_SIZE,
                    "ks_p_threshold": KS_P_THRESHOLD,
                },
                consecutive_runs=consecutive,
                action="investigate",
                detail=(
                    f"Drift statistic breached on 2 consecutive runs ({detail}). "
                    "Trust Map watch; human review required; no verdict changes."
                ),
            )
        else:
            _alert(
                tier=3,
                rule=RULE_DRIFT_STATISTIC,
                slice_name=slice_name,
                statistic=statistic,
                threshold={
                    "psi_action": PSI_ACTION,
                    "ks_effect_size": KS_EFFECT_SIZE,
                    "ks_p_threshold": KS_P_THRESHOLD,
                },
                consecutive_runs=consecutive,
                action="record",
                detail=(
                    f"Single-run drift statistic breach ({detail}). Logged only; no Trust Map change."
                ),
            )

    # --- Verdict flips (Tier 2 at >1% with Wilson CI excluding 0;
    # Tier 1 at >5% human->AI flips on a human slice only). A flip
    # toward AI on a human slice is an FPR event; a flip toward human
    # is a recovery (or a sensitivity loss on machine slices) and must
    # never demote on its own — otherwise the clean re-run that
    # recovers from a demotion would re-demote the detector and the
    # demotion could never clear. The verdict-based FPR rule already
    # covers sustained human-slice FPR; this rule covers the case
    # where the FPR is not claimable (n_human < 100) but a mass
    # human->AI flip is still a measured performance breach.
    for slice_name in sorted(slices):
        slice_metrics = slices[slice_name]
        flips = (slice_metrics or {}).get("flips")
        if not flips:
            continue
        rate = flips["flip_rate"]
        ci_lo, ci_hi = flips["flip_rate_ci"]
        n_flips = flips["n"] or 0
        # S07: the Tier-1 rate is over HUMAN-labelled paired items
        # only, at a paired human floor of MIN_SLICE_N. Legacy metrics
        # dicts predate the split fields and fall back to the
        # verdict-based count over all paired items (still floored).
        if "n_human_paired" in flips and "human_to_ai_human" in flips:
            n_human_paired = flips["n_human_paired"] or 0
            human_to_ai_human = flips["human_to_ai_human"] or 0
        else:
            n_human_paired = n_flips
            human_to_ai_human = flips["human_to_ai"] or 0
        human_to_ai_rate = human_to_ai_human / n_human_paired if n_human_paired else 0.0
        is_human = slice_metrics.get("is_human_slice", slice_name in HUMAN_SLICES)
        if is_human and n_human_paired >= MIN_SLICE_N and human_to_ai_rate > FLIP_RATE_TIER1:
            demote = True
            _alert(
                tier=1,
                rule=RULE_FLIP_RATE,
                slice_name=slice_name,
                statistic={
                    "flip_rate": rate,
                    "human_to_ai_rate": human_to_ai_rate,
                    "flip_rate_ci": [ci_lo, ci_hi],
                    "flips": flips["flips"],
                    "n": flips["n"],
                    "n_human_paired": n_human_paired,
                    "human_to_ai": flips["human_to_ai"],
                    "human_to_ai_human": human_to_ai_human,
                    "ai_to_human": flips["ai_to_human"],
                },
                threshold=FLIP_RATE_TIER1,
                consecutive_runs=1,
                action="demote",
                detail=(
                    f"Human->AI flip rate {human_to_ai_rate} > {FLIP_RATE_TIER1} on human slice {slice_name!r} "
                    f"({human_to_ai_human} human->AI flips over {n_human_paired} paired human-labelled items; "
                    f"{flips['ai_to_human']} AI->human). "
                    "Demote the detector's U1 records to stale; withhold binary verdicts until a full re-run passes."
                ),
            )
        elif rate is not None and n_flips >= MIN_SLICE_N and rate > FLIP_RATE_TIER2 and ci_lo > 0:
            watch = True
            _alert(
                tier=2,
                rule=RULE_FLIP_RATE,
                slice_name=slice_name,
                statistic={
                    "flip_rate": rate,
                    "flip_rate_ci": [ci_lo, ci_hi],
                    "flips": flips["flips"],
                    "n": flips["n"],
                },
                threshold=FLIP_RATE_TIER2,
                consecutive_runs=1,
                action="investigate",
                detail=(
                    f"Flip rate {rate} > {FLIP_RATE_TIER2} with Wilson CI "
                    f"excluding 0 ([{ci_lo}, {ci_hi}]). Trust Map watch; human review required."
                ),
            )
    # Overall flips are Tier 2 only: they mix human->AI and AI->human
    # directions across slices, so they can never be a Tier-1
    # performance breach on their own (a recovery run flips massively
    # toward human). The per-slice human->AI rule above is the Tier-1
    # flip rule.
    overall_flips = overall.get("flips")
    if overall_flips:
        rate = overall_flips["flip_rate"]
        ci_lo, _ = overall_flips["flip_rate_ci"]
        if (
            rate is not None
            and (overall_flips["n"] or 0) >= MIN_SLICE_N
            and rate > FLIP_RATE_TIER2
            and ci_lo > 0
        ):
            watch = True
            _alert(
                tier=2,
                rule=RULE_FLIP_RATE,
                slice_name="overall",
                statistic={
                    "flip_rate": rate,
                    "flip_rate_ci": overall_flips["flip_rate_ci"],
                    "flips": overall_flips["flips"],
                    "n": overall_flips["n"],
                },
                threshold=FLIP_RATE_TIER2,
                consecutive_runs=1,
                action="investigate",
                detail=(
                    f"Overall flip rate {rate} > {FLIP_RATE_TIER2} with Wilson CI excluding 0. Trust Map watch; human review required."
                ),
            )

    # --- Calibration drift (Tier 2: ECE increase > 0.05). Conformal
    # coverage is unavailable in v1.0, so its sub-rules are inactive.
    # S07: the ECE comparison needs an adequately sampled MATCHED
    # calibrated set (n_calibrated_paired >= MIN_SLICE_N). A metrics
    # dict without the matched count (legacy) never escalates.
    for slice_name in sorted(slices):
        calibration = (slices[slice_name] or {}).get("calibration") or {}
        ece = calibration.get("ece")
        baseline_ece = calibration.get("baseline_ece")
        n_calibrated_paired = calibration.get("n_calibrated_paired")
        if (
            ece is not None
            and baseline_ece is not None
            and n_calibrated_paired is not None
            and n_calibrated_paired >= MIN_SLICE_N
            and (ece - baseline_ece) > ECE_INCREASE_TIER2
        ):
            watch = True
            _alert(
                tier=2,
                rule=RULE_CALIBRATION_DRIFT,
                slice_name=slice_name,
                statistic={
                    "ece": ece,
                    "baseline_ece": baseline_ece,
                    "increase": ece - baseline_ece,
                    "n_calibrated_paired": n_calibrated_paired,
                },
                threshold=ECE_INCREASE_TIER2,
                consecutive_runs=1,
                action="investigate",
                detail=(
                    f"ECE increased by {ece - baseline_ece} (>{ECE_INCREASE_TIER2}) on slice {slice_name!r} "
                    f"over {n_calibrated_paired} matched calibrated items. Trust Map watch; human review required."
                ),
            )

    # --- Human-slice FPR cap (Tier 1, CI-aware: lower CI bound above cap).
    # Only claimable slices (n_human >= 100) can breach; below that the
    # rate is reported but never demotes.
    for slice_name in sorted(slices):
        human_fpr = (slices[slice_name] or {}).get("human_fpr")
        if not human_fpr or not human_fpr.get("fpr_claim_allowed"):
            continue
        ci_lo = human_fpr["fpr_ci"][0]
        if ci_lo > fpr_cap:
            demote = True
            _alert(
                tier=1,
                rule=RULE_FPR_CAP,
                slice_name=slice_name,
                statistic={
                    "fpr": human_fpr["fpr"],
                    "fpr_ci": human_fpr["fpr_ci"],
                    "n_human": human_fpr["n_human"],
                    "false_positives": human_fpr["false_positives"],
                },
                threshold=fpr_cap,
                consecutive_runs=1,
                action="demote",
                detail=(
                    f"Human-slice FPR on {slice_name!r} is {human_fpr['fpr']} with Wilson CI lower bound {ci_lo} above the declared cap {fpr_cap}. "
                    "Demote the detector's U1 records to stale; withhold binary verdicts until a full re-run passes."
                ),
            )

    # --- Detector/provider version change with no probe run within 7 days.
    # S07: this Tier-1 rule is a measurement-backed escalation, so it
    # fires only on an adequately sampled run: at least MIN_SLICE_N
    # scored observations in total. A below-floor run records the
    # change as a Tier-2 watch for investigation — a single human
    # sample must never cause a detector-wide demotion — and the change
    # stays unrevalidated until an adequately sampled run decides it.
    n_scored = _run_scored_count(metrics)
    adequately_sampled = n_scored is not None and n_scored >= MIN_SLICE_N
    if previous_detector_version is not None and previous_detector_version != detector_version:
        days_since_previous = None
        if previous_run_at is not None and run_at is not None:
            days_since_previous = (
                datetime.fromisoformat(run_at) - datetime.fromisoformat(previous_run_at)
            ).days
        if days_since_previous is None or days_since_previous > VERSION_CHANGE_STALE_DAYS:
            if adequately_sampled:
                demote = True
                _alert(
                    tier=1,
                    rule=RULE_VERSION_CHANGE_NO_RUN,
                    slice_name="overall",
                    statistic={
                        "previous_detector_version": previous_detector_version,
                        "detector_version": detector_version,
                        "days_since_previous_run": days_since_previous,
                        "n_scored": n_scored,
                    },
                    threshold=VERSION_CHANGE_STALE_DAYS,
                    consecutive_runs=1,
                    action="demote",
                    detail=(
                        f"Detector version changed {previous_detector_version!r} -> {detector_version!r} with no probe run within {VERSION_CHANGE_STALE_DAYS} days "
                        f"({days_since_previous} days since the previous run). Demote the detector's U1 records to stale until this run completes."
                    ),
                )
            else:
                watch = True
                _alert(
                    tier=2,
                    rule=RULE_VERSION_CHANGE_NO_RUN,
                    slice_name="overall",
                    statistic={
                        "previous_detector_version": previous_detector_version,
                        "detector_version": detector_version,
                        "days_since_previous_run": days_since_previous,
                        "n_scored": n_scored,
                    },
                    threshold=VERSION_CHANGE_STALE_DAYS,
                    consecutive_runs=1,
                    action="investigate",
                    detail=(
                        f"Detector version changed {previous_detector_version!r} -> {detector_version!r} with no probe run within {VERSION_CHANGE_STALE_DAYS} days "
                        f"({days_since_previous} days since the previous run), but this run scored only {n_scored} observation(s) "
                        f"(below the {MIN_SLICE_N} sample floor). The change is recorded for investigation, not escalated to a demotion."
                    ),
                )
    provider_diff = {}
    if previous_provider_metadata is not None and provider_metadata is not None:
        for key in sorted(set(previous_provider_metadata) | set(provider_metadata)):
            prev, curr = previous_provider_metadata.get(key), provider_metadata.get(key)
            if prev != curr:
                provider_diff[key] = [prev, curr]
    if provider_diff and previous_run_at is not None and run_at is not None:
        days_since_previous = (
            datetime.fromisoformat(run_at) - datetime.fromisoformat(previous_run_at)
        ).days
        if days_since_previous > VERSION_CHANGE_STALE_DAYS:
            if adequately_sampled:
                demote = True
                _alert(
                    tier=1,
                    rule=RULE_VERSION_CHANGE_NO_RUN,
                    slice_name="overall",
                    statistic={
                        "provider_metadata_diff": provider_diff,
                        "days_since_previous_run": days_since_previous,
                        "n_scored": n_scored,
                    },
                    threshold=VERSION_CHANGE_STALE_DAYS,
                    consecutive_runs=1,
                    action="demote",
                    detail=(
                        f"Provider metadata changed {provider_diff} with no probe run within {VERSION_CHANGE_STALE_DAYS} days "
                        f"({days_since_previous} days since the previous run). Demote the detector's U1 records to stale until this run completes."
                    ),
                )
            else:
                watch = True
                _alert(
                    tier=2,
                    rule=RULE_VERSION_CHANGE_NO_RUN,
                    slice_name="overall",
                    statistic={
                        "provider_metadata_diff": provider_diff,
                        "days_since_previous_run": days_since_previous,
                        "n_scored": n_scored,
                    },
                    threshold=VERSION_CHANGE_STALE_DAYS,
                    consecutive_runs=1,
                    action="investigate",
                    detail=(
                        f"Provider metadata changed {provider_diff} with no probe run within {VERSION_CHANGE_STALE_DAYS} days "
                        f"({days_since_previous} days since the previous run), but this run scored only {n_scored} observation(s) "
                        f"(below the {MIN_SLICE_N} sample floor). The change is recorded for investigation, not escalated to a demotion."
                    ),
                )

    return {
        "alerts": alerts,
        "breaches": breaches,
        "demote": demote,
        "watch": watch,
    }


# ---------------------------------------------------------------------------
# Demotion hook into the U1 registry (validation.py)
# ---------------------------------------------------------------------------


# Demotions are source-scoped segments of ``limits.demoted_by``
# (audit W4/S03). A record can carry several independent demotions at
# once — a manual/foreign reason and one U3 reason per probe run — and
# clearing the U3 restriction must never erase the foreign one. The
# segments are joined with ``_DEMOTION_SEPARATOR``; a foreign reason is
# kept verbatim as its own segment, never rewritten. A segment that
# starts with the reserved ``U3 probe run `` prefix is a U3 demotion;
# foreign reasons must not be given that prefix (a foreign reason that
# already starts with it is indistinguishable from a U3 demotion, as
# before — the prefix is reserved for U3).
_DEMOTION_SEPARATOR = " || "
_U3_DEMOTION_PREFIX = "U3 probe run "


def _split_demotions(demoted_by: str | None) -> list[str]:
    """Split a ``limits.demoted_by`` value into its source segments."""
    if not demoted_by:
        return []
    return [segment for segment in demoted_by.split(_DEMOTION_SEPARATOR) if segment]


def _join_demotions(segments: Sequence[str]) -> str | None:
    """Join demotion segments, or ``None`` when none remain."""
    kept = [segment for segment in segments if segment]
    return _DEMOTION_SEPARATOR.join(kept) if kept else None


def has_u3_demotion(demoted_by: str | None) -> bool:
    """Return ``True`` iff ``demoted_by`` carries a U3 demotion segment."""
    return any(segment.startswith(_U3_DEMOTION_PREFIX) for segment in _split_demotions(demoted_by))


def _resigned_record(record: ValidationRecord, limits: Any) -> ValidationRecord:
    """Return a copy of ``record`` with ``limits`` set + re-signed."""
    unsigned = record.to_dict()
    unsigned["limits"] = limits.to_dict()
    unsigned.pop("signature", None)
    return dataclasses.replace(record, limits=limits, signature=compute_signature(unsigned))


def _demoted_record(record: ValidationRecord, *, reason: str) -> ValidationRecord:
    """Return a copy of ``record`` with a U3 demotion segment appended.

    Any existing demotion segments — foreign/manual reasons and U3
    reasons from earlier runs — are preserved verbatim; the new U3
    reason is appended as its own segment, so the history stays
    auditable. Re-applying the identical reason is a no-op (the
    record is returned unchanged apart from re-signing with the same
    content).
    """
    segments = _split_demotions(record.limits.demoted_by)
    if reason not in segments:
        segments.append(reason)
    limits = dataclasses.replace(record.limits, demoted_by=_join_demotions(segments))
    return _resigned_record(record, limits)


def _u3_cleared_record(record: ValidationRecord) -> ValidationRecord:
    """Return a copy of ``record`` with only its U3 segments removed.

    Foreign/manual demotion segments survive verbatim; when none
    remain, ``demoted_by`` becomes ``None``. The record is re-signed.
    """
    kept = [
        segment
        for segment in _split_demotions(record.limits.demoted_by)
        if not segment.startswith(_U3_DEMOTION_PREFIX)
    ]
    limits = dataclasses.replace(record.limits, demoted_by=_join_demotions(kept))
    return _resigned_record(record, limits)


def apply_demotions(
    *,
    registry_path: str | Path,
    detector_id: str,
    run_id: str,
    alerts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Apply Tier-1 demotions to the U1 registry for ``detector_id``.

    For every Tier-1 alert in ``alerts``, every record for the detector
    gets a U3 demotion segment appended to ``limits.demoted_by``
    identifying the probe run and the rule. Demotion is per-detector in
    v1.0 (not per-slice): U1 records are regime-coarse, and a probe-corpus
    performance breach indicts the detector's measured performance
    generally. Per-slice demotion is a v1.1 refinement once records are
    slice-granular.
    Demotions are source-scoped (audit W4/S03): an existing
    foreign/manual demotion segment is preserved verbatim — a U3
    demotion never overwrites it — and a U3 demotion from an earlier
    run stays in the history as its own segment. The registry is
    rewritten atomically and reloaded to verify. When no record exists
    for the detector, nothing is demoted and the gap is reported
    (demotion needs a record to land on).
    """
    detector_id = _require_nonempty_string(detector_id, "detector_id")
    run_id = _require_nonempty_string(run_id, "run_id")
    tier1 = [a for a in alerts if a.get("tier") == 1]
    if not tier1:
        return {"demoted_record_ids": [], "reason": None, "gap": None}
    registry = load_validation_registry(registry_path)
    targets = [r for r in registry.records if r.detector_id == detector_id]
    if not targets:
        return {
            "demoted_record_ids": [],
            "reason": None,
            "gap": (
                f"No U1 validation records exist for detector {detector_id!r}; "
                "Tier-1 alerts cannot demote anything. Add a validation "
                "record for the detector before relying on U3 demotion."
            ),
        }
    rules = sorted({str(a.get("rule", "unknown")) for a in tier1})
    reason = (
        f"U3 probe run {run_id}: Tier-1 alert(s) {', '.join(rules)}; "
        "revalidate on the frozen probe corpus"
    )
    demoted_ids: list[str] = []
    target_ids = {record.record_id for record in targets}
    replaced: list[ValidationRecord] = []
    for record in registry.records:
        if record.record_id in target_ids:
            replaced.append(_demoted_record(record, reason=reason))
            demoted_ids.append(record.record_id)
        else:
            replaced.append(record)
    updated = ValidationRegistry(replaced, created_at_utc=registry.created_at_utc)
    updated.save(registry_path)
    reloaded = load_validation_registry(registry_path)
    if sorted(r.record_id for r in reloaded.records) != sorted(
        r.record_id for r in updated.records
    ):
        raise ProbeRunError("registry reload after demotion does not match the saved registry.")
    return {"demoted_record_ids": sorted(demoted_ids), "reason": reason, "gap": None}


def clear_demotions(
    *,
    registry_path: str | Path,
    detector_id: str,
    run_id: str,
) -> dict[str, Any]:
    """Clear U3 demotions for ``detector_id`` after a full re-run passes.

    Only the U3 demotion segments are removed; demotions from any
    other source are left untouched (audit W4/S03), so a record that
    was manually demoted stays manually demoted — and effectively
    ``stale`` — after a clean U3 run. The record is re-signed on
    clearing, like on demotion. ``cleared_record_ids`` lists every
    record that lost a U3 segment; ``foreign_demotions_retained``
    lists the records that remain demoted for a non-U3 reason.
    """
    detector_id = _require_nonempty_string(detector_id, "detector_id")
    run_id = _require_nonempty_string(run_id, "run_id")
    registry = load_validation_registry(registry_path)
    cleared_ids: list[str] = []
    retained_ids: list[str] = []
    replaced: list[ValidationRecord] = []
    for record in registry.records:
        demoted_by = record.limits.demoted_by
        if record.detector_id == detector_id and has_u3_demotion(demoted_by):
            cleared = _u3_cleared_record(record)
            replaced.append(cleared)
            cleared_ids.append(record.record_id)
            if cleared.limits.demoted_by is not None:
                retained_ids.append(record.record_id)
        else:
            replaced.append(record)
    if not cleared_ids:
        return {"cleared_record_ids": [], "reason": None, "foreign_demotions_retained": []}
    updated = ValidationRegistry(replaced, created_at_utc=registry.created_at_utc)
    updated.save(registry_path)
    reloaded = load_validation_registry(registry_path)
    if sorted(r.record_id for r in reloaded.records) != sorted(
        r.record_id for r in updated.records
    ):
        raise ProbeRunError("registry reload after clearing demotions does not match.")
    reason = f"U3 probe run {run_id}: full re-run passed with no Tier-1 alert"
    if retained_ids:
        reason += f"; {len(retained_ids)} record(s) remain demoted for a non-U3 reason"
    return {
        "cleared_record_ids": sorted(cleared_ids),
        "reason": reason,
        "foreign_demotions_retained": sorted(retained_ids),
    }


# ---------------------------------------------------------------------------
# Baseline management + longitudinal summary
# ---------------------------------------------------------------------------


def _provider_identity(run: Mapping[str, Any]) -> dict[str, Any]:
    """Return a run's provider identity (missing means no provider)."""
    provider = run.get("provider_metadata")
    return dict(provider) if isinstance(provider, Mapping) else {}


def resolve_baseline(
    history: Sequence[Mapping[str, Any]],
    *,
    detector_id: str,
    detector_version: str,
    corpus_fingerprint: str,
    provider_metadata: Mapping[str, Any] | None = None,
) -> Mapping[str, Any] | None:
    """Return the baseline run for this detector/version/corpus, if any.

    The baseline is the run flagged ``is_baseline`` for the same
    detector id, detector version, and corpus fingerprint. Only
    full-scope runs (``full`` / ``event-driven``) can be baselines:
    a monthly partial run never becomes one, however early it ran.
    A version change has no baseline until the re-baseline run
    completes (the caller marks that run ``is_baseline`` with
    ``rebaselined_from``).

    Evidence epochs (audit W4/S01/S06): a baseline must also be a
    *verified complete* run (its ``completeness`` accounting present
    and ``support_eligible``) — an incomplete run can never be a
    baseline — and, when ``provider_metadata`` is given, it must match
    the caller's provider identity exactly, so a run recorded under
    provider ``p1`` is never the baseline for a ``p2`` run.
    """
    candidates = [
        run
        for run in history
        if run.get("detector_id") == detector_id
        and run.get("detector_version") == detector_version
        and run.get("corpus_fingerprint") == corpus_fingerprint
        and run.get("is_baseline") is True
        and run.get("scope") in ("full", "event-driven")
        and _completeness_is_support_eligible(run)
        and (provider_metadata is None or _provider_identity(run) == dict(provider_metadata))
    ]
    if not candidates:
        return None
    return sorted(candidates, key=_run_at_sort_key)[-1]


def summarize_longitudinal(
    history: Sequence[Mapping[str, Any]],
    *,
    detector_id: str,
    detector_version: str,
    corpus_fingerprint: str,
) -> dict[str, Any]:
    """Summarise U3 longitudinal evidence for one detector/version/corpus.

    The summary is computed by ONE chronological state machine over
    the detector's full run history, most recent first (audit W4/S06):
    chronology is evaluated BEFORE any filtering, so nothing that
    breaks a streak is filtered out of sight first.

    * The current evidence epoch is fixed by the most recent run at
      the requested detector version + corpus fingerprint. An earlier
      run with a different detector version, a different corpus
      fingerprint, or a different provider identity ends the epoch:
      the walk stops there, however clean the older runs were
      (``v1 -> v2 -> v1`` is one clean v1 run, not two).
    * A run counts toward the clean-full-run streak only when it is a
      ``full``-scope run with no Tier-1/2 alert AND a verified
      complete run (``completeness.support_eligible`` — audit W4/S01).
      The first run that fails any of those stops the walk.
    * A partial-scope run never counts, but a partial-scope run that
      carries a Tier-1/2 alert DOES break the streak: a current breach
      cannot disappear because its scope is partial.
    * The watch is the most recent Tier-2 alert in the current epoch
      that fewer than ``MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT``
      clean full runs have followed — i.e. the watch expires once the
      streak that re-establishes temporal support is rebuilt. A Tier-1
      breach supersedes any older watch.
    """
    detector_runs = sorted(
        (run for run in history if run.get("detector_id") == detector_id),
        key=lambda r: (str(r.get("run_at_utc", "")), str(r.get("run_id", ""))),
        reverse=True,
    )
    # Epoch membership is fixed BEFORE the streak walk: the current
    # epoch is every run back to (but excluding) the first detector
    # version / corpus fingerprint / provider identity change. A
    # streak break inside the epoch (tier alert, incomplete run) does
    # NOT shrink the epoch: total_runs counts the whole epoch.
    epoch_runs: list[Mapping[str, Any]] = []
    epoch_provider: dict[str, Any] | None = None
    streak_break: dict[str, Any] | None = None
    for run in detector_runs:
        run_id = str(run.get("run_id"))
        if run.get("detector_version") != detector_version:
            streak_break = {"run_id": run_id, "reason": "detector_version_change"}
            break
        if run.get("corpus_fingerprint") != corpus_fingerprint:
            streak_break = {"run_id": run_id, "reason": "corpus_change"}
            break
        provider = _provider_identity(run)
        if epoch_provider is None:
            epoch_provider = provider
        elif provider != epoch_provider:
            streak_break = {"run_id": run_id, "reason": "provider_change"}
            break
        epoch_runs.append(run)
    clean_run_ids: list[str] = []
    watch: dict[str, Any] | None = None
    for run in epoch_runs:
        run_id = str(run.get("run_id"))
        tiers = {a.get("tier") for a in run.get("alerts", [])}
        has_breach = bool(tiers & {1, 2})
        if run.get("scope") != "full":
            if has_breach:
                streak_break = {"run_id": run_id, "reason": "partial_run_breach"}
                tier2 = [a for a in run.get("alerts", []) if a.get("tier") == 2]
                if tier2 and len(clean_run_ids) < MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT:
                    watch = {
                        "run_id": run_id,
                        "run_at_utc": str(run.get("run_at_utc")),
                        "alerts": tier2,
                    }
                break
            continue
        if has_breach:
            streak_break = {"run_id": run_id, "reason": "tier_alert"}
            tier2 = [a for a in run.get("alerts", []) if a.get("tier") == 2]
            if tier2 and len(clean_run_ids) < MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT:
                watch = {
                    "run_id": run_id,
                    "run_at_utc": str(run.get("run_at_utc")),
                    "alerts": tier2,
                }
            break
        if not _completeness_is_support_eligible(run):
            streak_break = {"run_id": run_id, "reason": "incomplete_run"}
            break
        clean_run_ids.append(run_id)
    return {
        "detector_id": detector_id,
        "detector_version": detector_version,
        "corpus_fingerprint": corpus_fingerprint,
        "consecutive_clean_full_runs": len(clean_run_ids),
        "clean_full_run_ids": clean_run_ids,
        "clean_full_runs_needed_for_temporal_support": MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT,
        "temporal_support": len(clean_run_ids) >= MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT,
        "watch": watch,
        "total_runs": len(epoch_runs),
        "last_run_at_utc": str(epoch_runs[0].get("run_at_utc")) if epoch_runs else None,
        "epoch_provider_metadata": epoch_provider,
        "streak_break": streak_break,
    }


# ---------------------------------------------------------------------------
# Run manifest: build / validate / store
# ---------------------------------------------------------------------------


def _validate_completeness(completeness: Mapping[str, Any]) -> None:
    """Fail-closed validation of a run manifest's completeness accounting.

    Counts must be non-negative integers that partition the attempts,
    ``is_complete``/``support_eligible`` must agree with the counts,
    and the retained item-ID lists must be lists of strings. A manifest
    without a completeness field is legacy (pre-W4) and stays valid —
    but it is NOT support-eligible (see :func:`_completeness_is_support_eligible`).
    """
    for field in ("selected", "attempted", "succeeded", "abstained", "failed"):
        value = completeness.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ProbeRunError(
                f"run manifest completeness.{field} must be a non-negative integer."
            )
    selected = completeness["selected"]
    attempted = completeness["attempted"]
    succeeded = completeness["succeeded"]
    abstained = completeness["abstained"]
    failed = completeness["failed"]
    if attempted > selected:
        raise ProbeRunError("run manifest completeness.attempted cannot exceed selected.")
    if succeeded + abstained + failed != attempted:
        raise ProbeRunError(
            "run manifest completeness counts must partition the attempts: "
            "succeeded + abstained + failed must equal attempted."
        )
    is_complete = completeness.get("is_complete")
    support_eligible = completeness.get("support_eligible")
    if is_complete is not None and bool(is_complete) != (attempted == selected):
        raise ProbeRunError("run manifest completeness.is_complete disagrees with the counts.")
    if support_eligible is not None and bool(support_eligible) != (
        attempted == selected and failed == 0 and succeeded == selected
    ):
        raise ProbeRunError("run manifest completeness.support_eligible disagrees with the counts.")
    for field in ("failed_item_ids", "missing_item_ids", "abstained_item_ids"):
        ids = completeness.get(field)
        if ids is not None and (
            not isinstance(ids, list) or any(not isinstance(i, str) for i in ids)
        ):
            raise ProbeRunError(f"run manifest completeness.{field} must be a list of strings.")


def build_run_manifest(
    *,
    run_id: str | None = None,
    run_at_utc: str | None = None,
    scope: str,
    corpus_version: str,
    corpus_fingerprint: str,
    corpus_manifest_sha256: str | None,
    detector_id: str,
    detector_version: str,
    provider_metadata: Mapping[str, Any] | None = None,
    code_sha: str | None = None,
    baseline_run_id: str | None,
    is_baseline: bool,
    rebaselined_from: str | None = None,
    previous_run_id: str | None,
    metrics: Mapping[str, Any],
    alerts: Sequence[Mapping[str, Any]],
    breaches: Sequence[Mapping[str, Any]],
    demotions_applied: Mapping[str, Any] | None = None,
    demotions_cleared: Mapping[str, Any] | None = None,
    watches: Sequence[Mapping[str, Any]] | None = None,
    gaps: Sequence[str] | None = None,
    score_series: Mapping[str, Mapping[str, Any]] | None = None,
    completeness: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a ``textforensics.probe-run/v1`` run manifest (JSON-safe)."""
    if scope not in RUN_SCOPES:
        raise ProbeRunError(f"scope must be one of {RUN_SCOPES}, got {scope!r}.")
    detector_id = _require_nonempty_string(detector_id, "detector_id")
    detector_version = _require_nonempty_string(detector_version, "detector_version")
    corpus_version = _require_nonempty_string(corpus_version, "corpus_version")
    corpus_fingerprint = _require_hex64(corpus_fingerprint, "corpus_fingerprint")
    if corpus_manifest_sha256 is not None:
        _require_hex64(corpus_manifest_sha256, "corpus_manifest_sha256")
    gaps = list(gaps or [])
    gaps.append(
        "MMD is unavailable in v1.0 (needs ~500+ samples per set; per-slice n=50 is far below that). Tier 3 fires on PSI/KS."
    )
    gaps.append(
        "Conformal coverage is unavailable: no conformal machinery exists in the repo (U5 is v1.1). Coverage-dependent tier rules are inactive."
    )
    manifest: dict[str, Any] = {
        "schema": PROBE_RUN_SCHEMA,
        "run_id": run_id or uuid.uuid4().hex,
        "run_at_utc": run_at_utc or _now_iso(),
        "scope": scope,
        "corpus_version": corpus_version,
        "corpus_fingerprint": corpus_fingerprint,
        "corpus_manifest_sha256": corpus_manifest_sha256,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "provider_metadata": dict(provider_metadata or {}),
        "code_sha": code_sha or "unknown",
        "baseline_run_id": baseline_run_id,
        "is_baseline": bool(is_baseline),
        "rebaselined_from": rebaselined_from,
        "previous_run_id": previous_run_id,
        "alpha_per_run": ALPHA_PER_RUN,
        "thresholds": {
            "psi_action": PSI_ACTION,
            "ks_effect_size": KS_EFFECT_SIZE,
            "ks_p_threshold": KS_P_THRESHOLD,
            "flip_rate_tier2": FLIP_RATE_TIER2,
            "flip_rate_tier1": FLIP_RATE_TIER1,
            "ece_increase_tier2": ECE_INCREASE_TIER2,
            "coverage_shortfall_tier2_pp": COVERAGE_SHORTFALL_TIER2_PP,
            "coverage_shortfall_tier1_pp": COVERAGE_SHORTFALL_TIER1_PP,
            "version_change_stale_days": VERSION_CHANGE_STALE_DAYS,
            "min_clean_full_runs_for_temporal_support": MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT,
            "min_slice_n": MIN_SLICE_N,
            "min_slice_n_for_fpr_claim": MIN_SLICE_N_FOR_FPR_CLAIM,
            "fpr_cap": FPR_CAP_DEFAULT,
        },
        "metrics": dict(metrics),
        "alerts": [dict(a) for a in alerts],
        "breaches": [dict(b) for b in breaches],
        "demotions_applied": dict(demotions_applied or {}),
        "demotions_cleared": dict(demotions_cleared or {}),
        "watches": [dict(w) for w in (watches or [])],
        "gaps": gaps,
        "score_series": {k: dict(v) for k, v in (score_series or {}).items()},
        # S01: the completeness accounting is the run's coverage proof.
        # A manifest without it is legacy and never support-eligible.
        "completeness": dict(completeness) if completeness is not None else None,
        "scope_statement": _SCOPE_STATEMENT,
        "limitations": list(RUN_LIMITATIONS),
    }
    validate_run_manifest(manifest)
    return manifest


# S20: the validator must enforce the shipped contract
# (src/textforensics/schemas/probe-run.schema.json), not a weaker
# subset of it. These lists mirror the schema's ``required`` and
# ``properties`` (and the thresholds object's); a test pins them
# against the schema file so the two cannot drift apart silently.
_PROBE_RUN_REQUIRED_FIELDS = (
    "schema",
    "run_id",
    "run_at_utc",
    "scope",
    "corpus_version",
    "corpus_fingerprint",
    "detector_id",
    "detector_version",
    "code_sha",
    "baseline_run_id",
    "is_baseline",
    "previous_run_id",
    "alpha_per_run",
    "thresholds",
    "metrics",
    "alerts",
    "breaches",
    "demotions_applied",
    "demotions_cleared",
    "watches",
    "gaps",
    "scope_statement",
    "limitations",
)
_PROBE_RUN_KNOWN_FIELDS = frozenset(
    _PROBE_RUN_REQUIRED_FIELDS
    + (
        "corpus_manifest_sha256",
        "provider_metadata",
        "rebaselined_from",
        "score_series",
        "completeness",
    )
)
_THRESHOLD_REQUIRED_FIELDS = (
    "psi_action",
    "ks_effect_size",
    "ks_p_threshold",
    "flip_rate_tier2",
    "flip_rate_tier1",
    "ece_increase_tier2",
    "coverage_shortfall_tier2_pp",
    "coverage_shortfall_tier1_pp",
    "version_change_stale_days",
    "min_clean_full_runs_for_temporal_support",
    "min_slice_n",
    "min_slice_n_for_fpr_claim",
    "fpr_cap",
)
_THRESHOLD_INTEGER_FIELDS = {
    "min_clean_full_runs_for_temporal_support": 1,
    "min_slice_n": 1,
    "min_slice_n_for_fpr_claim": 1,
    "version_change_stale_days": 0,
}
# A run_id becomes a filename (``run-<run_id>.json``): it must be a
# safe basename, never a path.
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def _require_finite_json(value: Any, field_name: str) -> None:
    """Reject NaN/Infinity anywhere in a manifest (S20).

    JSON text may spell them ``NaN``/``Infinity`` and Python's
    ``json`` module accepts those spellings, so a strict validator
    must walk the value instead of trusting the parser.
    """
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProbeRunError(f"run manifest {field_name} must be finite.")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _require_finite_json(item, f"{field_name}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _require_finite_json(item, f"{field_name}[{index}]")


def _require_finite_number(value: Any, field_name: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ProbeRunError(f"run manifest {field_name} must be a number.")
    if not math.isfinite(value):
        raise ProbeRunError(f"run manifest {field_name} must be finite.")
    return float(value)


def _parse_run_at_utc(value: Any) -> datetime:
    """Parse ``run_at_utc`` as a UTC timestamp (S20).

    Naive timestamps and non-UTC offsets are rejected: chronological
    ordering must come from parsed UTC instants, never from
    arbitrary ISO strings.
    """
    if not isinstance(value, str):
        raise ProbeRunError("run manifest run_at_utc must be an ISO-8601 UTC string.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ProbeRunError(
            f"run manifest run_at_utc is not a valid timestamp: {value!r}."
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProbeRunError("run manifest run_at_utc must carry a UTC offset.")
    if parsed.utcoffset() != timedelta(0):
        raise ProbeRunError("run manifest run_at_utc must be a UTC timestamp.")
    return parsed.astimezone(UTC)


def _run_at_sort_key(run: Mapping[str, Any]) -> datetime:
    """Best-effort chronological key for history ordering (S20).

    Validated histories always parse; an unparseable entry sorts
    first instead of breaking the sort.
    """
    try:
        return _parse_run_at_utc(run.get("run_at_utc"))
    except ProbeRunError:
        return datetime.min.replace(tzinfo=UTC)


def validate_run_manifest(manifest: Mapping[str, Any]) -> None:
    """Fail-closed validation of a probe-run manifest.

    Enforces the shipped ``textforensics.probe-run/v1`` schema:
    every required field present, no unknown fields, finite values
    throughout, UTC run times, safe run IDs, complete alert and
    threshold objects, and — where the manifest states them —
    metric totals and linkage consistent with the score series.
    """
    if not isinstance(manifest, Mapping):
        raise ProbeRunError("run manifest must be an object.")
    if manifest.get("schema") != PROBE_RUN_SCHEMA:
        raise ProbeRunError(f"unsupported probe run schema: {manifest.get('schema')!r}.")
    _require_finite_json(manifest, "manifest")
    unknown = sorted(set(manifest) - _PROBE_RUN_KNOWN_FIELDS)
    if unknown:
        raise ProbeRunError(f"run manifest has unknown fields: {', '.join(unknown)}.")
    for field in _PROBE_RUN_REQUIRED_FIELDS:
        if field not in manifest:
            raise ProbeRunError(f"run manifest is missing required field: {field}.")
    run_id = manifest.get("run_id")
    _require_nonempty_string(run_id, "run manifest run_id")
    if not _RUN_ID_PATTERN.match(str(run_id)):
        raise ProbeRunError(f"run manifest run_id must be a safe basename: {run_id!r}.")
    _parse_run_at_utc(manifest.get("run_at_utc"))
    for field in (
        "corpus_version",
        "detector_id",
        "detector_version",
    ):
        _require_nonempty_string(manifest.get(field), f"run manifest {field}")
    _require_nonempty_string(manifest.get("code_sha"), "run manifest code_sha")
    if manifest.get("scope") not in RUN_SCOPES:
        raise ProbeRunError(f"run manifest scope must be one of {RUN_SCOPES}.")
    _require_hex64(manifest.get("corpus_fingerprint"), "corpus_fingerprint")
    if manifest.get("corpus_manifest_sha256") is not None:
        _require_hex64(manifest.get("corpus_manifest_sha256"), "corpus_manifest_sha256")
    if not isinstance(manifest.get("is_baseline"), bool):
        raise ProbeRunError("run manifest is_baseline must be a boolean.")
    for field in ("previous_run_id", "baseline_run_id", "rebaselined_from"):
        link = manifest.get(field)
        if link is not None:
            _require_nonempty_string(link, f"run manifest {field}")
    alpha = _require_finite_number(manifest.get("alpha_per_run"), "alpha_per_run")
    if not 0.0 < alpha <= 1.0:
        raise ProbeRunError("run manifest alpha_per_run must be in (0, 1].")
    thresholds = manifest.get("thresholds")
    if not isinstance(thresholds, Mapping):
        raise ProbeRunError("run manifest thresholds must be an object.")
    for field in _THRESHOLD_REQUIRED_FIELDS:
        if field not in thresholds:
            raise ProbeRunError(f"run manifest thresholds is missing: {field}.")
    unknown_thresholds = sorted(set(thresholds) - set(_THRESHOLD_REQUIRED_FIELDS))
    if unknown_thresholds:
        raise ProbeRunError(
            f"run manifest thresholds has unknown fields: {', '.join(unknown_thresholds)}."
        )
    for field, value in thresholds.items():
        _require_finite_number(value, f"thresholds.{field}")
    for field, minimum in _THRESHOLD_INTEGER_FIELDS.items():
        value = thresholds[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise ProbeRunError(f"run manifest thresholds.{field} must be an integer >= {minimum}.")
    fpr_cap = thresholds["fpr_cap"]
    if not 0.0 <= fpr_cap <= 1.0:
        raise ProbeRunError("run manifest thresholds.fpr_cap must be in [0, 1].")
    if not isinstance(manifest.get("metrics"), Mapping):
        raise ProbeRunError("run manifest metrics must be an object.")
    # S10: a non-finite number anywhere in metrics (a NaN/±Infinity
    # that slipped past construction) must be rejected, not stored as
    # a fabricated metric.
    try:
        reject_nonfinite_value(manifest.get("metrics"), "metrics")
    except ValueError as exc:
        raise ProbeRunError(str(exc)) from exc
    completeness = manifest.get("completeness")
    if completeness is not None:
        if not isinstance(completeness, Mapping):
            raise ProbeRunError("run manifest completeness must be an object or null.")
        _validate_completeness(completeness)
    if not isinstance(manifest.get("alerts"), list):
        raise ProbeRunError("run manifest alerts must be a list.")
    for alert in manifest["alerts"]:
        if not isinstance(alert, Mapping):
            raise ProbeRunError("run manifest alerts must be objects.")
        for field in ("tier", "rule", "slice", "action", "detail"):
            if field not in alert:
                raise ProbeRunError(f"run manifest alerts must carry {field}.")
        if alert.get("tier") not in (1, 2, 3):
            raise ProbeRunError("run manifest alerts must carry tier 1, 2, or 3.")
        if alert.get("action") not in ("demote", "investigate", "record"):
            raise ProbeRunError("run manifest alerts must carry a valid action.")
        for field in ("rule", "slice", "detail"):
            _require_nonempty_string(alert.get(field), f"run manifest alert {field}")
    if not isinstance(manifest.get("breaches"), list):
        raise ProbeRunError("run manifest breaches must be a list.")
    for breach in manifest["breaches"]:
        if not isinstance(breach, Mapping):
            raise ProbeRunError("run manifest breaches must be objects.")
    for field in ("demotions_applied", "demotions_cleared"):
        if not isinstance(manifest.get(field), Mapping):
            raise ProbeRunError(f"run manifest {field} must be an object.")
    if manifest.get("provider_metadata") is not None and not isinstance(
        manifest.get("provider_metadata"), Mapping
    ):
        raise ProbeRunError("run manifest provider_metadata must be an object.")
    for field in ("watches", "gaps", "limitations"):
        values = manifest.get(field)
        if not isinstance(values, list):
            raise ProbeRunError(f"run manifest {field} must be a list.")
    for field in ("gaps", "limitations"):
        for item in manifest[field]:
            if not isinstance(item, str):
                raise ProbeRunError(f"run manifest {field} must contain strings.")
    score_series = manifest.get("score_series")
    if score_series is not None:
        if not isinstance(score_series, Mapping):
            raise ProbeRunError("run manifest score_series must be an object.")
        for item_id, entry in score_series.items():
            if not isinstance(entry, Mapping):
                raise ProbeRunError(f"score_series entry for {item_id!r} must be an object.")
            unknown_entry = sorted(
                set(entry)
                - {
                    "score",
                    "verdict",
                    "calibrated_ai_probability",
                    "calibration_id",
                    "native_score_direction",
                    "score_range",
                }
            )
            if unknown_entry:
                raise ProbeRunError(
                    f"score_series entry for {item_id!r} has unknown fields: "
                    f"{', '.join(unknown_entry)}."
                )
            direction = entry.get("native_score_direction")
            if direction is not None:
                try:
                    normalize_score_direction(direction)
                except ValueError:
                    raise ProbeRunError(
                        f"score_series entry for {item_id!r} has an unknown "
                        f"native_score_direction: {direction!r}."
                    ) from None
            score_range = entry.get("score_range")
            if score_range is not None and (
                not isinstance(score_range, (list, tuple))
                or len(score_range) != 2
                or any(
                    not isinstance(endpoint, (int, float))
                    or isinstance(endpoint, bool)
                    or not math.isfinite(endpoint)
                    for endpoint in score_range
                )
                or not score_range[0] < score_range[1]
            ):
                raise ProbeRunError(
                    f"score_series entry for {item_id!r} score_range must be [lo, hi] with lo < hi."
                )
            for field in ("score", "verdict"):
                if field not in entry:
                    raise ProbeRunError(f"score_series entry for {item_id!r} must carry {field}.")
            _require_finite_number(entry.get("score"), f"score_series {item_id!r} score")
            if entry.get("verdict") not in ("human_like", "ai_like", "abstain"):
                raise ProbeRunError(f"score_series entry for {item_id!r} needs a valid verdict.")
            calibrated = entry.get("calibrated_ai_probability")
            if calibrated is not None:
                probability = _require_finite_number(
                    calibrated, f"score_series {item_id!r} calibrated_ai_probability"
                )
                if not 0.0 <= probability <= 1.0:
                    raise ProbeRunError(
                        f"score_series entry for {item_id!r} calibrated_ai_probability "
                        "must be in [0, 1]."
                    )
            calibration_id = entry.get("calibration_id")
            if calibration_id is not None and not isinstance(calibration_id, str):
                raise ProbeRunError(
                    f"score_series entry for {item_id!r} calibration_id must be a string."
                )
    if manifest.get("scope_statement") != _SCOPE_STATEMENT:
        raise ProbeRunError("run manifest scope statement must match the canonical text.")
    # Linkage: a run cannot be its own predecessor or rebaselining
    # source. A baseline run's baseline_run_id is itself by
    # construction; any other run's baseline link must differ.
    for field in ("previous_run_id", "rebaselined_from"):
        if manifest.get(field) is not None and manifest[field] == run_id:
            raise ProbeRunError(f"run manifest {field} must not equal run_id.")
    baseline_link = manifest.get("baseline_run_id")
    if baseline_link is not None and baseline_link == run_id and not manifest.get("is_baseline"):
        raise ProbeRunError(
            "run manifest baseline_run_id must not equal run_id for a non-baseline run."
        )
    # Metric totals against the score series, where the manifest
    # states them: the overall n must be the series length, slice
    # ns must sum to it, the metrics detector must be this run's
    # detector, and the Holm alpha must be this run's alpha.
    metrics = manifest["metrics"]
    metrics_detector = metrics.get("detector_id")
    if metrics_detector is not None and metrics_detector != manifest.get("detector_id"):
        raise ProbeRunError("run manifest metrics detector_id does not match the run detector_id.")
    holm = metrics.get("holm")
    if isinstance(holm, Mapping) and "alpha_per_run" in holm:
        holm_alpha = _require_finite_number(holm["alpha_per_run"], "metrics.holm.alpha_per_run")
        if holm_alpha != alpha:
            raise ProbeRunError(
                "run manifest metrics holm alpha_per_run does not match alpha_per_run."
            )
    if score_series is not None:
        overall = metrics.get("overall")
        overall_n: int | None = None
        if isinstance(overall, Mapping) and "n" in overall:
            overall_n = overall["n"]
            if not isinstance(overall_n, int) or isinstance(overall_n, bool) or overall_n < 0:
                raise ProbeRunError(
                    "run manifest metrics overall n must be a non-negative integer."
                )
            if overall_n != len(score_series):
                raise ProbeRunError(
                    "run manifest metrics overall n does not match the score_series length."
                )
        slices = metrics.get("slices")
        if isinstance(slices, Mapping):
            slice_total = 0
            for slice_name, slice_metrics in slices.items():
                if not isinstance(slice_metrics, Mapping) or "n" not in slice_metrics:
                    continue
                slice_n = slice_metrics["n"]
                if not isinstance(slice_n, int) or isinstance(slice_n, bool) or slice_n < 0:
                    raise ProbeRunError(
                        f"run manifest metrics slice {slice_name!r} n must be a "
                        "non-negative integer."
                    )
                slice_total += slice_n
            if overall_n is not None and slice_total != overall_n:
                raise ProbeRunError("run manifest metrics slice ns do not sum to the overall n.")


def save_run(run: Mapping[str, Any], directory: str | Path) -> Path:
    """Atomically write one run manifest to the run-history directory.

    Append-only (S20): a run_id is an immutable identity. Saving a
    different manifest under an existing run_id is refused — the old
    file is left untouched. Saving the exact same bytes again is
    idempotent. Concurrent duplicate saves are safe: the file is
    published with an exclusive hard link, so at most one writer can
    claim the name.
    """
    validate_run_manifest(run)
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"run-{run['run_id']}.json"
    rendered = json.dumps(run, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    rendered_bytes = rendered.encode("utf-8")
    temp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target_dir,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = handle.name
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp_path, target)
        except FileExistsError:
            try:
                existing = target.read_bytes()
            except OSError as exc:
                raise ProbeRunError(
                    f"run {run['run_id']!r} already exists in {target_dir} "
                    "and cannot be read to compare; refusing to overwrite."
                ) from exc
            if existing == rendered_bytes:
                return target
            raise ProbeRunError(
                f"run {run['run_id']!r} already exists in {target_dir} with "
                "different content; run history is append-only and a run "
                "is never overwritten. Record a correction as a new run."
            ) from None
        temp_path = None
    finally:
        if temp_path is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp_path)
    return target


def load_run(path: str | Path) -> dict[str, Any]:
    """Load and validate one run manifest file."""
    # S10: strict parse — a NaN/Infinity token or an overflowing
    # literal (1e999) in a run file is rejected, not loaded.
    try:
        data = strict_json_loads(Path(path).read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ProbeRunError(str(exc)) from exc
    validate_run_manifest(data)
    return dict(data)


def load_run_history(directory: str | Path) -> list[dict[str, Any]]:
    """Load all run manifests in a directory, oldest first.

    Ordering is by parsed UTC instant, not by raw ISO string (S20).
    A duplicate run_id is a corrupt history — run identities are
    immutable and append-only — and fails closed.
    """
    target_dir = Path(directory)
    if not target_dir.is_dir():
        return []
    runs = [load_run(path) for path in sorted(target_dir.glob("run-*.json"))]
    seen: set[str] = set()
    for run in runs:
        run_id = run.get("run_id")
        if run_id in seen:
            raise ProbeRunError(f"duplicate run_id {run_id!r} in run history {target_dir}.")
        seen.add(run_id)
    runs.sort(key=_run_at_sort_key)
    return runs


def perform_probe_run(
    *,
    manifest: Mapping[str, Any],
    texts: Mapping[str, str],
    holdback_loader: Any,
    detector: Any,
    scope: str = "full",
    runs_dir: str | Path | None = None,
    registry_path: str | Path | None = None,
    corpus_manifest_sha256: str | None = None,
    dry_run: bool = False,
    allow_remote: bool = False,
    primitives: Any = None,
    run_at: datetime | None = None,
    execution_policy: ExecutionPolicy | None = None,
    cancellation: CancellationToken | None = None,
) -> dict[str, Any]:
    """Run one U3 probe run end to end and return its run manifest.

    ``manifest`` is a ``textforensics.probe-corpus/v1`` manifest dict
    (``version``, ``items_sha256``, ``items`` with ``item_id`` /
    ``slice`` / ``content_sha256``). ``texts`` maps item_id -> text.
    ``holdback_loader`` is a zero-argument callable returning the
    holdback mapping item_id -> entry dict with a ``label`` key
    (0 human / 1 machine / None mixed-origin). It is invoked **only
    after scoring completes**: the labels must never influence which
    items are scored or how they are scored. ``detector`` is a
    detector object (``detector_id`` / ``detector_version``) from the
    detector registry. ``registry_path`` is the U1 validation
    registry; it is required whenever a Tier-1 alert fires (demotion
    writes there) unless ``dry_run`` is set.

    ``execution_policy`` / ``cancellation`` are the W1 stop channel:
    the canonical emergency stop (and cooperative cancellation) is
    checked before scoring, after scoring, and before any registry
    mutation or save. A stop raises :class:`EmergencyStopError` —
    terminal, never converted into an ordinary failure or a
    clean-run record — and nothing is demoted or saved.

    The run is saved to ``runs_dir`` (default
    :func:`default_probe_runs_dir`) unless ``dry_run``. A Tier-1
    alert applies demotions to the registry; a clean, genuinely
    complete full run clears U3 demotions for this detector — an
    incomplete run never clears them, never becomes a baseline, and
    never advances temporal support (audit W4/S01). The returned
    manifest is the exact dict that was saved (or would have been
    saved, dry-run).
    """
    from .execution_policy import assert_execution_allowed
    from .observatory import DriftObservatory

    # S20 handoff (W2): the stop gate runs before any execution.
    # No policy supplied means the default local-only policy.
    assert_execution_allowed(execution_policy, cancellation=cancellation)

    if scope not in RUN_SCOPES:
        raise ProbeRunError(f"scope must be one of {RUN_SCOPES}, got {scope!r}.")
    if not callable(holdback_loader):
        raise ProbeRunError("holdback_loader must be a callable.")
    detector_id = _require_nonempty_string(
        getattr(detector, "detector_id", None), "detector.detector_id"
    )
    detector_version = _require_nonempty_string(
        getattr(detector, "detector_version", None), "detector.detector_version"
    )
    corpus_version = _require_nonempty_string(manifest.get("version"), "manifest version")
    corpus_fingerprint = _require_hex64(manifest.get("items_sha256"), "manifest items_sha256")
    items = manifest.get("items")
    if not isinstance(items, list) or not items:
        raise ProbeRunError("probe corpus manifest has no items.")
    run_at_dt = run_at or datetime.now(UTC)
    run_at_utc = run_at_dt.isoformat().replace("+00:00", "Z")
    if not run_at_utc.endswith("Z"):
        run_at_utc = run_at_dt.astimezone(UTC).isoformat().replace("+00:00", "Z")

    # Scope-filter the corpus before scoring: a monthly run scores
    # only its slices, and unscored slices never enter the metrics.
    scope_slices: set[str] | None = None
    if scope == "monthly-attacked":
        scope_slices = set(ATTACKED_SLICES)
    elif scope == "monthly-current-generator":
        scope_slices = {"ai-current-generator"}
    scoped_items: list[Mapping[str, Any]] = []
    slices: dict[str, str] = {}
    for item in items:
        if not isinstance(item, Mapping):
            raise ProbeRunError("probe corpus manifest items must be objects.")
        item_id = _require_nonempty_string(item.get("item_id"), "item item_id")
        slice_name = _require_nonempty_string(item.get("slice"), "item slice")
        content_sha256 = _require_hex64(item.get("content_sha256"), "item content_sha256")
        if scope_slices is not None and slice_name not in scope_slices:
            continue
        if item_id in slices:
            raise ProbeRunError(f"probe corpus manifest has duplicate item_id: {item_id!r}.")
        text = texts.get(item_id)
        if text is None:
            raise ProbeRunError(f"probe corpus has no text for item {item_id!r}.")
        scoped_items.append(
            {
                "id": item_id,
                "text_sha256": content_sha256,
                "text": text,
                "metadata": {"slice": slice_name},
            }
        )
        slices[item_id] = slice_name
    if not scoped_items:
        raise ProbeRunError(f"scope {scope!r} selects no corpus items.")

    # Score first. Labels are loaded only after this returns. A stop
    # raised here (EmergencyStopError via the W1 execution channel)
    # propagates: the run is never recorded, demoted, cleared, or
    # baselined (audit W4/S08).
    observatory = DriftObservatory(
        corpus={"schema": "textforensics.drift-corpus/v1", "samples": scoped_items}
    )
    snapshot = observatory.take_snapshot(
        detectors=[detector],
        allow_remote=bool(allow_remote),
        execution_policy=execution_policy,
        cancellation=cancellation,
    )
    # A stop that activated during scoring must abort before labels
    # are read, demotions applied, or anything saved.
    assert_execution_allowed(execution_policy, cancellation=cancellation)
    current_records = snapshot.get("records") or []
    if not current_records:
        raise ProbeRunError("probe run scored no records.")
    provider_metadata: dict[str, Any] = {}
    for record in current_records:
        provider_version = record.get("provider_version")
        if provider_version is not None:
            provider_metadata[str(record.get("detector_id", detector_id))] = provider_version

    # S01: the completeness accounting is an invariant against the
    # scope-selected item set. The observatory already collects
    # failures; they are retained here instead of discarded.
    completeness = compute_run_completeness(
        selected_item_ids=[item["id"] for item in scoped_items],
        records=current_records,
        failures=snapshot.get("failures") or [],
    )
    support_eligible = bool(completeness["support_eligible"])

    # Labels only now, after scoring.
    holdback = holdback_loader()
    if not isinstance(holdback, Mapping):
        raise ProbeRunError("holdback_loader must return a mapping.")
    labels: dict[str, int | None] = {}
    for item_id in slices:
        entry = holdback.get(item_id)
        if entry is None:
            raise ProbeRunError(
                f"holdback has no entry for scored item {item_id!r}; labels must "
                "cover every scored item."
            )
        if not isinstance(entry, Mapping) or "label" not in entry:
            raise ProbeRunError(f"holdback entry for {item_id!r} has no label.")
        label = entry["label"]
        if label is not None and label not in (0, 1):
            raise ProbeRunError(
                f"holdback label for {item_id!r} must be 0, 1, or None, got {label!r}."
            )
        labels[item_id] = label

    directory = (
        Path(runs_dir)
        if runs_dir is not None
        else default_probe_runs_dir(corpus_version=corpus_version)
    )
    history = load_run_history(directory) if directory.is_dir() else []
    detector_history = [r for r in history if r.get("detector_id") == detector_id]
    previous = detector_history[-1] if detector_history else None
    baseline = resolve_baseline(
        history,
        detector_id=detector_id,
        detector_version=detector_version,
        corpus_fingerprint=corpus_fingerprint,
        provider_metadata=provider_metadata,
    )
    version_changed = (
        previous is not None
        and previous.get("detector_version") is not None
        and previous.get("detector_version") != detector_version
    )
    # S06: a provider/model identity change is an evidence-epoch
    # change exactly like a detector-version change: it re-baselines.
    provider_changed = previous is not None and _provider_identity(previous) != provider_metadata
    identity_changed = version_changed or provider_changed
    # Only a genuinely complete full-scope run can be (or
    # re-establish) the baseline (S01). A monthly partial run with no
    # baseline yet simply has none, and an incomplete run never becomes
    # one — the next complete run re-baselines instead.
    is_baseline = baseline is None and scope in ("full", "event-driven") and support_eligible
    rebaselined_from: str | None = None
    if identity_changed and scope in ("full", "event-driven"):
        if support_eligible:
            is_baseline = True
            rebaselined_from = (
                baseline.get("run_id")
                if baseline
                else (previous.get("run_id") if previous else None)
            )
        baseline = None

    metrics = compute_run_metrics(
        current_records=current_records,
        baseline_records=_records_from_series(baseline.get("score_series") or {})
        if baseline
        else None,
        previous_records=_records_from_series(previous.get("score_series") or {})
        if previous
        else None,
        labels=labels,
        slices=slices,
        detector_id=detector_id,
        primitives=primitives,
        now=run_at_dt,
    )
    # The run manifest stores metrics plus the per-item score series
    # (numbers + IDs, never raw text); the raw snapshot records are
    # not embedded. The next run rebuilds baseline/previous records
    # from the stored series, which carries exactly the fields the
    # metrics read (score, verdict, calibrated probability,
    # calibration id).
    tier_result = evaluate_tiers(
        metrics=metrics,
        previous_breaches=previous.get("breaches") if previous else None,
        previous_run_at=previous.get("run_at_utc") if previous else None,
        detector_version=detector_version,
        previous_detector_version=previous.get("detector_version") if previous else None,
        previous_provider_metadata=previous.get("provider_metadata") if previous else None,
        provider_metadata=provider_metadata,
        run_at=run_at_utc,
    )
    alerts = tier_result["alerts"]
    breaches = tier_result["breaches"]
    tier1 = [a for a in alerts if a.get("tier") == 1]
    watches = [
        {
            "rule": a.get("rule"),
            "slice": a.get("slice"),
            "detail": a.get("detail"),
            "run_id": None,  # filled below, after the run id exists
        }
        for a in alerts
        if a.get("tier") == 2
    ]

    run_id = uuid.uuid4().hex
    for watch in watches:
        watch["run_id"] = run_id
    # A stop that activated anywhere up to here must abort before
    # any durable mutation: no demotion, no clearing, no save.
    assert_execution_allowed(execution_policy, cancellation=cancellation)
    demotions_applied: dict[str, Any] = {}
    demotions_cleared: dict[str, Any] = {}
    if not dry_run:
        if tier1:
            if registry_path is None:
                raise ProbeRunError(
                    "Tier-1 alert fired but no validation registry path was "
                    "given; refusing to demote without a registry."
                )
            demotions_applied = apply_demotions(
                registry_path=registry_path,
                detector_id=detector_id,
                run_id=run_id,
                alerts=tier1,
            )
        elif scope == "full" and registry_path is not None:
            # S01: only a genuinely complete clean full run clears U3
            # demotions. An incomplete run keeps every demotion and
            # says so in the gap, with the exact coverage shortfall.
            if support_eligible:
                demotions_cleared = clear_demotions(
                    registry_path=registry_path,
                    detector_id=detector_id,
                    run_id=run_id,
                )
            else:
                demotions_cleared = {
                    "cleared_record_ids": [],
                    "reason": None,
                    "gap": (
                        f"run is incomplete: {completeness['succeeded']} of "
                        f"{completeness['selected']} selected items scored "
                        f"successfully ({completeness['failed']} failed, "
                        f"{completeness['abstained']} abstained, "
                        f"{len(completeness['missing_item_ids'])} missing); "
                        "demotions are retained."
                    ),
                }

    # S21: a withheld baseline aggregate is missing-calibration
    # evidence, not a silent gap — surface it as a manifest gap line
    # so the run record itself says the baseline was partial.
    gaps: list[str] = []
    overall_missing = metrics.get("overall", {}).get("calibration", {}).get("missing_calibration")
    if isinstance(overall_missing, Mapping) and overall_missing.get("reason"):
        gaps.append(f"Missing calibration evidence: {overall_missing['reason']}")
    for slice_name, slice_result in (metrics.get("slices") or {}).items():
        slice_missing = (slice_result or {}).get("calibration", {}).get("missing_calibration")
        if (
            isinstance(slice_missing, Mapping)
            and slice_missing.get("reason")
            and slice_missing is not overall_missing
        ):
            gaps.append(
                f"Missing calibration evidence on slice {slice_name!r}: {slice_missing['reason']}"
            )

    manifest_out = build_run_manifest(
        run_id=run_id,
        run_at_utc=run_at_utc,
        scope=scope,
        corpus_version=corpus_version,
        corpus_fingerprint=corpus_fingerprint,
        corpus_manifest_sha256=corpus_manifest_sha256,
        detector_id=detector_id,
        detector_version=detector_version,
        provider_metadata=provider_metadata,
        code_sha=git_code_sha(),
        baseline_run_id=baseline.get("run_id") if baseline else (run_id if is_baseline else None),
        is_baseline=is_baseline,
        rebaselined_from=rebaselined_from,
        previous_run_id=previous.get("run_id") if previous else None,
        metrics=metrics,
        alerts=alerts,
        breaches=breaches,
        demotions_applied=demotions_applied,
        demotions_cleared=demotions_cleared,
        watches=watches,
        gaps=gaps,
        score_series=_series_from_records(current_records),
        completeness=completeness,
    )
    if not dry_run:
        save_run(manifest_out, directory)
    return manifest_out
