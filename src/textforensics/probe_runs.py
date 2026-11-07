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
* Baseline management: the first run after a corpus freeze is the
  baseline; a detector/provider version change re-baselines explicitly
  (the old baseline is retained in history, never silently replaced).
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
  detector/provider version change with no probe run within 7 days.
* Never claim drift from one sample or one run. Slices below n=50
  carry no drift signal; human-FPR claims need n>=100 per slice;
  a single run never demotes.
* An alert may demote a Trust Map tier and require human review, but
  must never silently change a verdict on a user's text. Demotion
  marks U1 registry records ``stale`` (via ``limits.demoted_by``);
  the Trust Map then shows ``stale`` for the affected dimensions and
  the operator withholds binary verdicts on the affected slices until
  a full re-run passes. No verdict is ever rewritten by an alert.

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
import os
import subprocess
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .datasets import default_cache_dir
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
    "load_probe_metrics",
    "compute_run_metrics",
    "evaluate_tiers",
    "apply_demotions",
    "clear_demotions",
    "resolve_baseline",
    "summarize_longitudinal",
    "build_run_manifest",
    "validate_run_manifest",
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
FLIP_RATE_TIER1 = 0.05  # >5% flips -> demote.
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
    "A single run never demotes; Tier 2 requires a breach on 2 consecutive runs.",
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

    The real module ships on the ``u3-corpus`` branch. Until it merges,
    callers that need metric computation must inject a ``primitives``
    object exposing the same function names (tests do this); otherwise
    :class:`ProbeMetricsUnavailable` is raised with a clear message.
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
    except ImportError as exc:  # pragma: no cover - branch not merged yet
        raise ProbeMetricsUnavailable(
            "textforensics.probe_metrics is not available: the u3-corpus "
            "branch has not merged. Metric computation needs the probe "
            "corpus module; alert/demotion logic does not."
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


def _score(record: Mapping[str, Any]) -> float | None:
    value = record.get("score")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProbeRunError(f"snapshot record score must be a number, got {value!r}.")
    return float(value)


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


def _slice_metrics(
    *,
    item_ids: list[str],
    current: dict[str, Mapping[str, Any]],
    baseline: dict[str, Mapping[str, Any]] | None,
    previous: dict[str, Mapping[str, Any]] | None,
    labels: Mapping[str, int],
    primitives: Any,
    is_human_slice: bool,
    is_attacked_slice: bool,
    human_scores_all: list[float],
    human_labels_all: list[int],
    calibration_created_at: Mapping[str, str] | None,
    now: datetime,
) -> dict[str, Any]:
    """The §7.6 metrics for one slice (or the overall population)."""
    present = [item for item in item_ids if item in current]
    n = len(present)
    scores = [_score(current[item]) for item in present]
    scores = [s for s in scores if s is not None]
    verdicts = [_verdict(current[item]) for item in present]
    item_labels = [int(labels[item]) for item in present]
    n_human = sum(1 for y in item_labels if y == 0)
    n_ai = sum(1 for y in item_labels if y == 1)

    # Metric 1: score-distribution shift vs the baseline run (KS + PSI).
    score_shift: dict[str, Any] = {
        "ks_statistic": None,
        "ks_pvalue": None,
        "ks_pvalue_holm_adjusted": None,
        "psi": None,
        "status": "unavailable",
        "reason": "no baseline run to compare against",
    }
    if baseline is not None:
        baseline_scores = [
            s for item in present if item in baseline and (s := _score(baseline[item])) is not None
        ]
        if scores and baseline_scores:
            ks = primitives.ks_statistic(baseline_scores, scores)
            ks_p = primitives.ks_pvalue(ks, len(baseline_scores), len(scores))
            psi_value = primitives.psi(baseline_scores, scores)
            score_shift = {
                "ks_statistic": _round(ks),
                "ks_pvalue": _round(ks_p),
                "ks_pvalue_holm_adjusted": None,  # Filled in by the caller (family = slices).
                "psi": _round(psi_value),
                "status": "breach" if psi_value > PSI_ACTION else "stable",
                "reason": ("PSI > 0.2" if psi_value > PSI_ACTION else "PSI <= 0.2"),
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
            }

    # Metric 3: calibration drift — ECE + Brier where calibrated
    # probabilities are emitted; conformal coverage is unavailable
    # (no conformal machinery exists in the repo; U5 is v1.1).
    probs = [_calibrated_probability(current[item]) for item in present]
    calibration: dict[str, Any] = {
        "ece": None,
        "brier": None,
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
        # > 0.05): same items, baseline run's calibrated probabilities.
        if baseline is not None:
            baseline_probs = [_calibrated_probability(baseline[item]) for item in present]
            if baseline_probs and all(p is not None for p in baseline_probs):
                calibration["baseline_ece"] = _round(
                    primitives.ece([float(p) for p in baseline_probs], item_labels)
                )
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
            for item, y in zip(present, item_labels, strict=True)
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
    attacked_tpr: dict[str, Any] | None = None
    if is_attacked_slice:
        machine_scores = [
            float(s)
            for item, y in zip(present, item_labels, strict=True)
            if y == 1 and (s := _score(current[item])) is not None
        ]
        if machine_scores and human_scores_all:
            combined_scores = human_scores_all + machine_scores
            combined_labels = human_labels_all + [1] * len(machine_scores)
            result = primitives.tpr_at_fpr(combined_scores, combined_labels, target_fpr=0.01)
            attacked_tpr = {
                "tpr_at_1pct_fpr": _round(result["tpr"]),
                "achieved_fpr": _round(result["achieved_fpr"]),
                "threshold": _round(result["threshold"]),
                "n_machine": len(machine_scores),
                "n_human_reference": len(human_scores_all),
            }
        else:
            attacked_tpr = {
                "tpr_at_1pct_fpr": None,
                "achieved_fpr": None,
                "threshold": None,
                "n_machine": len(machine_scores),
                "n_human_reference": len(human_scores_all),
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
        "drift_signal_allowed": n >= MIN_SLICE_N,
        "score_shift": score_shift,
        "flips": flips,
        "calibration": calibration,
        "human_fpr": human_fpr,
        "attacked_tpr": attacked_tpr,
        "abstention_rate": _round(abstention["rate"]) if abstention["rate"] is not None else None,
        "abstained": abstention["abstained"],
    }


def compute_run_metrics(
    *,
    current_records: Sequence[Mapping[str, Any]],
    baseline_records: Sequence[Mapping[str, Any]] | None,
    previous_records: Sequence[Mapping[str, Any]] | None,
    labels: Mapping[str, int],
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
    run). ``labels`` maps item_id -> 0 (human) / 1 (machine) and is
    read from the holdback file only after scoring. ``slices`` maps
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

    for item_id, label in labels.items():
        if label not in (0, 1):
            raise ProbeRunError(f"label for {item_id!r} must be 0 or 1, got {label!r}.")
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

    # --- Verdict flips (Tier 2 at >1% with Wilson CI excluding 0; Tier 1 at >5%).
    for slice_name in sorted(slices):
        flips = (slices[slice_name] or {}).get("flips")
        if not flips:
            continue
        rate = flips["flip_rate"]
        ci_lo, ci_hi = flips["flip_rate_ci"]
        if rate is not None and rate > FLIP_RATE_TIER1:
            demote = True
            _alert(
                tier=1,
                rule=RULE_FLIP_RATE,
                slice_name=slice_name,
                statistic={
                    "flip_rate": rate,
                    "flip_rate_ci": [ci_lo, ci_hi],
                    "flips": flips["flips"],
                    "n": flips["n"],
                    "human_to_ai": flips["human_to_ai"],
                    "ai_to_human": flips["ai_to_human"],
                },
                threshold=FLIP_RATE_TIER1,
                consecutive_runs=1,
                action="demote",
                detail=(
                    f"Flip rate {rate} > {FLIP_RATE_TIER1} on slice {slice_name!r} "
                    f"({flips['human_to_ai']} human->AI, {flips['ai_to_human']} AI->human). "
                    "Demote the detector's U1 records to stale; withhold binary verdicts until a full re-run passes."
                ),
            )
        elif rate is not None and rate > FLIP_RATE_TIER2 and ci_lo > 0:
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
    overall_flips = overall.get("flips")
    if overall_flips:
        rate = overall_flips["flip_rate"]
        ci_lo, _ = overall_flips["flip_rate_ci"]
        if rate is not None and rate > FLIP_RATE_TIER1:
            demote = True
            _alert(
                tier=1,
                rule=RULE_FLIP_RATE,
                slice_name="overall",
                statistic={
                    "flip_rate": rate,
                    "flip_rate_ci": overall_flips["flip_rate_ci"],
                    "flips": overall_flips["flips"],
                    "n": overall_flips["n"],
                },
                threshold=FLIP_RATE_TIER1,
                consecutive_runs=1,
                action="demote",
                detail=(
                    f"Overall flip rate {rate} > {FLIP_RATE_TIER1}. Demote the "
                    "detector's U1 records to stale; withhold binary verdicts until a full re-run passes."
                ),
            )
        elif rate is not None and rate > FLIP_RATE_TIER2 and ci_lo > 0:
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
    for slice_name in sorted(slices):
        calibration = (slices[slice_name] or {}).get("calibration") or {}
        ece = calibration.get("ece")
        baseline_ece = calibration.get("baseline_ece")
        if (
            ece is not None
            and baseline_ece is not None
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
                },
                threshold=ECE_INCREASE_TIER2,
                consecutive_runs=1,
                action="investigate",
                detail=(
                    f"ECE increased by {ece - baseline_ece} (>{ECE_INCREASE_TIER2}) on slice {slice_name!r}. Trust Map watch; human review required."
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
    if previous_detector_version is not None and previous_detector_version != detector_version:
        days_since_previous = None
        if previous_run_at is not None and run_at is not None:
            days_since_previous = (
                datetime.fromisoformat(run_at) - datetime.fromisoformat(previous_run_at)
            ).days
        if days_since_previous is None or days_since_previous > VERSION_CHANGE_STALE_DAYS:
            demote = True
            _alert(
                tier=1,
                rule=RULE_VERSION_CHANGE_NO_RUN,
                slice_name="overall",
                statistic={
                    "previous_detector_version": previous_detector_version,
                    "detector_version": detector_version,
                    "days_since_previous_run": days_since_previous,
                },
                threshold=VERSION_CHANGE_STALE_DAYS,
                consecutive_runs=1,
                action="demote",
                detail=(
                    f"Detector version changed {previous_detector_version!r} -> {detector_version!r} with no probe run within {VERSION_CHANGE_STALE_DAYS} days "
                    f"({days_since_previous} days since the previous run). Demote the detector's U1 records to stale until this run completes."
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
            demote = True
            _alert(
                tier=1,
                rule=RULE_VERSION_CHANGE_NO_RUN,
                slice_name="overall",
                statistic={
                    "provider_metadata_diff": provider_diff,
                    "days_since_previous_run": days_since_previous,
                },
                threshold=VERSION_CHANGE_STALE_DAYS,
                consecutive_runs=1,
                action="demote",
                detail=(
                    f"Provider metadata changed {provider_diff} with no probe run within {VERSION_CHANGE_STALE_DAYS} days "
                    f"({days_since_previous} days since the previous run). Demote the detector's U1 records to stale until this run completes."
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


def _demoted_record(record: ValidationRecord, *, reason: str) -> ValidationRecord:
    """Return a copy of ``record`` with ``limits.demoted_by`` set + re-signed.

    The stored record changes (a new signature is computed), so the
    registry id changes too. That is the point: demotion is a visible,
    auditable registry event, not a silent flag. The signature is
    computed from the unsigned dict first: ``ValidationRecord`` is a
    frozen dataclass whose ``__post_init__`` rejects an empty signature,
    so an intermediate ``signature=""`` record can never be built.
    """
    limits = dataclasses.replace(record.limits, demoted_by=reason)
    unsigned = record.to_dict()
    unsigned["limits"] = limits.to_dict()
    unsigned.pop("signature", None)
    return dataclasses.replace(record, limits=limits, signature=compute_signature(unsigned))


def _undemoted_record(record: ValidationRecord) -> ValidationRecord:
    unsigned = record.to_dict()
    unsigned["limits"] = dataclasses.replace(record.limits, demoted_by=None).to_dict()
    unsigned.pop("signature", None)
    return dataclasses.replace(
        record,
        limits=dataclasses.replace(record.limits, demoted_by=None),
        signature=compute_signature(unsigned),
    )


def apply_demotions(
    *,
    registry_path: str | Path,
    detector_id: str,
    run_id: str,
    alerts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Apply Tier-1 demotions to the U1 registry for ``detector_id``.

    For every Tier-1 alert in ``alerts``, every record for the detector
    gets ``limits.demoted_by`` set to a reason identifying the probe
    run and the rule. Demotion is per-detector in v1.0 (not per-slice):
    U1 records are regime-coarse, and a probe-corpus performance breach
    indicts the detector's measured performance generally. Per-slice
    demotion is a v1.1 refinement once records are slice-granular.
    The registry is rewritten atomically and reloaded to verify. When
    no record exists for the detector, nothing is demoted and the gap
    is reported (demotion needs a record to land on).
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

    Only records whose ``demoted_by`` names a U3 probe run are cleared;
    demotions from any other source are left untouched. The record is
    re-signed on clearing, like on demotion.
    """
    detector_id = _require_nonempty_string(detector_id, "detector_id")
    run_id = _require_nonempty_string(run_id, "run_id")
    registry = load_validation_registry(registry_path)
    cleared_ids: list[str] = []
    replaced: list[ValidationRecord] = []
    for record in registry.records:
        demoted_by = record.limits.demoted_by
        if (
            record.detector_id == detector_id
            and demoted_by is not None
            and demoted_by.startswith("U3 probe run ")
        ):
            replaced.append(_undemoted_record(record))
            cleared_ids.append(record.record_id)
        else:
            replaced.append(record)
    if not cleared_ids:
        return {"cleared_record_ids": [], "reason": None}
    updated = ValidationRegistry(replaced, created_at_utc=registry.created_at_utc)
    updated.save(registry_path)
    reloaded = load_validation_registry(registry_path)
    if sorted(r.record_id for r in reloaded.records) != sorted(
        r.record_id for r in updated.records
    ):
        raise ProbeRunError("registry reload after clearing demotions does not match.")
    return {
        "cleared_record_ids": sorted(cleared_ids),
        "reason": f"U3 probe run {run_id}: full re-run passed with no Tier-1 alert",
    }


# ---------------------------------------------------------------------------
# Baseline management + longitudinal summary
# ---------------------------------------------------------------------------


def resolve_baseline(
    history: Sequence[Mapping[str, Any]],
    *,
    detector_id: str,
    detector_version: str,
    corpus_fingerprint: str,
) -> Mapping[str, Any] | None:
    """Return the baseline run for this detector/version/corpus, if any.

    The baseline is the run flagged ``is_baseline`` for the same
    detector id, detector version, and corpus fingerprint. A version
    change has no baseline until the re-baseline run completes (the
    caller marks that run ``is_baseline`` with ``rebaselined_from``).
    """
    candidates = [
        run
        for run in history
        if run.get("detector_id") == detector_id
        and run.get("detector_version") == detector_version
        and run.get("corpus_fingerprint") == corpus_fingerprint
        and run.get("is_baseline") is True
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda r: str(r.get("run_at_utc", "")))[-1]


def summarize_longitudinal(
    history: Sequence[Mapping[str, Any]],
    *,
    detector_id: str,
    detector_version: str,
    corpus_fingerprint: str,
) -> dict[str, Any]:
    """Summarise U3 longitudinal evidence for one detector/version/corpus.

    Counts consecutive clean *full* runs (scope ``full``, no Tier-1 or
    Tier-2 alert) at the same detector version, most recent first. A
    run with any Tier-1/2 alert, or a different detector version, or a
    different corpus fingerprint, breaks the streak. Also reports the
    active watch (latest Tier-2 alert) and active demotions.
    """
    runs = sorted(
        (
            run
            for run in history
            if run.get("detector_id") == detector_id
            and run.get("detector_version") == detector_version
            and run.get("corpus_fingerprint") == corpus_fingerprint
        ),
        key=lambda r: str(r.get("run_at_utc", "")),
        reverse=True,
    )
    clean_run_ids: list[str] = []
    for run in runs:
        if run.get("scope") != "full":
            continue
        tiers = {a.get("tier") for a in run.get("alerts", [])}
        if tiers & {1, 2}:
            break
        clean_run_ids.append(str(run.get("run_id")))
    watch: dict[str, Any] | None = None
    for run in runs:
        tier2 = [a for a in run.get("alerts", []) if a.get("tier") == 2]
        if tier2:
            watch = {
                "run_id": str(run.get("run_id")),
                "run_at_utc": str(run.get("run_at_utc")),
                "alerts": tier2,
            }
            break
    return {
        "detector_id": detector_id,
        "detector_version": detector_version,
        "corpus_fingerprint": corpus_fingerprint,
        "consecutive_clean_full_runs": len(clean_run_ids),
        "clean_full_run_ids": clean_run_ids,
        "clean_full_runs_needed_for_temporal_support": MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT,
        "temporal_support": len(clean_run_ids) >= MIN_CLEAN_FULL_RUNS_FOR_TEMPORAL_SUPPORT,
        "watch": watch,
        "total_runs": len(runs),
        "last_run_at_utc": str(runs[0].get("run_at_utc")) if runs else None,
    }


# ---------------------------------------------------------------------------
# Run manifest: build / validate / store
# ---------------------------------------------------------------------------


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
        "scope_statement": _SCOPE_STATEMENT,
        "limitations": list(RUN_LIMITATIONS),
    }
    validate_run_manifest(manifest)
    return manifest


def validate_run_manifest(manifest: Mapping[str, Any]) -> None:
    """Fail-closed validation of a probe-run manifest."""
    if not isinstance(manifest, Mapping):
        raise ProbeRunError("run manifest must be an object.")
    if manifest.get("schema") != PROBE_RUN_SCHEMA:
        raise ProbeRunError(f"unsupported probe run schema: {manifest.get('schema')!r}.")
    for field in (
        "run_id",
        "run_at_utc",
        "corpus_version",
        "detector_id",
        "detector_version",
    ):
        _require_nonempty_string(manifest.get(field), f"run manifest {field}")
    if manifest.get("scope") not in RUN_SCOPES:
        raise ProbeRunError(f"run manifest scope must be one of {RUN_SCOPES}.")
    _require_hex64(manifest.get("corpus_fingerprint"), "corpus_fingerprint")
    if manifest.get("corpus_manifest_sha256") is not None:
        _require_hex64(manifest.get("corpus_manifest_sha256"), "corpus_manifest_sha256")
    if not isinstance(manifest.get("metrics"), Mapping):
        raise ProbeRunError("run manifest metrics must be an object.")
    if not isinstance(manifest.get("alerts"), list):
        raise ProbeRunError("run manifest alerts must be a list.")
    for alert in manifest["alerts"]:
        if not isinstance(alert, Mapping) or alert.get("tier") not in (1, 2, 3):
            raise ProbeRunError("run manifest alerts must carry tier 1, 2, or 3.")
        if alert.get("action") not in ("demote", "investigate", "record"):
            raise ProbeRunError("run manifest alerts must carry a valid action.")
    if not isinstance(manifest.get("breaches"), list):
        raise ProbeRunError("run manifest breaches must be a list.")
    if manifest.get("scope_statement") != _SCOPE_STATEMENT:
        raise ProbeRunError("run manifest scope statement must match the canonical text.")
    datetime.fromisoformat(str(manifest["run_at_utc"]))


def save_run(run: Mapping[str, Any], directory: str | Path) -> Path:
    """Atomically write one run manifest to the run-history directory."""
    validate_run_manifest(run)
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"run-{run['run_id']}.json"
    rendered = json.dumps(run, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
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
        os.replace(temp_path, target)
        temp_path = None
    finally:
        if temp_path is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp_path)
    return target


def load_run(path: str | Path) -> dict[str, Any]:
    """Load and validate one run manifest file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_run_manifest(data)
    return dict(data)


def load_run_history(directory: str | Path) -> list[dict[str, Any]]:
    """Load all run manifests in a directory, oldest first."""
    target_dir = Path(directory)
    if not target_dir.is_dir():
        return []
    runs = [load_run(path) for path in sorted(target_dir.glob("run-*.json"))]
    runs.sort(key=lambda r: str(r.get("run_at_utc", "")))
    return runs
