#!/usr/bin/env python3
"""build_w8_human_fpr_run_artifact.py — Aggregate the six W8 final-test
human-FPR measurements into one worst-slice run artifact
(``docs/evidence/runs/EV-20261116-human-fpr.json``), following the
EV-20261110 precedent (``scripts/build_human_fpr_run_artifact.py``).

What this script does (and does not do):

* It READS the six committed W8 corpus run artifacts
  (EV-20261116-dataset-{raid,mage,beemo,detectrl-x,ghostwriter,
  opai-bench}.json) and re-expresses every document slice measured on
  W8 final-test data with n_human > 0 — the 6 pooled per-dataset
  slices plus the finer required slices (per-domain/category/language/
  testbed partitions, per-attack, length buckets, per-generator
  cross-cuts with n_h > 0). Slices with n_human = 0 go in a separate
  ``results.unmeasured_slices`` list (null FPR, reason stated). The
  OpAI-Bench segment slice is excluded (different unit, not a W8
  final-test slice).
* Every per-slice value is quoted VERBATIM from its source artifact
  (4-decimal Wilson uppers as recorded there) and independently
  re-verified: the Wilson 95% upper is recomputed with the repo's own
  ``textforensics.probe_metrics.wilson_ci`` from the recorded (k, n)
  "and must agree within 5e-4. Any disagreement fails the build;
  nothing is written.
* It does NOT re-run the detector. Unlike the EV-20261110 precedent
  (a fresh re-measurement), this is an aggregation of the six W8
  measurements; independent re-scoring is already established by
  worker E's reproductions (Beemo 1318/1318, GhostWriter 879/879,
  OpAI-Bench 386/386, RAID 3519/3519, MAGE 3134/3134 AGREE) and
  worker B's DetectRL-X reproduction (2134/2134 AGREE).
* The report-card lead does NOT change. The worst document slice is
  MAGE testbed:dialogsum, 0/3, Wilson 95% upper 0.5615 (tied with
  testbed:pubmed, 0/3; alphabetical tie-break, per worker C's
  precedent) — n_human=3 is below the 100-row minimum and 0.5615
  exceeds the 0.05 ceiling, so the gate's worst-slice qualification
  fails and the lead stays ``unknown``. The artifact deliberately
  carries no ``worst_slice_human_fpr`` / ``human_fpr`` lead-flipping
  key: 0.5615 is a Wilson upper bound on a 0/3 rate, not a measured
  FPR point rate. The pooled value (0/4194 over the six pooled
  slices) is reported for completeness only and is never a gate
  statistic: pooling hides slice heterogeneity, and the finer slices
  overlap the pooled slices by construction (the same human rows
  counted under several partitions), so no pooled number is computed
  over all slices.
* ``badge`` is ``available`` (committed and hash-verified once
  pinned). ``functional``/``reproduced`` are not claimed: the gate
  has not re-run this command and CI has not reproduced these
  numbers.
* No claim is added or restated, no registry file is edited by this
  script. Pinning the new artifact in ``docs/evidence/registry.json``
  is a separate step.

Expected worst slice (failing the build if it differs — do not force
the number): ``results.worst_slice_wilson_ci_upper`` =
``results.worst_document_slice_wilson_ci_upper`` = 0.5615
(MAGE testbed:dialogsum, n_human=3).

Usage:
    python scripts/build_w8_human_fpr_run_artifact.py [--check]
    python scripts/build_w8_human_fpr_run_artifact.py --output <path>
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from textforensics.probe_metrics import wilson_ci  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-human-fpr"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"

FPR_BAR_N_HUMAN_MINIMUM = 100
FPR_BAR_N_AI_MINIMUM = 100
FPR_BAR_WILSON_UPPER_CEILING = 0.05
EXPECTED_WORST_UPPER = 0.5615
EXPECTED_WORST_DATASET = "MAGE"
EXPECTED_WORST_SLICE_ID = "testbed:dialogsum"

WILSON_METHOD = "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci"

# Keys the gate's worst_slice_fpr() reads to set the report-card lead.
# A Wilson CI upper bound is not a measured FPR point rate, so neither
# key may appear in this artifact's results. Enforced by build().
LEAD_FLIPPING_KEYS = ("worst_slice_human_fpr", "human_fpr")

CORPUS_ARTIFACTS = (
    ("RAID", "EV-20261116-dataset-raid", "evr-20261116-raid-builtin-heuristic"),
    ("MAGE", "EV-20261116-dataset-mage", "evr-20261116-mage-builtin-heuristic"),
    ("Beemo", "EV-20261116-dataset-beemo", "evr-20261116-beemo-builtin-heuristic"),
    (
        "DetectRL-X",
        "EV-20261116-dataset-detectrl-x",
        "evr-20261116-detectrl-x-builtin-heuristic",
    ),
    (
        "GhostWriter",
        "EV-20261116-dataset-ghostwriter",
        "evr-20261116-ghostwriter-builtin-heuristic",
    ),
    (
        "OpAI-Bench",
        "EV-20261116-dataset-opai-bench",
        "evr-20261116-opai-bench-builtin-heuristic",
    ),
)

DROPS = [
    {
        "item": "Beemo / DetectRL-X per-generator pooled cross-cuts",
        "reason": (
            "by_generator_pooled is pooled across the fit, validation "
            "and final-test partitions, not a final-test slice; no "
            "per-generator final-test breakdown exists in either "
            "artifact, so there is no final-test per-generator slice "
            "to aggregate"
        ),
    },
    {
        "item": "Beemo / DetectRL-X pooled by-category / by-kind / by-domain / by-language cross-cuts",
        "reason": (
            "by_category_pooled, by_kind_pooled, by_domain_pooled and "
            "by_lang_pooled are pooled across partitions, not "
            "final-test slices; only their final-test counterparts "
            "are aggregated"
        ),
    },
    {
        "item": "DetectRL-X by_split_pooled",
        "reason": (
            "pooled across the train/test source splits and across "
            "partitions; not a final-test slice"
        ),
    },
    {
        "item": "OpAI-Bench segment slice (evr-20261107-opai-bench-builtin-heuristic)",
        "reason": (
            "segment-level slice (sentences, not documents): a "
            "different unit, not a W8 final-test slice; assessed "
            "separately and never pooled with document slices"
        ),
    },
    {
        "item": "human populations and regimes outside the measured slices",
        "reason": (
            "non-English document text outside DetectRL-X/GhostWriter, "
            "ESL human text, texts below 80 words, generators newer "
            "than each record's declared vintage — none of these are "
            "in the measured slices"
        ),
    },
    {
        "item": "Python 3.11, 3.13, 3.14, 3.15",
        "reason": "measured on the local interpreter only; CI covers the matrix",
    },
]

METHOD = (
    "Aggregation of the six W8 final-test measurements "
    "(EV-20261116-dataset-raid, -mage, -beemo, -detectrl-x, "
    "-ghostwriter, -opai-bench). Every per-slice value is quoted "
    "verbatim from its source run artifact (Wilson 95% uppers as "
    "recorded there) and independently re-verified: the Wilson 95% "
    "interval is recomputed with "
    "textforensics.probe_metrics.wilson_ci from the recorded (k, n) "
    "and must agree within 5e-4 (the source artifacts round Wilson "
    "uppers to 4 decimals in the A/C artifacts and to 6 decimals in "
    "the B artifacts). The detector was NOT re-run for "
    "this artifact; independent re-scoring is established by the "
    "reproduction artifacts (worker E AGREE on all five A/C corpora; "
    "worker B AGREE on DetectRL-X). Human FPR = P(verdict=ai_like | "
    "human); native TPR = P(verdict=ai_like | AI) at the same native "
    "operating point (builtin-heuristic native verdict via "
    "analyze_text; no score threshold). Intervals are Wilson 95% CIs "
    "(z=1.96). Slices with n_human = 0 are listed separately under "
    "unmeasured_slices with a null FPR and a stated reason; they are "
    "not measured slices. The pooled_documents_only value pools only "
    "the six disjoint pooled per-dataset slices (0/4194); finer "
    "slices overlap the pooled slices by construction and are never "
    "pooled."
)

NOTES = (
    "Pooling is NOT legitimate as the gate statistic. The slices "
    "differ in regime (raw vs human-edited), language (en vs mul "
    "8-language vs en+de), domain, generator vintage and editing; "
    "pooling hides that heterogeneity. The pooled 0/4194 number is "
    "reported for completeness only. The release gate must use the "
    "per-slice worst Wilson ci_upper among the document slices — "
    "a single pooled number would let a large slice (DetectRL-X, "
    "n=2400) mask a thin slice (MAGE testbed:dialogsum, n=3, Wilson "
    "upper 0.5615).\n"
    "\n"
    "Worst document slice: MAGE testbed:dialogsum, 0/3 human rows "
    "verdict ai_like, Wilson 95% upper 0.5615. It is tied with MAGE "
    "testbed:pubmed (0/3, upper 0.5615); the alphabetically-first "
    "slice wins the tie-break, per worker C's precedent (GhostWriter "
    "arxiv_papers vs euro_court_cases, both 0/26, upper 0.1287). The "
    "worst slice is worst by small-n Wilson bound, not by observed "
    "false positives: every slice in this aggregation has k_fp = 0.\n"
    "\n"
    "Still unknown:\n"
    "- Worst-slice human FPR as a *supported* claim: the worst "
    "document slice (MAGE testbed:dialogsum, n_human=3, Wilson upper "
    "0.5615) fails the FPR bar outright (n_human below the 100-row "
    "minimum; Wilson upper above the 0.05 ceiling). The report-card "
    "lead ('worst-slice human FPR = unknown') changes only by a "
    "parent decision; this artifact does not change it.\n"
    "- Human FPR on slices the W8 final-test sets do not cover at "
    "all: the 43 unmeasured slices listed in unmeasured_slices "
    "(n_human = 0 in final-test), non-English document text outside "
    "DetectRL-X/GhostWriter, ESL human text, texts below 80 words, "
    "generators newer than each record's declared vintage, and human "
    "populations outside the declared ones.\n"
    "- Whether the zero observed false positives persist on larger "
    "human samples: every Wilson upper bound here is a bound on zero "
    "events, not a measured positive rate.\n"
    "\n"
    "This artifact aggregates the W8 final-test measurements; it is "
    "not a new claim and it does not change the report-card lead: the "
    'gate reads results["worst_slice_human_fpr"] for the lead, and '
    "this artifact deliberately carries no such key — 0.5615 is the "
    "Wilson 95% upper bound on a 0/3 rate (MAGE testbed:dialogsum), "
    "not a measured FPR point rate. No claim cites this record; the "
    "worst-slice human FPR as a supported claim remains unknown."
)


def _code_version() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _wilson_rate(k: int, n: int) -> dict:
    lo, hi = wilson_ci(k, n)
    return {
        "k": k,
        "n": n,
        "value": k / n if n else None,
        "ci_lower": lo,
        "ci_upper": hi,
        "method": WILSON_METHOD,
    }


def _check_wilson(recorded: dict, label: str, errors: list[str]) -> None:
    """Recompute a recorded Wilson interval; fail loudly on mismatch."""
    k = recorded.get("k")
    n = recorded.get("n")
    if not isinstance(k, int) or not isinstance(n, int) or n <= 0:
        errors.append(f"{label}: bad (k, n) for Wilson recomputation: k={k!r}, n={n!r}")
        return
    lo, hi = wilson_ci(k, n)
    # Tolerance 5e-4 (worker D's criterion): the source artifacts
    # round Wilson uppers to 4 decimals (A/C) or 6 decimals (B).
    if abs(hi - recorded.get("ci_upper")) >= 5e-4:
        errors.append(
            f"{label}: recorded ci_upper {recorded.get('ci_upper')} != "
            f"recomputed {hi} (diff {abs(hi - recorded.get('ci_upper')):.2g})"
        )
    if abs(lo - recorded.get("ci_lower")) >= 5e-4:
        errors.append(
            f"{label}: recorded ci_lower {recorded.get('ci_lower')} != "
            f"recomputed {lo} (diff {abs(lo - recorded.get('ci_lower')):.2g})"
        )


def _assessment(n_human: int, n_ai: int, ci_upper: float) -> dict:
    blockers: list[str] = []
    if n_human < FPR_BAR_N_HUMAN_MINIMUM:
        blockers.append(f"n_human={n_human} is below the 100-row minimum for a supported slice")
    if n_ai < FPR_BAR_N_AI_MINIMUM:
        blockers.append(f"n_ai={n_ai} is below the 100-row minimum (paired native TPR is thin)")
    if ci_upper > FPR_BAR_WILSON_UPPER_CEILING:
        blockers.append(f"Wilson fpr_native ci_upper is {ci_upper}, which exceeds the ceiling 0.05")
    return {
        "can_support_fpr_claim": not blockers,
        "blockers": blockers,
    }


def _unmeasured_reason(dataset: str, slice_id: str) -> str:
    if dataset == "GhostWriter":
        return (
            "no human rows in the W8 final-test set for this slice: all "
            "12 pooled human gutenberg rows fell into fit (7) and dev "
            "(5) under the frozen hash partition (worker C report §8)"
        )
    if dataset == "Beemo":
        return (
            "AI-only kind by construction: single-class slice with no "
            "human rows in the W8 final-test set (human rows carry "
            "kind human / human_edits)"
        )
    if dataset == "RAID":
        if slice_id.startswith("length:"):
            return (
                "no human rows in this length bucket in the W8 "
                "final-test set (all 121 final-test human rows are "
                ">= 80 words)"
            )
        if slice_id.startswith("model:"):
            return (
                "AI-only cross-cut: human rows carry model=human; this "
                "generator slice has no human rows by construction"
            )
        if slice_id.startswith("decoding:"):
            return (
                "AI-only cross-cut: human rows carry decoding=None; "
                "this decoding slice has no human rows by construction"
            )
    if dataset == "MAGE":
        if slice_id.endswith("_gpt4") or slice_id.endswith("_gpt4_para"):
            return (
                "no human rows sampled in this OOD testbed in the W8 final-test set (AI rows only)"
            )
        if slice_id.startswith("task:"):
            return (
                "AI-only cross-cut: the task label applies to machine "
                "rows; no human row carries this task label in the "
                "W8 final-test set"
            )
        if slice_id.startswith("generator_family:"):
            return (
                "AI-only cross-cut: human rows carry no generator "
                "family; this family slice has no human rows by "
                "construction"
            )
    return "no human rows in the W8 final-test set for this slice"


def _extract_raid_mage(
    dataset: str, artifact: dict, artifact_id: str, artifact_sha: str, errors: list[str]
) -> tuple[list[dict], list[dict]]:
    slices: list[dict] = []
    unmeasured: list[dict] = []
    ft = artifact["results"]["final_test"]
    for source in (ft.get("slices_primary", []), ft.get("slices_secondary", [])):
        for s in source:
            slice_id = s["slice_id"]
            n_human = s.get("n_human")
            n_ai = s.get("n_ai")
            fpr = s.get("fpr_native")
            if not isinstance(n_human, int) or fpr is None:
                unmeasured.append(
                    {
                        "dataset": dataset,
                        "slice_id": slice_id,
                        "source_artifact": artifact_id,
                        "source_artifact_sha256": artifact_sha,
                        "slice_kind": "document",
                        "n_human": 0,
                        "n_ai": n_ai,
                        "fpr_native_wilson": None,
                        "reason": _unmeasured_reason(dataset, slice_id),
                    }
                )
                continue
            _check_wilson(fpr, f"{dataset} {slice_id} fpr_native", errors)
            tpr = s.get("tpr_native")
            tpr_out = None
            if isinstance(tpr, dict) and isinstance(tpr.get("n"), int) and tpr["n"] > 0:
                _check_wilson(tpr, f"{dataset} {slice_id} tpr_native", errors)
                tpr_out = {
                    "k": tpr["k"],
                    "n": tpr["n"],
                    "value": tpr["value"],
                    "ci_lower": tpr["ci_lower"],
                    "ci_upper": tpr["ci_upper"],
                    "method": tpr.get("method", WILSON_METHOD),
                }
            slices.append(
                {
                    "dataset": dataset,
                    "slice_id": slice_id,
                    "source_artifact": artifact_id,
                    "source_artifact_sha256": artifact_sha,
                    "slice_kind": "document",
                    "n_human": n_human,
                    "n_ai": n_ai,
                    "abstentions": s.get("abstentions"),
                    "max_human_score": s.get("max_human_score"),
                    "operating_point": s.get("operating_point"),
                    "fpr_native_wilson": {
                        "k": fpr["k"],
                        "n": fpr["n"],
                        "value": fpr["value"],
                        "ci_lower": fpr["ci_lower"],
                        "ci_upper": fpr["ci_upper"],
                        "method": fpr.get("method", WILSON_METHOD),
                    },
                    "tpr_native_wilson": tpr_out,
                    "assessment": _assessment(n_human, n_ai, fpr["ci_upper"]),
                }
            )
    return slices, unmeasured


def _extract_beemo_detectrlx(
    dataset: str,
    artifact: dict,
    artifact_id: str,
    artifact_sha: str,
    errors: list[str],
    group_keys: list[tuple[str, str]],
) -> tuple[list[dict], list[dict]]:
    """B-shaped artifacts: final_test + by_<dim>_final_test dicts."""
    slices: list[dict] = []
    unmeasured: list[dict] = []
    results = artifact["results"]

    def emit(slice_id: str, block: dict) -> None:
        n_human = block.get("n_human")
        n_ai = block.get("n_ai")
        wilson = block.get("fpr_native_wilson_95")
        if not isinstance(n_human, int) or wilson is None:
            unmeasured.append(
                {
                    "dataset": dataset,
                    "slice_id": slice_id,
                    "source_artifact": artifact_id,
                    "source_artifact_sha256": artifact_sha,
                    "slice_kind": "document",
                    "n_human": 0,
                    "n_ai": n_ai,
                    "fpr_native_wilson": None,
                    "reason": _unmeasured_reason(dataset, slice_id),
                }
            )
            return
        k_fp = block.get("k_fp_native")
        if not isinstance(k_fp, int):
            errors.append(f"{dataset} {slice_id}: k_fp_native is not an int: {k_fp!r}")
            return
        recorded = {
            "k": k_fp,
            "n": n_human,
            "ci_lower": wilson[0],
            "ci_upper": wilson[1],
        }
        _check_wilson(recorded, f"{dataset} {slice_id} fpr_native", errors)
        tpr_out = None
        tpr_wilson = block.get("tpr_native_wilson_95")
        k_tp = block.get("k_tp_native")
        if (
            isinstance(tpr_wilson, list)
            and isinstance(k_tp, int)
            and isinstance(n_ai, int)
            and n_ai > 0
        ):
            tpr_recorded = {
                "k": k_tp,
                "n": n_ai,
                "ci_lower": tpr_wilson[0],
                "ci_upper": tpr_wilson[1],
            }
            _check_wilson(tpr_recorded, f"{dataset} {slice_id} tpr_native", errors)
            tpr_out = {
                "k": k_tp,
                "n": n_ai,
                "value": block.get("tpr_native"),
                "ci_lower": tpr_wilson[0],
                "ci_upper": tpr_wilson[1],
                "method": WILSON_METHOD,
            }
        slices.append(
            {
                "dataset": dataset,
                "slice_id": slice_id,
                "source_artifact": artifact_id,
                "source_artifact_sha256": artifact_sha,
                "slice_kind": "document",
                "n_human": n_human,
                "n_ai": n_ai,
                "abstentions": block.get("abstentions"),
                "max_human_score": block.get("max_human_score"),
                "operating_point": block.get("operating_point"),
                "fpr_native_wilson": {
                    "k": k_fp,
                    "n": n_human,
                    "value": block.get("fpr_native"),
                    "ci_lower": wilson[0],
                    "ci_upper": wilson[1],
                    "method": WILSON_METHOD,
                },
                "tpr_native_wilson": tpr_out,
                "assessment": _assessment(n_human, n_ai, wilson[1]),
            }
        )

    emit("pooled", results["final_test"])
    for key, prefix in group_keys:
        for name, block in sorted((results.get(key) or {}).items()):
            emit(f"{prefix}:{name}", block)
    return slices, unmeasured


def _extract_ghostwriter_opai(
    dataset: str, artifact: dict, artifact_id: str, artifact_sha: str, errors: list[str]
) -> tuple[list[dict], list[dict]]:
    slices: list[dict] = []
    unmeasured: list[dict] = []
    for key, s in sorted((artifact["results"]["evaluation"].get("slices") or {}).items()):
        slice_id = key
        n_human = s.get("n_human")
        n_ai = s.get("n_ai")
        fpr = s.get("fpr_native") or {}
        if not isinstance(n_human, int) or fpr.get("ci_upper") is None:
            unmeasured.append(
                {
                    "dataset": dataset,
                    "slice_id": slice_id,
                    "source_artifact": artifact_id,
                    "source_artifact_sha256": artifact_sha,
                    "source_slice_id": s.get("slice_id"),
                    "slice_kind": "document",
                    "n_human": 0,
                    "n_ai": n_ai,
                    "fpr_native_wilson": None,
                    "reason": _unmeasured_reason(dataset, slice_id),
                }
            )
            continue
        _check_wilson(fpr, f"{dataset} {slice_id} fpr_native", errors)
        tpr = s.get("tpr_native") or {}
        tpr_out = None
        if isinstance(tpr.get("n"), int) and tpr["n"] > 0 and tpr.get("ci_upper") is not None:
            _check_wilson(tpr, f"{dataset} {slice_id} tpr_native", errors)
            tpr_out = {
                "k": tpr["k"],
                "n": tpr["n"],
                "value": tpr["value"],
                "ci_lower": tpr["ci_lower"],
                "ci_upper": tpr["ci_upper"],
                "method": tpr.get("method", WILSON_METHOD),
            }
        score_by_label = s.get("score_by_label") or {}
        human_scores = score_by_label.get("human") or {}
        slices.append(
            {
                "dataset": dataset,
                "slice_id": slice_id,
                "source_artifact": artifact_id,
                "source_artifact_sha256": artifact_sha,
                "source_slice_id": s.get("slice_id"),
                "slice_kind": "document",
                "n_human": n_human,
                "n_ai": n_ai,
                "abstentions": s.get("abstentions"),
                "max_human_score": human_scores.get("max"),
                "operating_point": fpr.get("operating_point"),
                "fpr_native_wilson": {
                    "k": fpr["k"],
                    "n": fpr["n"],
                    "value": fpr["value"],
                    "ci_lower": fpr["ci_lower"],
                    "ci_upper": fpr["ci_upper"],
                    "method": fpr.get("method", WILSON_METHOD),
                },
                "tpr_native_wilson": tpr_out,
                "assessment": _assessment(n_human, n_ai, fpr["ci_upper"]),
            }
        )
    return slices, unmeasured


def extract_all(errors: list[str]) -> tuple[list[dict], list[dict]]:
    """Extract every W8 final-test document slice (n_human > 0) plus the
    unmeasured (n_human = 0) slices. Pooled slice first per corpus,
    then finer slices sorted alphabetically by slice_id (deterministic;
    the alphabetical order is also the tie-break for the worst slice).
    """
    all_slices: list[dict] = []
    all_unmeasured: list[dict] = []
    runs_dir = REPO_ROOT / "docs" / "evidence" / "runs"
    for dataset, artifact_id, record_id in CORPUS_ARTIFACTS:
        path = runs_dir / f"{artifact_id}.json"
        if not path.exists():
            errors.append(f"source artifact missing: {path}")
            continue
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact_sha = _sha256_file(path)
        if dataset in ("RAID", "MAGE"):
            slices, unmeasured = _extract_raid_mage(
                dataset, artifact, artifact_id, artifact_sha, errors
            )
        elif dataset == "Beemo":
            slices, unmeasured = _extract_beemo_detectrlx(
                dataset,
                artifact,
                artifact_id,
                artifact_sha,
                errors,
                [("by_category_final_test", "category"), ("by_kind_final_test", "kind")],
            )
        elif dataset == "DetectRL-X":
            slices, unmeasured = _extract_beemo_detectrlx(
                dataset,
                artifact,
                artifact_id,
                artifact_sha,
                errors,
                [("by_domain_final_test", "domain"), ("by_lang_final_test", "language")],
            )
        else:
            slices, unmeasured = _extract_ghostwriter_opai(
                dataset, artifact, artifact_id, artifact_sha, errors
            )
        # Pooled slice first, then finer slices alphabetically.
        pooled = [s for s in slices if s["slice_id"] == "pooled"]
        finer = sorted(
            (s for s in slices if s["slice_id"] != "pooled"),
            key=lambda s: s["slice_id"],
        )
        if len(pooled) != 1:
            errors.append(f"{dataset}: expected exactly one pooled slice, found {len(pooled)}")
        for s in pooled:
            s["record_id"] = record_id
        ordered = pooled + finer
        all_slices.extend(ordered)
        all_unmeasured.extend(sorted(unmeasured, key=lambda u: (u["dataset"], u["slice_id"])))
    return all_slices, all_unmeasured


def validate_run_artifact(artifact: dict, root: Path | None = None) -> list[str]:
    """Validate an artifact with the repo's own gate validator."""
    root = root or REPO_ROOT
    check_claims = _load_module("check_claims_for_validation", root / "scripts" / "check_claims.py")
    schema = check_claims._load_schema(root, "run-artifact.schema.json")
    return check_claims._schema_errors(schema, artifact)


def build() -> tuple[dict | None, list[str]]:
    """Build the aggregation artifact dict. Returns (artifact, errors);
    artifact is None when errors is non-empty."""
    errors: list[str] = []
    slices, unmeasured = extract_all(errors)
    if errors:
        return None, errors
    if not slices:
        return None, ["no slices extracted"]
    pooled = [s for s in slices if s["slice_id"] == "pooled"]
    if len(pooled) != 6:
        return None, [f"expected 6 pooled slices, found {len(pooled)}"]
    worst_upper = max(s["fpr_native_wilson"]["ci_upper"] for s in slices)
    worst = max(slices, key=lambda s: s["fpr_native_wilson"]["ci_upper"])
    if worst_upper != EXPECTED_WORST_UPPER:
        return None, [
            "WORST-SLICE DISCREPANCY: computed worst Wilson upper "
            f"{worst_upper} != expected {EXPECTED_WORST_UPPER}; "
            "stopping instead of forcing the number"
        ]
    if worst["dataset"] != EXPECTED_WORST_DATASET or worst["slice_id"] != EXPECTED_WORST_SLICE_ID:
        return None, [
            "WORST-SLICE DISCREPANCY: computed worst slice is "
            f"{worst['dataset']} {worst['slice_id']} "
            f"(n_human={worst['n_human']}), expected "
            f"{EXPECTED_WORST_DATASET} {EXPECTED_WORST_SLICE_ID}"
        ]
    pooled_k = sum(s["fpr_native_wilson"]["k"] for s in pooled)
    pooled_n = sum(s["n_human"] for s in pooled)
    pooled_rate = _wilson_rate(pooled_k, pooled_n)
    artifact = {
        "schema": RUN_ARTIFACT_SCHEMA,
        "evidence_record_id": ARTIFACT_ID,
        "kind": "command",
        "command": "python scripts/build_w8_human_fpr_run_artifact.py",
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "detector": "textforensics/builtin-heuristic",
            "detector_family": "stylometric-heuristic",
            "detector_version": "0.1.0",
            "method": METHOD,
            "slices": slices,
            "unmeasured_slices": unmeasured,
            "pooled_documents_only": pooled_rate,
            "worst_slice_wilson_ci_upper": worst_upper,
            "worst_document_slice_wilson_ci_upper": worst_upper,
        },
        "drops": DROPS,
        "badge": "available",
        "detector_version": "0.1.0",
        "notes": NOTES,
    }
    for key in LEAD_FLIPPING_KEYS:
        if key in artifact["results"]:
            errors.append(f"results carries {key!r}, which would flip the report-card lead")
    if errors:
        return None, errors
    schema_errors = validate_run_artifact(artifact)
    if schema_errors:
        return None, [f"run-artifact/v1 validation: {e}" for e in schema_errors]
    return artifact, []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="extract, verify and validate only; write no artifact file",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="artifact path (default: docs/evidence/runs/EV-20261116-human-fpr.json)",
    )
    args = parser.parse_args(argv)
    artifact, errors = build()
    if artifact is None:
        print("BUILD FAILURE:", file=sys.stderr)
        for item in errors:
            print(f"  - {item}", file=sys.stderr)
        return 2
    slices = artifact["results"]["slices"]
    unmeasured = artifact["results"]["unmeasured_slices"]
    worst = max(slices, key=lambda s: s["fpr_native_wilson"]["ci_upper"])
    n_pass = sum(1 for s in slices if s["assessment"]["can_support_fpr_claim"])
    print(f"slices with n_human > 0: {len(slices)} (pass the FPR bar: {n_pass})")
    print(f"unmeasured slices (n_human = 0): {len(unmeasured)}")
    print(
        f"worst document slice: {worst['dataset']} {worst['slice_id']} "
        f"(n_human={worst['n_human']}, Wilson upper "
        f"{worst['fpr_native_wilson']['ci_upper']})"
    )
    print(
        "pooled over the 6 pooled slices: "
        f"k={artifact['results']['pooled_documents_only']['k']}, "
        f"n={artifact['results']['pooled_documents_only']['n']}, "
        f"Wilson upper {artifact['results']['pooled_documents_only']['ci_upper']}"
    )
    print("run-artifact/v1 validation errors: 0")
    print("verdict: worst slice 0.5615 as expected; report-card lead unchanged (unknown)")
    if args.check:
        print("check mode: no artifact file written")
        return 0
    output = (
        Path(args.output)
        if args.output
        else REPO_ROOT / "docs" / "evidence" / "runs" / f"{ARTIFACT_ID}.json"
    )
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
