#!/usr/bin/env python3
"""reproduce_w8a_raid.py — W8 worker E (independent reproduction).

Independently reproduces Worker A's RAID qualification run artifact
(docs/evidence/runs/EV-20261116-dataset-raid.json) from scratch.

Source: the INTEGRATED copies on audit-w7 in the main clone
(~/workspace/TextForensics-rewrite, head ed45ce5); Worker A's branch
and worktree were deleted after integration. The integrated artifact
(SHA fce89889...) is byte-identical to the worktree copy this
reproduction first ran against.

- Reads the pinned cache files DIRECTLY as JSONL (no dataset-loader
  helpers, no import of Worker A's script, no import of
  scripts/measure_datasets.py).
- Re-derives the sampling grid from the frozen plan (strided offsets
  ``i * total // n``; phase shift = smallest shift disjoint from the
  U1 3000-grid and the +189 6000-grid) and checks the offsets SHA-256
  against the frozen manifest.
- Verifies cache file SHA-256s, row counts and label counts for the
  validation and final-test caches and for every disjointness target.
- Re-derives the exact-dedupe, the RAID leakage rules (human
  source_id exclusion + word-8-gram Jaccard > 0.8 near-duplicate
  exclusion) and the content-hash disjointness (final-test vs
  validation, vs the U1 sample, vs raid_test/test) from the raw rows.
- Re-scores the validation and final-test rows with a fresh
  BuiltinHeuristicDetector at its native operating point, with a
  determinism self-check (final-test scored twice).
- Recomputes every reported metric with INDEPENDENT implementations
  written here. CONVENTION NOTE: Worker A uses a DIFFERENT bootstrap
  convention from Workers B/C — a FRESH ``random.Random(20261116)``
  per ``_bootstrap_ci`` call (not a shared stream), resamples drawn
  with ``rng.randrange(n)`` (not ``rng.choices``), and percentile
  indices ``lo = boot[max(0, int(0.025 * len) - 1)]``,
  ``hi = boot[min(len - 1, int(0.975 * len))]``. This script follows
  A's convention exactly; using B/C's shared-stream convention would
  give different CIs. AUROC is computed pairwise (Mann-Whitney wins +
  0.5 * ties) and cross-checked against the rank method; AUPRC is the
  stepwise average precision (sort by score desc, label desc on ties);
  TPR@FPR is the max TPR among distinct-score thresholds with
  FPR <= target.
- Compares every field of Worker A's artifact (final-test and
  validation slices, worst slice, reproduction check, inclusion,
  disjointness, near-duplicate report, exclusions, determinism,
  manifest SHA, environment lock) against the recomputation and
  reports agreement or ANY discrepancy, however small.

Usage:
    python scripts/reproduce_w8a_raid.py [--check]
    python scripts/reproduce_w8a_raid.py --output <path>

--check measures and compares only; it writes nothing. The default
output is docs/evidence/runs/EV-20261116-reproduction-raid.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import random
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-reproduction-raid"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
A_DIR = Path("/home/hatch/workspace/TextForensics-rewrite")
CACHE_ROOT = Path.home() / ".cache" / "textforensics" / "datasets"
BOOTSTRAP_SEED = 20261116
BOOTSTRAP_RESAMPLES = 1000
MIN_N_HUMAN = 100
FPR_UPPER_MAX = 0.05
Z_95 = 1.96

RAID_TRAIN_TOTAL = 2_270_000
RAID_FINAL_N = 4000
RAID_U1_N = 3000
RAID_OLD_N = 6000
RAID_OLD_SHIFT = 189

# Frozen plan values (from Worker A's script — the pinned record).
VAL_CACHE_REL = ("raid", "raid", "train-6000.jsonl")
VAL_SHA256 = "59cf57c4db6778dad065cc78c4b4f92c54544d57652aa30606c307c3f81d44d3"
VAL_ROWS = 6000
VAL_HUMAN = 171
VAL_AI = 5829
PRIOR_RUN = "EV-20261108-dataset-raid"
PRIOR_AUROC = 0.5958
PRIOR_TPR_AT_1PCT = 0.0571
PRIOR_TPR_AT_5PCT = 0.1414
FINAL_CACHE_REL = ("raid", "raid", "train-4000-w8.jsonl")
EXTRA_TARGETS = [
    {
        "cache_rel": ("raid", "raid", "train.jsonl"),
        "sha256": "f689a30963024b2dc1fa159f2888e1d2ba36e68263d467ab7f73db5d9e780c00",
        "label": "raid/train U1 sample (n=3000)",
    },
    {
        "cache_rel": ("raid", "raid_test", "test.jsonl"),
        "sha256": "bf2b73d5a45c299b3ce0dae8f9369b80fc08f165fa5f5b7173f35754bdec570a",
        "label": "raid_test/test (n=50, unlabelled)",
    },
]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_hash(text: str) -> str:
    """Own canonical-LF SHA-256 (CRLF/lone CR -> LF before hashing)."""
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def _load_cache_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _code_version() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


# --- Independent metric implementations (written here, not imported) ---


def wilson_ci(k: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval, 95%, from the formula."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    denom = 1.0 + z * z / n
    centre = p + z * z / (2.0 * n)
    adj = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n))
    return (centre - adj) / denom, (centre + adj) / denom


def auroc_pairwise(labels: list[int], scores: list[float]) -> float:
    """AUROC by pairwise Mann-Whitney counting (wins + 0.5 * ties)."""
    pos = [s for s, lab in zip(scores, labels, strict=False) if lab == 1]
    neg = [s for s, lab in zip(scores, labels, strict=False) if lab == 0]
    if not pos or not neg:
        raise ValueError("auroc needs both classes present")
    wins = 0.0
    for p in pos:
        for q in neg:
            if p > q:
                wins += 1.0
            elif p == q:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def auroc_rank(labels: list[int], scores: list[float]) -> float:
    """AUROC by average-rank Mann-Whitney (cross-check for pairwise)."""
    pairs = sorted(zip(scores, labels, strict=True))
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("auroc needs both classes present")
    rank_sum = 0.0
    i = 0
    n = len(pairs)
    while i < n:
        j = i
        while j < n and pairs[j][0] == pairs[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            if pairs[k][1] == 1:
                rank_sum += avg_rank
        i = j
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def auprc_stepwise(labels: list[int], scores: list[float]) -> float:
    """Stepwise average precision: sort desc (label desc on score ties)."""
    pairs = sorted(zip(scores, labels, strict=True), reverse=True)
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("auprc needs both classes present")
    tp = fp = 0
    prev_recall = 0.0
    ap = 0.0
    for _score, label in pairs:
        if label == 1:
            tp += 1
        else:
            fp += 1
        recall = tp / n_pos
        precision = tp / (tp + fp)
        ap += (recall - prev_recall) * precision
        prev_recall = recall
    return ap


def tpr_at_fpr(labels: list[int], scores: list[float], target_fpr: float) -> float:
    """Max TPR among distinct-score thresholds with FPR <= target."""
    pairs = sorted(zip(scores, labels, strict=True), reverse=True)
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("tpr_at_fpr needs both classes present")
    best = 0.0
    tp = fp = 0
    idx = 0
    while idx < len(pairs):
        threshold = pairs[idx][0]
        while idx < len(pairs) and pairs[idx][0] == threshold:
            if pairs[idx][1] == 1:
                tp += 1
            else:
                fp += 1
            idx += 1
        if fp / n_neg <= target_fpr and tp / n_pos > best:
            best = tp / n_pos
    return best


def bootstrap_ci(
    pairs: list[tuple[int, float]],
    fn,
    *,
    seed: int = BOOTSTRAP_SEED,
    resamples: int = BOOTSTRAP_RESAMPLES,
) -> dict | None:
    """Percentile bootstrap 95% CI, following Worker A's convention:
    fresh Random(seed) per call, resamples via rng.randrange(n),
    ValueError resamples skipped and counted, None when the full-sample
    statistic raises or fewer than 100 resamples survive."""
    try:
        value = fn([lab for lab, _ in pairs], [s for _, s in pairs])
    except ValueError:
        return None
    rng = random.Random(seed)
    n = len(pairs)
    boot: list[float] = []
    skipped = 0
    for _ in range(resamples):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        try:
            boot.append(fn([lab for lab, _ in sample], [s for _, s in sample]))
        except ValueError:
            skipped += 1
    if len(boot) < 100:
        return None
    boot.sort()
    lo = boot[max(0, int(0.025 * len(boot)) - 1)]
    hi = boot[min(len(boot) - 1, int(0.975 * len(boot)))]
    return {
        "value": round(value, 4),
        "ci_lower": round(lo, 4),
        "ci_upper": round(hi, 4),
        "method": f"bootstrap, {resamples} resamples, seed {seed}",
        "resamples_skipped": skipped,
    }


def wilson_entry(k: int, n: int) -> dict:
    lo, hi = wilson_ci(k, n)
    return {
        "k": k,
        "n": n,
        "value": round(k / n, 4) if n else None,
        "ci_lower": round(lo, 4),
        "ci_upper": round(hi, 4),
        "method": "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci",
    }


def score_summary(scores: list[float]) -> dict:
    if not scores:
        return {"n": 0, "mean": None, "median": None, "min": None, "max": None}
    return {
        "n": len(scores),
        "mean": round(statistics.fmean(scores), 4),
        "median": round(statistics.median(scores), 4),
        "min": round(min(scores), 4),
        "max": round(max(scores), 4),
    }


def cluster_bootstrap_fpr(
    human_clusters: list[tuple[str, int]],
    *,
    seed: int = BOOTSTRAP_SEED,
    resamples: int = BOOTSTRAP_RESAMPLES,
) -> dict | None:
    """Cluster bootstrap 95% CI for human FPR; None when k_fp == 0."""
    clusters: dict[str, list[int]] = defaultdict(list)
    for cluster_id, is_fp in human_clusters:
        clusters[cluster_id].append(is_fp)
    cluster_list = list(clusters.values())
    k = sum(sum(v) for v in cluster_list)
    if k == 0:
        return None
    rng = random.Random(seed)
    n_clusters = len(cluster_list)
    boot: list[float] = []
    for _ in range(resamples):
        fp = tot = 0
        for _ in range(n_clusters):
            vals = cluster_list[rng.randrange(n_clusters)]
            fp += sum(vals)
            tot += len(vals)
        boot.append(fp / tot if tot else 0.0)
    boot.sort()
    return {
        "value": round(k / sum(len(v) for v in cluster_list), 4),
        "ci_lower": round(boot[max(0, int(0.025 * len(boot)) - 1)], 4),
        "ci_upper": round(boot[min(len(boot) - 1, int(0.975 * len(boot)))], 4),
        "method": f"cluster bootstrap, {resamples} resamples over "
        f"{n_clusters} clusters, seed {seed}",
        "n_clusters": n_clusters,
    }


# --- Slice construction (same groupings as the predeclared lists) ---


def length_bucket(words: int) -> str:
    if words < 80:
        return "<80 words (below detector floor)"
    if words < 200:
        return "80-199 words"
    if words < 500:
        return "200-499 words"
    return "500+ words"


OPERATING_POINT = (
    "builtin-heuristic native verdict (analyze_text via "
    "BuiltinHeuristicDetector.detect); no score threshold"
)


def cluster_key(m: dict) -> str:
    return str(m["meta"].get("source_id") or m["source_id"])


def slice_metrics(slice_id: str, measured: list[dict]) -> dict:
    labelled = [m for m in measured if m["label"] is not None and m["error"] is None]
    human = [m for m in labelled if m["label"] == 0]
    ai = [m for m in labelled if m["label"] == 1]
    abstentions = sum(1 for m in labelled if m["verdict"] == "abstain")
    errors = sum(1 for m in measured if m["error"] is not None)
    unlabelled = sum(1 for m in measured if m["label"] is None)
    k_fp = sum(1 for m in human if m["verdict"] == "ai_like")
    k_tp = sum(1 for m in ai if m["verdict"] == "ai_like")
    pairs = [(m["label"], m["score"]) for m in labelled]
    result: dict = {
        "slice_id": slice_id,
        "n_rows": len(measured),
        "n_labelled": len(labelled),
        "n_unlabelled": unlabelled,
        "n_detection_errors": errors,
        "n_human": len(human),
        "n_ai": len(ai),
        "n_human_clusters": len({cluster_key(m) for m in human}),
        "n_ai_clusters": len({cluster_key(m) for m in ai}),
        "fpr_native": wilson_entry(k_fp, len(human)) if human else None,
        "tpr_native": wilson_entry(k_tp, len(ai)) if ai else None,
        "coverage": round(1 - abstentions / len(labelled), 4) if labelled else None,
        "abstention_rate": round(abstentions / len(labelled), 4) if labelled else None,
        "abstentions": abstentions,
        "score_by_label": {
            "human": score_summary([m["score"] for m in human]),
            "machine": score_summary([m["score"] for m in ai]),
        },
        "max_human_score": round(max((m["score"] for m in human), default=0.0), 4),
        "operating_point": OPERATING_POINT,
    }
    fpr = result["fpr_native"]
    if fpr is not None:
        result["fpr_native"]["operating_point"] = result["operating_point"]
        result["meets_gate"] = len(human) >= MIN_N_HUMAN and fpr["ci_upper"] <= FPR_UPPER_MAX
        result["gate_blockers"] = [
            b
            for b, bad in (
                (f"n_human={len(human)} < {MIN_N_HUMAN}", len(human) < MIN_N_HUMAN),
                (
                    f"Wilson upper {fpr['ci_upper']} > {FPR_UPPER_MAX}",
                    fpr["ci_upper"] > FPR_UPPER_MAX,
                ),
            )
            if bad
        ]
    if len(human) >= 10 and len(ai) >= 10:
        result["auroc"] = bootstrap_ci(pairs, auroc_pairwise)
        result["auprc"] = bootstrap_ci(pairs, auprc_stepwise)
        result["auprc_baseline_prevalence"] = round(len(ai) / len(labelled), 4)
        result["tpr_at_fpr_0_01"] = bootstrap_ci(
            pairs, lambda labs, scs: tpr_at_fpr(labs, scs, 0.01)
        )
        result["tpr_at_fpr_0_05"] = bootstrap_ci(
            pairs, lambda labs, scs: tpr_at_fpr(labs, scs, 0.05)
        )
    else:
        result["auroc"] = None
        result["auprc"] = None
        result["auroc_not_computed"] = (
            f"both classes need >= 10 rows; n_human={len(human)}, n_ai={len(ai)}"
            if labelled
            else "no labelled rows in this slice"
        )
    cluster_fpr = cluster_bootstrap_fpr(
        [(cluster_key(m), 1 if m["verdict"] == "ai_like" else 0) for m in human]
    )
    if cluster_fpr is not None:
        result["fpr_native_cluster_bootstrap"] = cluster_fpr
    return result


def build_slices(measured: list[dict]) -> tuple[list[dict], list[dict]]:
    primary: list[dict] = [slice_metrics("pooled", measured)]
    secondary: list[dict] = []
    by_domain: dict[str, list[dict]] = defaultdict(list)
    by_length: dict[str, list[dict]] = defaultdict(list)
    for m in measured:
        by_domain[str(m["meta"].get("domain"))].append(m)
        by_length[length_bucket(m["words"])].append(m)
    for domain in sorted(by_domain):
        primary.append(slice_metrics(f"domain:{domain}", by_domain[domain]))
    for bucket in sorted(by_length):
        secondary.append(slice_metrics(f"length:{bucket}", by_length[bucket]))
    for field, prefix in (("model", "model"), ("attack", "attack"), ("decoding", "decoding")):
        groups: dict[str, list[dict]] = defaultdict(list)
        for m in measured:
            groups[str(m["meta"].get(field))].append(m)
        for value in sorted(groups):
            secondary.append(slice_metrics(f"{prefix}:{value}", groups[value]))
    return primary, secondary


def worst_human_slice(slices: list[dict]) -> dict | None:
    candidates = [
        s
        for s in slices
        if s["slice_id"] != "pooled" and s["fpr_native"] is not None and s["n_human"] >= 10
    ]
    if not candidates:
        return None
    worst = max(candidates, key=lambda s: s["fpr_native"]["ci_upper"])
    return {
        "slice_id": worst["slice_id"],
        "n_human": worst["n_human"],
        "k_fp": worst["fpr_native"]["k"],
        "fpr_value": worst["fpr_native"]["value"],
        "fpr_wilson_upper": worst["fpr_native"]["ci_upper"],
    }


# --- Reproduction helpers ---


def _word_ngrams(text: str, n: int = 8) -> set[str]:
    words = text.split()
    if len(words) < n:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i : i + n]) for i in range(len(words) - n + 1)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _dedupe_exact(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Drop exact-duplicate texts within one sample (keep first)."""
    seen: set[str] = set()
    kept, dropped = [], []
    for row in rows:
        h = _canonical_hash(row["text"])
        if h in seen:
            dropped.append(
                {
                    "item": f"duplicate text sha256 {h[:16]}...",
                    "reason": "exact duplicate of an earlier row in the same sample",
                }
            )
            continue
        seen.add(h)
        kept.append(row)
    return kept, dropped


def _sample_offsets(total: int, n: int) -> list[int]:
    """Evenly spaced row offsets: offset i is i * total // n."""
    return [i * total // n for i in range(n)]


def _find_shift(total: int, n: int, forbidden: list[set[int]]) -> int:
    """Smallest shift s with the s-shifted n-grid disjoint from every forbidden set."""
    base = _sample_offsets(total, n)
    for shift in range(0, total // n + 1):
        cand = {(offset + shift) % total for offset in base}
        if len(cand) != n:
            continue
        if any(cand & other for other in forbidden):
            continue
        return shift
    raise ValueError(f"no disjoint shift found for total={total} n={n}")


def _shifted_offsets(total: int, n: int, shift: int) -> list[int]:
    return [(offset + shift) % total for offset in _sample_offsets(total, n)]


def _raid_leakage_checks(
    validation_rows: list[dict], final_rows: list[dict]
) -> tuple[list[dict], list[dict], dict]:
    """RAID source-document leakage rules (predeclared).

    Exclusion 1: final-test human row sharing a validation human
    meta.source_id. Exclusion 2: any final-test row with word-8-gram
    Jaccard > 0.8 against a validation row sharing its meta.source_id.
    """
    val_human_sids = {r["meta"].get("source_id") for r in validation_rows if r["label"] == 0}
    val_by_sid: dict[str, list[dict]] = defaultdict(list)
    for row in validation_rows:
        val_by_sid[row["meta"].get("source_id")].append(row)
    exclusions: list[dict] = []
    kept: list[dict] = []
    max_jaccard = 0.0
    n_over_half = 0
    n_pairs_checked = 0
    for row in final_rows:
        sid = row["meta"].get("source_id")
        if row["label"] == 0 and sid in val_human_sids:
            exclusions.append(
                {
                    "item": f"final-test human row source_id={sid}",
                    "reason": "same human source document as a validation human row: "
                    "the identical human text would be evaluated twice",
                    "text_sha256_prefix": _canonical_hash(row["text"])[:16],
                }
            )
            continue
        worst_for_row = 0.0
        row_grams = _word_ngrams(row["text"])
        for other in val_by_sid.get(sid, []):
            n_pairs_checked += 1
            jac = _jaccard(row_grams, _word_ngrams(other["text"]))
            worst_for_row = max(worst_for_row, jac)
        max_jaccard = max(max_jaccard, worst_for_row)
        if worst_for_row > 0.5:
            n_over_half += 1
        if worst_for_row > 0.8:
            exclusions.append(
                {
                    "item": f"final-test row source_id={sid} (label={row['label']})",
                    "reason": f"near-duplicate of a validation row sharing its source "
                    f"document (word-8-gram Jaccard {worst_for_row:.3f} > 0.8)",
                    "text_sha256_prefix": _canonical_hash(row["text"])[:16],
                }
            )
            continue
        kept.append(row)
    report = {
        "pairs_checked_same_source_id": n_pairs_checked,
        "max_word_8gram_jaccard": round(max_jaccard, 4),
        "pairs_jaccard_over_0_5": n_over_half,
        "threshold_exclude": 0.8,
        "n_excluded": len(exclusions),
    }
    return kept, exclusions, report


def _content_hashes(rows: list[dict]) -> set[str]:
    return {_canonical_hash(r["text"]) for r in rows}


def _auprc_tie_grouped(labels: list[int], scores: list[float]) -> float:
    """Tie-grouped stepwise AP (informational cross-check only: a
    different estimator from Worker A's per-row form; differs only
    when tied scores straddle the ranking)."""
    n_pos = sum(labels)
    if n_pos == 0 or n_pos == len(labels):
        raise ValueError("auprc needs both classes present")
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    idx = 0
    n = len(order)
    while idx < n:
        threshold = scores[order[idx]]
        while idx < n and scores[order[idx]] == threshold:
            if labels[order[idx]] == 1:
                tp += 1
            else:
                fp += 1
            idx += 1
        precision = tp / (tp + fp)
        recall = tp / n_pos
        ap += (recall - prev_recall) * precision
        prev_recall = recall
    return ap


def measure_rows(detector, rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        try:
            prediction = detector.detect(row["text"])
            score, verdict, error = float(prediction.score), prediction.verdict, None
        except Exception as exc:  # noqa: BLE001 - counted, never hidden
            score, verdict, error = float("nan"), "error", f"{type(exc).__name__}: {exc}"
        out.append(
            {
                "label": row["label"],
                "score": score,
                "verdict": verdict,
                "error": error,
                "words": len(row["text"].split()),
                "meta": row.get("meta", {}),
                "source_id": row.get("source_id", ""),
                "text_sha256": _canonical_hash(row["text"]),
                "raw_sha256": _sha256_text(row["text"]),
            }
        )
    return out


def _env_lock(repo_root: Path) -> dict:
    lock = {}
    for name in ("requirements-pinned.txt", "requirements-hashed.txt"):
        path = repo_root / name
        lock[name] = _sha256_file(path) if path.exists() else None
    return lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="measure and compare only; write nothing"
    )
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    a_results_path = A_DIR / "docs" / "evidence" / "runs" / "EV-20261116-dataset-raid.json"
    a_manifest_path = A_DIR / "docs" / "evidence" / "manifests" / "EV-20261116-raid-manifest.json"
    if not a_results_path.exists():
        raise ValueError(f"Worker A RAID artifact missing (rerun in progress?): {a_results_path}")
    if not a_manifest_path.exists():
        raise ValueError(f"Worker A RAID manifest missing (rerun in progress?): {a_manifest_path}")
    a_artifact = json.loads(a_results_path.read_text(encoding="utf-8"))
    a_results = a_artifact["results"]
    a_manifest = json.loads(a_manifest_path.read_text(encoding="utf-8"))
    a_sha = _sha256_file(a_results_path)
    manifest_sha = _sha256_file(a_manifest_path)

    checks: list[dict] = []
    comparison: list[dict] = []
    discrepancies: list[dict] = []
    cross_checks: dict = {}

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(ok), "detail": str(detail)})
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)

    def compare(path: str, mine, theirs) -> None:
        same = mine == theirs
        comparison.append({"field": path, "reproduction": mine, "worker_a": theirs, "agree": same})
        if not same:
            discrepancies.append({"field": path, "reproduction": mine, "worker_a": theirs})

    def deep_compare(path: str, mine, theirs) -> None:
        if isinstance(mine, dict) and isinstance(theirs, dict):
            for k in sorted(set(mine) | set(theirs)):
                if k not in mine:
                    compare(f"{path}.{k}", "<missing>", theirs[k])
                elif k not in theirs:
                    compare(f"{path}.{k}", mine[k], "<missing>")
                else:
                    deep_compare(f"{path}.{k}", mine[k], theirs[k])
        elif isinstance(mine, list) and isinstance(theirs, list):
            compare(f"{path}.__len__", len(mine), len(theirs))
            for i, (a, b) in enumerate(zip(mine, theirs, strict=False)):
                if i < min(len(mine), len(theirs)):
                    deep_compare(f"{path}[{i}]", a, b)
        else:
            compare(path, mine, theirs)

    # --- 1. Frozen validation cache: SHA, rows, label counts ---
    val_cache_path = CACHE_ROOT.joinpath(*VAL_CACHE_REL)
    check(
        "validation cache sha256 matches FROZEN",
        _sha256_file(val_cache_path) == VAL_SHA256,
        f"{_sha256_file(val_cache_path)[:12]} vs {VAL_SHA256[:12]}",
    )
    val_rows_raw = _load_cache_jsonl(val_cache_path)
    check(
        "validation cache row count",
        len(val_rows_raw) == VAL_ROWS,
        f"{len(val_rows_raw)} vs {VAL_ROWS}",
    )
    val_counts_raw = Counter(r["label"] for r in val_rows_raw)
    check(
        "validation cache label counts",
        val_counts_raw.get(0, 0) == VAL_HUMAN and val_counts_raw.get(1, 0) == VAL_AI,
        dict(val_counts_raw),
    )
    val_rows, val_dupes = _dedupe_exact(val_rows_raw)
    val_counts = Counter(r["label"] for r in val_rows)

    # --- 2. Frozen manifest: status, offsets, final-test cache ---
    check("manifest status is frozen", a_manifest["status"] == "frozen", a_manifest["status"])
    ft = a_manifest["partitions"]["final_test"]
    u1_offsets = set(_sample_offsets(RAID_TRAIN_TOTAL, RAID_U1_N))
    old_offsets = {
        (o + RAID_OLD_SHIFT) % RAID_TRAIN_TOTAL
        for o in _sample_offsets(RAID_TRAIN_TOTAL, RAID_OLD_N)
    }
    shift = _find_shift(RAID_TRAIN_TOTAL, RAID_FINAL_N, [u1_offsets, old_offsets])
    final_offsets = _shifted_offsets(RAID_TRAIN_TOTAL, RAID_FINAL_N, shift)
    check(
        "final-test phase shift re-derives",
        shift == ft["phase_shift"],
        f"recomputed {shift} vs manifest {ft['phase_shift']}",
    )
    check(
        "final-test offsets sha256 re-derives",
        _sha256_text(json.dumps(final_offsets)) == ft["offsets_sha256"],
        f"{_sha256_text(json.dumps(final_offsets))[:12]} vs {ft['offsets_sha256'][:12]}",
    )
    check(
        "final-test offsets first/last 5",
        final_offsets[:5] == ft["offsets_first_5"] and final_offsets[-5:] == ft["offsets_last_5"],
        f"{final_offsets[:5]} / {final_offsets[-5:]}",
    )
    final_cache_path = CACHE_ROOT / "raid" / ft["config"] / ft["cache_filename"]
    check(
        "final-test cache sha256 matches manifest",
        _sha256_file(final_cache_path) == ft["cache_sha256"],
        f"{_sha256_file(final_cache_path)[:12]} vs {ft['cache_sha256'][:12]}",
    )
    check(
        "final-test cache sha256 matches artifact",
        _sha256_file(final_cache_path) == a_results["final_test"]["cache_sha256"],
        _sha256_file(final_cache_path)[:12],
    )
    check(
        "manifest top-up is null (n_human >= 100, no top-up fired)",
        ft.get("topup") is None,
        str(ft.get("topup")),
    )
    final_rows_raw = _load_cache_jsonl(final_cache_path)
    check(
        "final-test fetched rows == n_target",
        len(final_rows_raw) == RAID_FINAL_N,
        f"{len(final_rows_raw)} vs {RAID_FINAL_N}",
    )
    final_rows_pre, final_dupes = _dedupe_exact(final_rows_raw)

    # --- 3. Disjointness (independent content-hash set intersections) ---
    shared_val = _content_hashes(final_rows_pre) & _content_hashes(val_rows)
    check(
        "final-test disjoint from validation (content-hash sets)",
        len(shared_val) == 0,
        f"{len(shared_val)} shared hashes",
    )
    disjointness = [
        {
            "against": f"validation ({PRIOR_RUN})",
            "disjoint": len(shared_val) == 0,
            "verified": len(shared_val) == 0,
            "shared_samples": len(shared_val),
            "errors": [],
        }
    ]
    for target in EXTRA_TARGETS:
        other = CACHE_ROOT.joinpath(*target["cache_rel"])
        check(
            f"disjointness target sha {target['label']}",
            _sha256_file(other) == target["sha256"],
            _sha256_file(other)[:12],
        )
        other_rows = _load_cache_jsonl(other)
        shared_t = _content_hashes(final_rows_pre) & _content_hashes(other_rows)
        check(
            f"disjoint vs {target['label']} (content-hash sets)",
            len(shared_t) == 0,
            f"{len(shared_t)} shared hashes",
        )
        disjointness.append(
            {
                "against": target["label"],
                "disjoint": len(shared_t) == 0,
                "verified": len(shared_t) == 0,
                "shared_samples": len(shared_t),
                "errors": [],
            }
        )
    deep_compare("disjointness", disjointness, a_results["disjointness"])
    deep_compare("manifest.disjointness", disjointness, a_manifest.get("disjointness"))

    # --- 4. Leakage exclusions + near-duplicate report ---
    final_rows, exclusions, near_dup_report = _raid_leakage_checks(val_rows, final_rows_pre)
    final_counts = Counter(r["label"] for r in final_rows)
    deep_compare("exclusions", exclusions, a_results["exclusions"])
    deep_compare("near_duplicate_check", near_dup_report, a_results["near_duplicate_check"])
    deep_compare(
        "manifest.near_duplicate_check", near_dup_report, a_manifest.get("near_duplicate_check")
    )
    deep_compare("manifest.exclusions", exclusions, a_manifest.get("exclusions"))

    # --- 5. Fresh scoring (validation + final-test), determinism double-score ---
    detector = BuiltinHeuristicDetector()
    print(
        f"[raid] scoring validation ({len(val_rows)} rows) + final-test ({len(final_rows)} rows) ...",
        flush=True,
    )
    val_measured = measure_rows(detector, val_rows)
    final_measured = measure_rows(detector, final_rows)
    final_measured_again = measure_rows(detector, final_rows)
    deterministic = all(
        a["score"] == b["score"] and a["verdict"] == b["verdict"]
        for a, b in zip(final_measured, final_measured_again, strict=True)
    )
    check("determinism self-check (final-test scored twice)", deterministic)
    n_det_errors = sum(1 for m in final_measured if m["error"] is not None)
    check("final-test detection errors == 0", n_det_errors == 0, str(n_det_errors))
    deep_compare(
        "determinism_self_check",
        {
            "final_test_scored_twice": True,
            "n_rows": len(final_rows),
            "identical_scores_and_verdicts": deterministic,
        },
        a_results["determinism_self_check"],
    )

    # --- 6. Slices (primary + secondary) + worst slice ---
    val_primary, val_secondary = build_slices(val_measured)
    final_primary, final_secondary = build_slices(final_measured)
    worst = worst_human_slice(final_primary)
    for tag, measured in (
        ("final_test.pooled", final_measured),
        ("validation.pooled", val_measured),
    ):
        labelled = [m for m in measured if m["label"] is not None and m["error"] is None]
        labels = [m["label"] for m in labelled]
        scores = [m["score"] for m in labelled]
        pw = round(auroc_pairwise(labels, scores), 6)
        rk = round(auroc_rank(labels, scores), 6)
        ap_row = round(auprc_stepwise(labels, scores), 6)
        ap_grp = round(_auprc_tie_grouped(labels, scores), 6)
        cross_checks[tag] = {
            "auroc_pairwise": pw,
            "auroc_rank": rk,
            "auprc_per_row": ap_row,
            "auprc_tie_grouped": ap_grp,
        }
        check(f"{tag} AUROC pairwise == rank form", pw == rk, f"{pw} vs {rk}")
    deep_compare(
        "validation_remeasurement.slices_primary",
        val_primary,
        a_results["validation_remeasurement"]["slices_primary"],
    )
    deep_compare(
        "validation_remeasurement.slices_secondary",
        val_secondary,
        a_results["validation_remeasurement"]["slices_secondary"],
    )
    deep_compare(
        "final_test.slices_primary", final_primary, a_results["final_test"]["slices_primary"]
    )
    deep_compare(
        "final_test.slices_secondary", final_secondary, a_results["final_test"]["slices_secondary"]
    )
    deep_compare("final_test.worst_slice", worst, a_results["final_test"]["worst_slice"])

    # --- 7. Inclusion, reproduction check, manifest, seeds/gates, drops ---
    inclusion = {
        "validation_rows_in_cache": VAL_ROWS,
        "validation_rows_after_exact_dedupe": len(val_rows),
        "validation_label_counts": {
            str(k): v for k, v in sorted(val_counts.items(), key=lambda kv: str(kv[0]))
        },
        "final_test_rows_fetched": RAID_FINAL_N,
        "final_test_rows_after_exact_dedupe": len(final_rows) + len(exclusions),
        "final_test_rows_after_leakage_exclusions": len(final_rows),
        "final_test_label_counts": {
            str(k): v for k, v in sorted(final_counts.items(), key=lambda kv: str(kv[0]))
        },
        "final_test_exact_duplicates_dropped": len(final_dupes),
        "validation_exact_duplicates_dropped": len(val_dupes),
        "leakage_exclusions": len(exclusions),
    }
    deep_compare("inclusion", inclusion, a_results["inclusion"])
    deep_compare("manifest.inclusion", inclusion, a_manifest.get("inclusion"))
    val_pooled = val_primary[0]
    reproduction = {
        "prior_run": PRIOR_RUN,
        "prior_auroc": PRIOR_AUROC,
        "remeasured_auroc": val_pooled["auroc"]["value"] if val_pooled["auroc"] else None,
        "prior_tpr_at_fpr_0_01": PRIOR_TPR_AT_1PCT,
        "remeasured_tpr_at_fpr_0_01": val_pooled["tpr_at_fpr_0_01"]["value"]
        if val_pooled.get("tpr_at_fpr_0_01")
        else None,
        "prior_tpr_at_fpr_0_05": PRIOR_TPR_AT_5PCT,
        "remeasured_tpr_at_fpr_0_05": val_pooled["tpr_at_fpr_0_05"]["value"]
        if val_pooled.get("tpr_at_fpr_0_05")
        else None,
        "note": "Same frozen rows re-measured on the W7 code (17b8951 lineage); "
        "AUROC/TPR@FPR are threshold-free so small differences come only from "
        "code changes between the prior run and this run, not from tuning.",
    }
    deep_compare(
        "validation_remeasurement.reproduction_check",
        reproduction,
        a_results["validation_remeasurement"]["reproduction_check"],
    )
    compare(
        "validation_remeasurement.prior_run",
        PRIOR_RUN,
        a_results["validation_remeasurement"]["prior_run"],
    )
    compare(
        "validation_remeasurement.cache_sha256",
        VAL_SHA256,
        a_results["validation_remeasurement"]["cache_sha256"],
    )
    compare("manifest.sha256", manifest_sha, a_results["manifest"]["sha256"])
    compare(
        "manifest.path",
        f"docs/evidence/manifests/{a_manifest_path.name}",
        a_results["manifest"]["path"],
    )
    deep_compare("seeds", {"bootstrap_seed": BOOTSTRAP_SEED}, a_results["seeds"])
    deep_compare(
        "predeclared_gates",
        {"min_n_human": MIN_N_HUMAN, "fpr_wilson_upper_max": FPR_UPPER_MAX},
        a_results["predeclared_gates"],
    )
    deep_compare("environment_lock", _env_lock(REPO_ROOT), a_results["environment_lock"])
    drops = [
        {
            "item": "full-corpus evaluation",
            "reason": f"sample only: validation n={VAL_ROWS} + final-test "
            f"n={len(final_rows)} normalised rows from {RAID_TRAIN_TOTAL} split rows",
        },
        {
            "item": "Python 3.11, 3.13, 3.14, 3.15",
            "reason": "measured on the local interpreter only; CI covers the matrix",
        },
        {
            "item": "train/test threshold selection",
            "reason": "no threshold was fitted on any sample; AUROC/TPR@FPR are "
            "threshold-free and the native verdict has no threshold",
        },
        {
            "item": "train/dev/selection/fit partitions",
            "reason": "empty by design — nothing is fitted, calibrated or selected",
        },
        {
            "item": "raid_test/test (50 rows)",
            "reason": "unlabelled in the CSV distribution (label None on every row): "
            "coverage/abstention probe and disjointness target only, never scored as a class",
        },
        {
            "item": "RAID extra split (2,039,100 rows) and non-train domains",
            "reason": "not evaluated in this wave: the served train split holds 4 domains "
            "(abstracts/books/news/poetry); other domains and non-English (Czech/German) "
            "material live in extra/test and are an explicit coverage gap",
        },
        {
            "item": f"{len(exclusions)} leakage-excluded final-test rows",
            "reason": "human-source overlap / near-duplicate vs validation (see exclusions)",
        },
    ]
    drops += val_dupes + final_dupes
    deep_compare("drops", drops, a_artifact.get("drops"))

    n_agree = sum(1 for c in comparison if c["agree"])
    print(
        f"comparison: {n_agree}/{len(comparison)} fields agree; {len(discrepancies)} discrepancies",
        flush=True,
    )
    for d in discrepancies:
        print(
            f"  DISCREPANCY {d['field']}: reproduction={d['reproduction']} worker_a={d['worker_a']}",
            flush=True,
        )
    n_checks_pass = sum(1 for c in checks if c["passed"])
    print(f"identity checks: {n_checks_pass}/{len(checks)} pass", flush=True)
    for c in checks:
        if not c["passed"]:
            print(f"  FAILED CHECK {c['check']}: {c['detail']}", flush=True)
    all_checks_pass = all(c["passed"] for c in checks)
    verdict = "AGREE" if (not discrepancies and all_checks_pass) else "DISCREPANCY"
    print(f"reproduction verdict: {verdict}", flush=True)

    if args.check:
        print("check mode: no artifact file written")
        return 0 if verdict == "AGREE" else 1

    output = (
        Path(args.output)
        if args.output
        else (REPO_ROOT / "docs" / "evidence" / "runs" / f"{ARTIFACT_ID}.json")
    )
    environment_extras = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, check=True
    ).stdout.strip()
    artifact = {
        "schema": RUN_ARTIFACT_SCHEMA,
        "evidence_record_id": ARTIFACT_ID,
        "kind": "command",
        "command": "python scripts/reproduce_w8a_raid.py",
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
            "extras": environment_extras,
        },
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "reproduces": "EV-20261116-dataset-raid",
            "reproduces_artifact_sha256": a_sha,
            "reproduces_artifact_code_version": a_artifact.get("code_version"),
            "reproduces_manifest": "EV-20261116-raid-manifest.json",
            "reproduces_manifest_sha256": manifest_sha,
            "detector": "textforensics/builtin-heuristic",
            "detector_family": "stylometric-heuristic",
            "detector_version": "0.1.0",
            "operating_point": "builtin-heuristic native verdict (analyze_text); no score threshold",
            "method": (
                "Independent reproduction: frozen validation cache and final-test "
                "cache read directly as JSONL with SHA-256 verification; offset "
                "grid re-derived (smallest disjoint shift); content-hash "
                "disjointness checked by independent direct set intersection; "
                "RAID leakage exclusions re-derived (same-human-source rule and "
                "word-8-gram Jaccard > 0.8); detector re-run fresh at its native "
                "operating point, twice for determinism; every slice recomputed "
                "with Worker A's exact slice definitions, Wilson FPR/TPR from "
                "my own formula implementation, bootstrap CIs from a fresh "
                "Random(20261116) per call with randrange resampling (Worker A's "
                "convention), cluster-bootstrap FPR where k_fp > 0. AUROC point "
                "values cross-checked pairwise vs rank; AUPRC cross-checked in "
                "the tie-grouped form alongside. No tuning on the final holdout."
            ),
            "identity_checks": checks,
            "auroc_auprc_cross_checks": cross_checks,
            "validation": {
                "cache_sha256": VAL_SHA256,
                "rows_in_cache": len(val_rows_raw),
                "rows_after_dedupe": len(val_rows),
                "label_counts": {
                    str(k): v for k, v in sorted(val_counts.items(), key=lambda kv: str(kv[0]))
                },
                "exact_duplicates_dropped": len(val_dupes),
                "pooled": val_primary[0],
            },
            "final_test": {
                "cache_sha256": _sha256_file(final_cache_path),
                "rows_fetched": RAID_FINAL_N,
                "rows_after_dedupe": len(final_rows) + len(exclusions),
                "rows_after_exclusions": len(final_rows),
                "label_counts": {
                    str(k): v for k, v in sorted(final_counts.items(), key=lambda kv: str(kv[0]))
                },
                "exact_duplicates_dropped": len(final_dupes),
                "leakage_exclusions": len(exclusions),
                "phase_shift": shift,
                "offsets_sha256": _sha256_text(json.dumps(final_offsets)),
                "pooled": final_primary[0],
                "worst_slice": worst,
                "slices_primary": final_primary,
                "slices_secondary": final_secondary,
            },
            "deterministic": deterministic,
            "comparison": comparison,
            "discrepancies": discrepancies,
            "verdict": verdict,
        },
        "drops": [
            {
                "item": "Worker A fit/dev/selection partitions",
                "reason": "empty by design — nothing is fitted, calibrated or selected",
            },
            {
                "item": "RAID extra split and non-train domains",
                "reason": "not evaluated in this wave; see the reproduced artifact's drops",
            },
        ],
        "badge": "available",
        "detector_version": "0.1.0",
        "notes": (
            "Independent reproduction of Worker A's RAID qualification. Every "
            "compared field either agrees exactly or is listed in "
            "'discrepancies'. "
            f"Reproduction verdict: {verdict}. Pooled final-test holdout as "
            "re-measured here: human FPR "
            f"{final_primary[0]['fpr_native']['k']}/{final_primary[0]['fpr_native']['n']} "
            f"(Wilson 95% upper {final_primary[0]['fpr_native']['ci_upper']}) and native TPR "
            f"{final_primary[0]['tpr_native']['k']}/{final_primary[0]['tpr_native']['n']}. "
            "A below-chance ranking result is reported as measured, not "
            "tuned around. The native operating point is unchanged."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)[:12]}...)")
    return 0 if verdict == "AGREE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
