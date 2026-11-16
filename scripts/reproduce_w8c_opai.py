#!/usr/bin/env python3
"""reproduce_w8c_opai.py — W8 worker E (independent reproduction).

Independently reproduces Worker C's OpAI-Bench partitioned evaluation
(docs/evidence/runs/EV-20261116-dataset-opai-bench.json) from scratch.

Source: the INTEGRATED copies on audit-w7 in the main clone
(~/workspace/TextForensics-rewrite, head 0495d96); Worker C's branch
and worktree were deleted after integration. Earlier worktree versions
of the artifact/manifest had different SHAs (the artifact was
regenerated during integration, e.g. pre-commit formatting); this
script verifies the integrated files, not the deleted worktree copies.

- Reads the two pinned cache files DIRECTLY (json, no dataset-loader
  helpers, no import of Worker C's script, no import of
  scripts/measure_datasets.py).
- Re-derives the partition from the frozen rule (sha256(group_key)
  mod 10; buckets 0-2 fit, 3-4 dev, 5-9 final-test) for every pooled
  row and checks it against Worker C's frozen manifest row by row.
- Verifies cache file SHA-256s, per-row content hashes, label and
  slice identity, pooled content-disjointness, and final-test vs dev
  split content-disjointness.
- Re-scores the 293 final-test labelled rows with a fresh
  BuiltinHeuristicDetector at its native operating point.
- Recomputes every reported metric with INDEPENDENT implementations
  written here (Wilson interval from the formula; AUROC by pairwise
  Mann-Whitney counting, not the rank method; stepwise average
  precision; TPR@FPR by the documented distinct-threshold convention;
  cluster bootstrap over document groups, seed 20261116, 1000
  resamples, following the documented procedure).
- Compares every field of Worker C's artifact evaluation against the
  recomputation and reports agreement or ANY discrepancy, however
  small. A discrepancy is a finding, not something to smooth over.

Usage:
    python scripts/reproduce_w8c_opai.py [--check]
    python scripts/reproduce_w8c_opai.py --output <path>

--check measures and compares only; it writes nothing.
The default output is docs/evidence/runs/EV-20261116-reproduction-opai-bench.json.
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
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-reproduction-opai-bench"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
# Host-neutral: the worker checkout the paths used to name is gone;
# the artifacts live at these repo-relative paths on every checkout.
C_MANIFEST = (
    REPO_ROOT / "docs" / "evidence" / "manifests" / "EV-20261116-dataset-opai-bench-partitions.json"
)
C_ARTIFACT = REPO_ROOT / "docs" / "evidence" / "runs" / "EV-20261116-dataset-opai-bench.json"
CACHE_ROOT = Path.home() / ".cache" / "textforensics" / "datasets" / "opai_bench" / "default"
BOOTSTRAP_SEED = 20261116
BOOTSTRAP_RESAMPLES = 1000
Z_95 = 1.96


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    """Content hash per the repo benchmark construction
    (textforensics.benchmark._compute_sample_hashes, as documented in
    Worker C's script): sha256 of the compact JSON {"text": text}."""
    content = json.dumps({"text": text}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _code_version() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def _round6(value: float | None) -> float | None:
    return None if value is None else round(float(value), 6)


# --- Independent metric implementations (written here, from definitions) ---


def wilson(k: int, n: int, *, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval, 95%. Formula: centre +- half, clamped [0,1]."""
    if n < 1 or not 0 <= k <= n:
        raise ValueError(f"wilson needs 0 <= k <= n, n >= 1, got k={k} n={n}")
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def auroc_pairwise(labels: list[int], scores: list[float]) -> float:
    """AUROC by direct pairwise Mann-Whitney counting: P(ai > human)
    + 0.5 * P(ai == human). O(n_pos * n_neg); n <= 293 here."""
    pos = [s for lab, s in zip(labels, scores, strict=True) if lab == 1]
    neg = [s for lab, s in zip(labels, scores, strict=True) if lab == 0]
    if not pos or not neg:
        raise ValueError("auroc needs both classes present")
    wins = ties = 0
    for a in pos:
        for b in neg:
            if a > b:
                wins += 1
            elif a == b:
                ties += 1
    return (wins + 0.5 * ties) / (len(pos) * len(neg))


def average_precision(labels: list[int], scores: list[float]) -> float:
    """Stepwise average precision (sklearn convention): sum over recall
    steps of (recall gain * precision at that step), scores descending."""
    n_pos = sum(labels)
    if n_pos == 0 or n_pos == len(labels):
        raise ValueError("average_precision needs both classes present")
    order = sorted(range(len(labels)), key=lambda i: -scores[i])
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    for idx in order:
        if labels[idx] == 1:
            tp += 1
        else:
            fp += 1
        recall = tp / n_pos
        precision = tp / (tp + fp)
        ap += (recall - prev_recall) * precision
        prev_recall = recall
    return ap


def tpr_at_fpr(labels: list[int], scores: list[float], target: float) -> float:
    """Max TPR among distinct-score thresholds (score >= t predicts
    machine) with empirical FPR <= target; 0.0 if none qualifies."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("tpr_at_fpr needs both classes present")
    pairs = sorted(zip(scores, labels, strict=True), reverse=True)
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
        if fp / n_neg <= target and tp / n_pos > best:
            best = tp / n_pos
    return best


def cluster_bootstrap(
    metric: str, labels: list[int], scores: list[float], group_ids: list[str]
) -> dict:
    """Cluster bootstrap 95% CI, following the documented procedure:
    resample document groups (sorted keys) with replacement, each
    sampled group contributing all its rows; 1000 resamples, seed
    20261116; percentile interval at 2.5%/97.5% with the documented
    index convention; resamples missing a class are skipped/counted."""

    def metric_on(lab, sco):
        if metric == "auroc":
            return auroc_pairwise(lab, sco)
        if metric == "auprc":
            return average_precision(lab, sco)
        if metric == "tpr_at_1pct_fpr":
            return tpr_at_fpr(lab, sco, 0.01)
        if metric == "tpr_at_5pct_fpr":
            return tpr_at_fpr(lab, sco, 0.05)
        raise ValueError(metric)

    point = metric_on(labels, scores)
    groups: dict[str, list[int]] = defaultdict(list)
    for idx, gid in enumerate(group_ids):
        groups[gid].append(idx)
    keys = sorted(groups)
    rng = random.Random(BOOTSTRAP_SEED)
    values: list[float] = []
    skipped = 0
    for _ in range(BOOTSTRAP_RESAMPLES):
        chosen = [rng.choice(keys) for _ in keys]
        idxs = [i for key in chosen for i in groups[key]]
        sub_labels = [labels[i] for i in idxs]
        sub_scores = [scores[i] for i in idxs]
        if sum(sub_labels) == 0 or sum(sub_labels) == len(sub_labels):
            skipped += 1
            continue
        values.append(metric_on(sub_labels, sub_scores))
    if not values:
        raise ValueError(f"cluster bootstrap for {metric}: every resample missed a class")
    values.sort()
    lo = values[int(0.025 * len(values))]
    hi = values[int(0.975 * len(values)) - 1 if len(values) > 1 else 0]
    return {
        "value": round(point, 4),
        "ci_lower": round(lo, 4),
        "ci_upper": round(hi, 4),
        "resamples": len(values),
        "resamples_skipped_no_class": skipped,
    }


def partition_of(group_key: str) -> str:
    bucket = int(hashlib.sha256(group_key.encode("utf-8")).hexdigest(), 16) % 10
    if bucket in (0, 1, 2):
        return "fit"
    if bucket in (3, 4):
        return "dev"
    return "final-test"


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


def slice_metrics(slice_id: str, labels, scores, verdicts, group_ids) -> dict:
    n_human = sum(1 for lab in labels if lab == 0)
    n_ai = sum(1 for lab in labels if lab == 1)
    k_fp = sum(1 for lab, v in zip(labels, verdicts, strict=True) if lab == 0 and v == "ai_like")
    k_tp = sum(1 for lab, v in zip(labels, verdicts, strict=True) if lab == 1 and v == "ai_like")
    abstentions = sum(1 for v in verdicts if v == "abstain")

    def rate(k, n):
        lo, hi = wilson(k, n)
        return {
            "k": k,
            "n": n,
            "value": round(k / n, 4),
            "ci_lower": round(lo, 4),
            "ci_upper": round(hi, 4),
        }

    out = {
        "slice_id": slice_id,
        "n_human": n_human,
        "n_ai": n_ai,
        "n_human_groups": len({g for lab, g in zip(labels, group_ids, strict=True) if lab == 0}),
        "n_ai_groups": len({g for lab, g in zip(labels, group_ids, strict=True) if lab == 1}),
        "fpr_native": rate(k_fp, n_human),
        "tpr_native": rate(k_tp, n_ai),
        "coverage": round(1 - abstentions / len(labels), 4) if labels else 0.0,
        "abstention_rate": round(abstentions / len(labels), 4) if labels else 0.0,
        "abstentions": abstentions,
        "score_by_label": {
            "human": score_summary([s for lab, s in zip(labels, scores, strict=True) if lab == 0]),
            "machine": score_summary(
                [s for lab, s in zip(labels, scores, strict=True) if lab == 1]
            ),
        },
    }
    if min(n_human, n_ai) >= 10:
        for metric in ("auroc", "auprc", "tpr_at_1pct_fpr", "tpr_at_5pct_fpr"):
            out[metric] = cluster_bootstrap(metric, labels, scores, group_ids)
    return out


def load_cache_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true", help="measure and compare only; write nothing"
    )
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    manifest = json.loads(C_MANIFEST.read_text(encoding="utf-8"))
    c_artifact = json.loads(C_ARTIFACT.read_text(encoding="utf-8"))
    c_eval = c_artifact["results"]["evaluation"]
    manifest_sha = _sha256_file(C_MANIFEST)
    c_artifact_sha = _sha256_file(C_ARTIFACT)

    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(ok), "detail": str(detail)})
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")

    # --- 1. Cache files: SHA-256 vs manifest sources ---
    cache_by_file: dict[str, list[dict]] = {}
    for source in manifest["sources"]:
        path = CACHE_ROOT / source["cache_file"]
        actual_sha = _sha256_file(path)
        check(
            f"cache sha256 {source['cache_file']}",
            actual_sha == source["file_sha256"],
            f"{actual_sha[:12]}... vs manifest {source['file_sha256'][:12]}...",
        )
        rows = load_cache_jsonl(path)
        check(
            f"cache row count {source['cache_file']}",
            len(rows) == source["rows"],
            f"{len(rows)} vs {source['rows']}",
        )
        cache_by_file[source["cache_file"]] = rows

    by_source: dict[str, dict] = {}
    for _fname, rows in cache_by_file.items():
        for r in rows:
            by_source[r["source_id"]] = r
    check(
        "manifest rows all resolve to a cache row",
        all(m["source_id"] in by_source for m in manifest["rows"]),
        f"{len(manifest['rows'])} manifest rows",
    )

    # --- 2. Per-row identity: label, content hash, group key, slice, partition ---
    mismatches = {
        "label": 0,
        "content_hash": 0,
        "group_key": 0,
        "slice": 0,
        "partition": 0,
        "cache_file": 0,
    }
    for m in manifest["rows"]:
        r = by_source.get(m["source_id"])
        if r is None:
            continue
        if r["label"] != m["label"]:
            mismatches["label"] += 1
        if _sha256_text(r["text"]) != m["content_hash"]:
            mismatches["content_hash"] += 1
        if str(r["meta"]["document_hash_id"]) != m["group_key"]:
            mismatches["group_key"] += 1
        if str(r["meta"].get("domain")) != m["slice"]:
            mismatches["slice"] += 1
        if partition_of(m["group_key"]) != m["partition"]:
            mismatches["partition"] += 1
    for field, count in mismatches.items():
        check(
            f"manifest {field} matches cache/rule for all rows",
            count == 0,
            f"{count} mismatches / {len(manifest['rows'])} rows",
        )

    # Partition counts vs manifest counts and vs C artifact.
    counts: dict[str, dict] = {}
    for m in manifest["rows"]:
        c = counts.setdefault(
            m["partition"], {"rows": 0, "n_human": 0, "n_ai": 0, "n_unlabelled": 0}
        )
        c["rows"] += 1
        if m["label"] == 0:
            c["n_human"] += 1
        elif m["label"] == 1:
            c["n_ai"] += 1
        else:
            c["n_unlabelled"] += 1
    check(
        "partition counts match manifest counts",
        counts == manifest["counts"],
        json.dumps(counts, sort_keys=True),
    )
    check(
        "partition manifest sha matches artifact record",
        manifest_sha == c_artifact["results"]["partition"]["manifest_sha256"],
        f"{manifest_sha[:12]} vs {c_artifact['results']['partition']['manifest_sha256'][:12]}",
    )

    # Group leakage: no document group spans two partitions.
    group_partitions: dict[str, set] = defaultdict(set)
    for m in manifest["rows"]:
        group_partitions[m["group_key"]].add(m["partition"])
    spanning = {g: sorted(p) for g, p in group_partitions.items() if len(p) > 1}
    check(
        "no document group spans two partitions",
        not spanning,
        f"{len(group_partitions)} groups, {len(spanning)} spanning",
    )
    # "89 groups span the two pooled samples" = 89 document groups occur
    # in BOTH pooled samples (U1 train + train-2000); total distinct
    # groups across the pool is 2216.
    groups_u1 = {m["group_key"] for m in manifest["rows"] if m["cache_file"] == "train.jsonl"}
    groups_2000 = {
        m["group_key"] for m in manifest["rows"] if m["cache_file"] == "train-2000.jsonl"
    }
    check(
        "89 document groups occur in both pooled samples (as stated)",
        len(groups_u1 & groups_2000) == 89,
        f"intersection={len(groups_u1 & groups_2000)}, union={len(group_partitions)}",
    )

    # --- 3. Content disjointness ---
    hashes_u1 = {_sha256_text(r["text"]) for r in cache_by_file["train.jsonl"]}
    hashes_2000 = {_sha256_text(r["text"]) for r in cache_by_file["train-2000.jsonl"]}
    check(
        "pooled samples content-disjoint (U1 vs train-2000)",
        not (hashes_u1 & hashes_2000),
        f"{len(hashes_u1 & hashes_2000)} shared hashes",
    )
    dev_rows = load_cache_jsonl(CACHE_ROOT / "dev.jsonl")
    dev_hashes = {_sha256_text(r["text"]) for r in dev_rows}
    final_rows_manifest = [m for m in manifest["rows"] if m["partition"] == "final-test"]
    final_hashes = {m["content_hash"] for m in final_rows_manifest}
    check(
        "final-test disjoint from dev split by content hash",
        not (final_hashes & dev_hashes),
        f"{len(final_hashes & dev_hashes)} shared hashes",
    )

    # --- 4. U1 registry reproduction check (fail-closed identity check) ---
    detector = BuiltinHeuristicDetector()
    u1_labelled = [r for r in cache_by_file["train.jsonl"] if r["label"] is not None]
    u1_verdicts = [detector.detect(r["text"]).verdict for r in u1_labelled]
    u1_counts = {
        "n_human": sum(1 for r in u1_labelled if r["label"] == 0),
        "n_ai": sum(1 for r in u1_labelled if r["label"] == 1),
        "abstentions": sum(1 for v in u1_verdicts if v == "abstain"),
    }
    check(
        "U1 registry counts reproduce (56 human / 55 AI / 55 abstentions)",
        u1_counts == {"n_human": 56, "n_ai": 55, "abstentions": 55},
        json.dumps(u1_counts),
    )

    # --- 5. Score the final-test labelled rows ---
    final_labelled = [m for m in final_rows_manifest if m["label"] is not None]
    scored = []
    for m in final_labelled:
        r = by_source[m["source_id"]]
        pred = detector.detect(r["text"])
        scored.append(
            {
                "source_id": m["source_id"],
                "label": int(m["label"]),
                "score": float(pred.score),
                "reliability": float(pred.reliability),
                "verdict": str(pred.verdict),
                "group": m["group_key"],
                "domain": str(r["meta"].get("domain")),
                "generator": str(r["meta"].get("generator")),
            }
        )
    check(
        "final-test labelled count is 293 (146 human / 147 AI)",
        len(scored) == 293
        and sum(1 for s in scored if s["label"] == 0) == 146
        and sum(1 for s in scored if s["label"] == 1) == 147,
        f"n={len(scored)}",
    )

    # --- 6. Recompute slices exactly as Worker C grouped them ---
    human_rows = [s for s in scored if s["label"] == 0]
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for item in scored:
        by_domain[item["domain"]].append(item)
    groupings: dict[str, list[dict]] = {"pooled": scored, **dict(by_domain)}
    for generator in sorted({s["generator"] for s in scored if s["label"] == 1}):
        groupings[f"generator-{generator}"] = human_rows + [
            s for s in scored if s["label"] == 1 and s["generator"] == generator
        ]
    recomputed: dict[str, dict] = {}
    for name, items in sorted(groupings.items()):
        recomputed[name] = slice_metrics(
            f"opai-bench-{name}",
            labels=[i["label"] for i in items],
            scores=[i["score"] for i in items],
            verdicts=[i["verdict"] for i in items],
            group_ids=[i["group"] for i in items],
        )
    # Worst slice: highest Wilson FPR upper among slices with n_human >= 10.
    # Ties keep the first slice in sorted-grouping order (stable sort by
    # the upper bound only, exactly as Worker C's summarize_slices does).
    ranked = [
        (m["fpr_native"]["ci_upper"], name) for name, m in recomputed.items() if m["n_human"] >= 10
    ]
    ranked.sort(key=lambda t: t[0], reverse=True)
    worst = (
        {
            "slice_id": ranked[0][1],
            "fpr_wilson_upper": ranked[0][0],
            "n_human": recomputed[ranked[0][1]]["n_human"],
        }
        if ranked
        else None
    )

    # --- 7. Field-by-field comparison against Worker C's artifact ---
    comparison: list[dict] = []
    discrepancies: list[dict] = []

    def compare(path: str, mine, theirs) -> None:
        same = mine == theirs
        comparison.append({"field": path, "reproduction": mine, "worker_c": theirs, "agree": same})
        if not same:
            discrepancies.append({"field": path, "reproduction": mine, "worker_c": theirs})

    compare("evaluation.n_final_test_labelled", len(scored), c_eval["n_final_test_labelled"])
    compare("evaluation.worst_slice", worst, c_eval["worst_slice"])
    for name in sorted(set(recomputed) | set(c_eval["slices"])):
        mine = recomputed.get(name)
        theirs = c_eval["slices"].get(name)
        if mine is None or theirs is None:
            compare(f"slices.{name}.present", mine is not None, theirs is not None)
            continue
        for field in (
            "slice_id",
            "n_human",
            "n_ai",
            "n_human_groups",
            "n_ai_groups",
            "coverage",
            "abstention_rate",
            "abstentions",
        ):
            compare(f"slices.{name}.{field}", mine[field], theirs[field])
        for rate in ("fpr_native", "tpr_native"):
            for sub in ("k", "n", "value", "ci_lower", "ci_upper"):
                compare(f"slices.{name}.{rate}.{sub}", mine[rate][sub], theirs[rate][sub])
        for lab in ("human", "machine"):
            for sub in ("n", "mean", "median", "min", "max"):
                compare(
                    f"slices.{name}.score_by_label.{lab}.{sub}",
                    mine["score_by_label"][lab][sub],
                    theirs["score_by_label"][lab][sub],
                )
        for metric in ("auroc", "auprc", "tpr_at_1pct_fpr", "tpr_at_5pct_fpr"):
            for sub in ("value", "ci_lower", "ci_upper", "resamples", "resamples_skipped_no_class"):
                compare(f"slices.{name}.{metric}.{sub}", mine[metric][sub], theirs[metric][sub])
    n_agree = sum(1 for c in comparison if c["agree"])
    print(
        f"comparison: {n_agree}/{len(comparison)} fields agree; {len(discrepancies)} discrepancies"
    )
    for d in discrepancies:
        print(
            f"  DISCREPANCY {d['field']}: reproduction={d['reproduction']} worker_c={d['worker_c']}"
        )

    all_checks_pass = all(c["passed"] for c in checks)
    verdict = "AGREE" if (not discrepancies and all_checks_pass) else "DISCREPANCY"
    print(f"reproduction verdict: {verdict}")

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
        "command": "python scripts/reproduce_w8c_opai.py",
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
            "extras": environment_extras,
        },
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "reproduces": "EV-20261116-dataset-opai-bench",
            "reproduces_artifact_sha256": c_artifact_sha,
            "reproduces_manifest": "EV-20261116-dataset-opai-bench-partitions.json",
            "reproduces_manifest_sha256": manifest_sha,
            "detector": "textforensics/builtin-heuristic",
            "detector_family": "stylometric-heuristic",
            "detector_version": "0.1.0",
            "operating_point": "builtin-heuristic native verdict (analyze_text); no score threshold",
            "method": (
                "Independent reproduction: cache files read directly as JSONL; partition "
                "re-derived row by row from sha256(group_key) mod 10; detector re-run on "
                "the 293 final-test labelled rows; Wilson/AUROC (pairwise Mann-Whitney)/"
                "AUPRC/TPR@FPR/cluster-bootstrap recomputed from scratch with independent "
                "implementations in this script. No tuning on the final holdout."
            ),
            "identity_checks": checks,
            "u1_registry_reproduction": u1_counts,
            "partition_counts": counts,
            "group_count": len(group_partitions),
            "groups_in_both_pooled_samples": len(groups_u1 & groups_2000),
            "groups_spanning_partitions": spanning,
            "evaluation": {
                "slices": recomputed,
                "worst_slice": worst,
                "n_final_test_labelled": len(scored),
            },
            "comparison": comparison,
            "discrepancies": discrepancies,
            "verdict": verdict,
        },
        "drops": [
            {
                "item": "Worker C fit/dev partitions",
                "reason": "reproduction scores the final-test holdout only; fit/dev rows are "
                "verified for identity and partition correctness but not scored",
            },
            {
                "item": "Partial (mixed-origin) rows",
                "reason": "rows with 0 < ai_sentence_ratio < 1 carry no binary label; "
                "excluded from binary metrics, as in Worker C's artifact",
            },
        ],
        "badge": "available",
        "detector_version": "0.1.0",
        "notes": (
            "Independent reproduction of Worker C's OpAI-Bench partitioned evaluation. "
            "Every compared field either agrees exactly or is listed in 'discrepancies'. "
            "Reproduction verdict: "
            f"{verdict}. Pooled final-test holdout as re-measured here: human FPR "
            f"{recomputed['pooled']['fpr_native']['k']}/{recomputed['pooled']['fpr_native']['n']} "
            f"(Wilson 95% upper {recomputed['pooled']['fpr_native']['ci_upper']}) and native TPR "
            f"{recomputed['pooled']['tpr_native']['k']}/{recomputed['pooled']['tpr_native']['n']}. "
            "A below-chance ranking result is reported as measured, not tuned around."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)[:12]}...)")
    return 0 if verdict == "AGREE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
