#!/usr/bin/env python3
"""reproduce_w8c_ghostwriter.py — W8 worker E (independent reproduction).

Independently reproduces Worker C's GhostWriter partitioned evaluation
(docs/evidence/runs/EV-20261116-dataset-ghostwriter.json) from scratch.

Source: the INTEGRATED copies on audit-w7 in the main clone
(~/workspace/TextForensics-rewrite, head 0495d96); Worker C's branch
and worktree were deleted after integration. Earlier worktree versions
of the artifact/manifest had different SHAs (the artifact was
regenerated during integration, e.g. pre-commit formatting and the
threshold-sensitivity attribution correction); this script verifies
the integrated files, not the deleted worktree copies.

- Reads the two pinned cache files DIRECTLY (json, no dataset-loader
  helpers, no import of Worker C's script, no import of
  scripts/measure_datasets.py).
- Re-derives the content-dedup (2 dropped duplicates) and verifies the
  2 fetch-time exclusions recorded in train-2000.excluded.json.
- Recomputes the near-duplicate grouping INDEPENDENTLY (union-find
  over exact content hashes merged at word-8-shingle Jaccard >= 0.8,
  following the documented procedure including the >100-row shingle
  skip and the exact union order) and checks the per-row group key
  against Worker C's frozen manifest row by row.
- Re-derives the partition from the frozen rule (sha256(group_key)
  mod 10; buckets 0-2 fit, 3-4 dev, 5-9 final-test) for every pooled
  row and checks it against the manifest; verifies no group spans two
  partitions and that final-test is content-disjoint from the
  validation split cache.
- Re-runs the U1 registry reproduction check (137 human / 210 AI /
  162 abstentions) and re-scores the 861 final-test labelled rows
  with a fresh BuiltinHeuristicDetector at its native operating point.
- Recomputes every reported metric with INDEPENDENT implementations
  (Wilson interval from the formula; AUROC by pairwise Mann-Whitney
  counting; stepwise average precision; TPR@FPR by the documented
  distinct-threshold convention; cluster bootstrap over near-duplicate
  groups, seed 20261116, 1000 resamples) plus the threshold
  sensitivity on the final-test human rows (native 0.68, floor 0.28,
  perturbed 0.66/0.68/0.70).
- Compares every field of Worker C's artifact evaluation against the
  recomputation and reports agreement or ANY discrepancy, however
  small. A discrepancy is a finding, not something to smooth over.

Usage:
    python scripts/reproduce_w8c_ghostwriter.py [--check]
    python scripts/reproduce_w8c_ghostwriter.py --output <path>

--check measures and compares only; it writes nothing.
The default output is docs/evidence/runs/EV-20261116-reproduction-ghostwriter.json.
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
ARTIFACT_ID = "EV-20261116-reproduction-ghostwriter"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
C_MANIFEST = Path("/home/hatch/workspace/TextForensics-rewrite/docs/evidence/manifests/EV-20261116-dataset-ghostwriter-partitions.json")
C_ARTIFACT = Path("/home/hatch/workspace/TextForensics-rewrite/docs/evidence/runs/EV-20261116-dataset-ghostwriter.json")
CACHE_ROOT = Path.home() / ".cache" / "textforensics" / "datasets" / "ghostwriter" / "default"
BOOTSTRAP_SEED = 20261116
BOOTSTRAP_RESAMPLES = 1000
Z_95 = 1.96
NATIVE_THRESHOLD = 0.68
PERTURBED_THRESHOLDS = (0.66, 0.68, 0.70)
RELIABILITY_FLOOR = 0.28


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _content_hash(text: str) -> str:
    """Content hash per the repo benchmark construction: sha256 of the
    compact JSON {"text": text}."""
    content = json.dumps(
        {"text": text}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _code_version() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


# --- Independent metric implementations (written here, from definitions) ---

def wilson(k: int, n: int, *, z: float = Z_95) -> tuple[float, float]:
    if n < 1 or not 0 <= k <= n:
        raise ValueError(f"wilson needs 0 <= k <= n, n >= 1, got k={k} n={n}")
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def auroc_pairwise(labels: list[int], scores: list[float]) -> float:
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


def cluster_bootstrap(metric: str, labels: list[int], scores: list[float],
                      group_ids: list[str]) -> dict:
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
        if n == 0:
            return {"k": k, "n": 0, "value": None, "ci_lower": None, "ci_upper": None,
                    "not_computed": "no rows of this class in the slice"}
        lo, hi = wilson(k, n)
        return {"k": k, "n": n, "value": round(k / n, 4),
                "ci_lower": round(lo, 4), "ci_upper": round(hi, 4)}

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
            "machine": score_summary([s for lab, s in zip(labels, scores, strict=True) if lab == 1]),
        },
    }
    if min(n_human, n_ai) >= 10:
        for metric in ("auroc", "auprc", "tpr_at_1pct_fpr", "tpr_at_5pct_fpr"):
            out[metric] = cluster_bootstrap(metric, labels, scores, group_ids)
    else:
        out["ranking_metrics"] = None
        out["ranking_metrics_not_computed"] = (
            f"both classes need >= 10 rows; n_human={n_human}, n_ai={n_ai}"
        )
    return out


def threshold_sensitivity(human_scores, human_reliabilities) -> dict:
    n = len(human_scores)
    entries = []
    for threshold in PERTURBED_THRESHOLDS:
        k = sum(1 for s, r in zip(human_scores, human_reliabilities, strict=True)
                if s >= threshold and r >= RELIABILITY_FLOOR)
        if n == 0:
            entries.append({"threshold": threshold, "k": k, "n": 0, "rate": None,
                            "ci_lower": None, "ci_upper": None,
                            "not_computed": "no human rows in the slice"})
            continue
        lo, hi = wilson(k, n)
        entries.append({"threshold": threshold, "k": k, "n": n,
                        "rate": round(k / n, 4), "ci_lower": round(lo, 4), "ci_upper": round(hi, 4)})
    return {
        "native_threshold": NATIVE_THRESHOLD,
        "reliability_floor": RELIABILITY_FLOOR,
        "max_human_score": round(max(human_scores), 4) if human_scores else None,
        "within_below_threshold": {
            str(delta): sum(1 for s in human_scores if NATIVE_THRESHOLD - delta <= s < NATIVE_THRESHOLD)
            for delta in (0.01, 0.02, 0.05)
        },
        "human_scores_at_or_above_threshold": sum(1 for s in human_scores if s >= NATIVE_THRESHOLD),
        "sensitivity": entries,
    }


# --- Near-duplicate grouping (independent implementation of the documented procedure) ---

def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


def _word_shingles(normalized: str, k: int = 8) -> set[str]:
    words = normalized.split()
    if len(words) < k:
        return set()
    return {" ".join(words[i:i + k]) for i in range(len(words) - k + 1)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class _UnionFind:
    """Union-find over content-hash keys; union attaches the second
    root under the first (same representative rule as documented)."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        parent = self.parent.setdefault(item, item)
        if parent != item:
            self.parent[item] = self.find(parent)
            return self.parent[item]
        return item

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def group_rows(texts: list[str]) -> dict[int, str]:
    """Group row indices by exact content hash, merged at word-8-shingle
    Jaccard >= 0.8. Candidate pairs come from an inverted shingle index;
    shingles occurring in >100 rows are skipped as non-discriminating.
    Returns {row_index: group_key} where the key is the content hash of
    the group's representative row."""
    uf = _UnionFind()
    hashes = [_content_hash(t) for t in texts]
    by_hash: dict[str, list[int]] = defaultdict(list)
    for i, h in enumerate(hashes):
        by_hash[h].append(i)
    for idxs in by_hash.values():
        for j in idxs[1:]:
            uf.union(hashes[idxs[0]], hashes[j])
    shingles = [_word_shingles(_normalize(t)) for t in texts]
    index: dict[str, list[int]] = defaultdict(list)
    for i, sh in enumerate(shingles):
        for s in sh:
            index[s].append(i)
    candidates: set[tuple[int, int]] = set()
    for _s, idxs in index.items():
        if len(idxs) > 100 or len(idxs) < 2:
            continue
        for a in range(len(idxs)):
            for b in range(a + 1, len(idxs)):
                candidates.add((idxs[a], idxs[b]))
    for i, j in sorted(candidates):
        if uf.find(hashes[i]) == uf.find(hashes[j]):
            continue
        if _jaccard(shingles[i], shingles[j]) >= 0.8:
            uf.union(hashes[i], hashes[j])
    return {i: uf.find(hashes[i]) for i in range(len(texts))}


def load_cache_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="measure and compare only; write nothing")
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    manifest = json.loads(C_MANIFEST.read_text(encoding="utf-8"))
    c_artifact = json.loads(C_ARTIFACT.read_text(encoding="utf-8"))
    c_eval = c_artifact["results"]["evaluation"]
    c_results = c_artifact["results"]
    manifest_sha = _sha256_file(C_MANIFEST)
    c_artifact_sha = _sha256_file(C_ARTIFACT)

    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(ok), "detail": str(detail)})
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)

    # --- 1. Cache files: SHA-256 vs manifest sources ---
    cache_by_file: dict[str, list[dict]] = {}
    for source in manifest["sources"]:
        path = CACHE_ROOT / source["cache_file"]
        actual_sha = _sha256_file(path)
        check(f"cache sha256 {source['cache_file']}",
              actual_sha == source["file_sha256"],
              f"{actual_sha[:12]}... vs manifest {source['file_sha256'][:12]}...")
        rows = load_cache_jsonl(path)
        check(f"cache row count {source['cache_file']}",
              len(rows) == source["rows"], f"{len(rows)} vs {source['rows']}")
        cache_by_file[source["cache_file"]] = rows

    by_source: dict[str, dict] = {}
    for fname, rows in cache_by_file.items():
        for r in rows:
            by_source[r["source_id"]] = r
    check("manifest rows all resolve to a cache row",
          all(m["source_id"] in by_source for m in manifest["rows"]),
          f"{len(manifest['rows'])} manifest rows")

    # --- 2. Content dedup re-derivation ---
    pooled = cache_by_file["train.jsonl"] + cache_by_file["train-2000.jsonl"]
    seen: dict[str, str] = {}
    kept: list[dict] = []
    drops: list[dict] = []
    for r in pooled:
        digest = _content_hash(r["text"])
        if digest in seen:
            drops.append({"source_id": r["source_id"], "content_hash": digest,
                          "duplicates_kept_source_id": seen[digest], "label": r["label"]})
            continue
        seen[digest] = r["source_id"]
        kept.append(r)
    check("pooled rows before dedup is 2498", len(pooled) == 2498, f"{len(pooled)}")
    check("content dedup drops exactly 2 rows", len(drops) == 2, f"{len(drops)}")
    check("kept rows after dedup is 2496", len(kept) == 2496, f"{len(kept)}")
    c_drops = [d for d in c_results["inclusion_drop_counts"]["dropped_duplicate_rows"]
               if "origin" not in d]
    check("dedup drops match artifact (source_id + kept id)",
          {(d["source_id"], d["duplicates_kept_source_id"]) for d in drops}
          == {(d["source_id"], d["duplicates_kept_source_id"]) for d in c_drops},
          json.dumps(drops))
    excluded = json.loads((CACHE_ROOT / "train-2000.excluded.json").read_text(encoding="utf-8"))["excluded"]
    c_fetch = [d for d in c_results["inclusion_drop_counts"]["dropped_duplicate_rows"]
               if d.get("origin") == "fetch"]
    check("fetch-time exclusions match artifact (2)",
          len(excluded) == 2 and
          {(e["source_id"], e["content_hash"]) for e in excluded}
          == {(d["source_id"], d["content_hash"]) for d in c_fetch},
          f"{len(excluded)} excluded")
    check("rows_pooled is 2500 (2496 kept + 4 drops)",
          c_results["inclusion_drop_counts"]["rows_pooled"] == 2500)

    # --- 3. Grouping recomputation ---
    print("recomputing near-duplicate groups ...", flush=True)
    group_of_idx = group_rows([r["text"] for r in kept])
    group_of = {kept[i]["source_id"]: group_of_idx[i] for i in range(len(kept))}
    n_groups = len(set(group_of.values()))
    check("near-duplicate group count is 2493", n_groups == 2493, f"{n_groups}")
    group_mismatch = sum(
        1 for m in manifest["rows"] if group_of.get(m["source_id"]) != m["group_key"])
    check("per-row group_key matches manifest for all rows", group_mismatch == 0,
          f"{group_mismatch} mismatches / {len(manifest['rows'])} rows")

    # --- 4. Per-row identity + partition ---
    mismatches = {"label": 0, "content_hash": 0, "slice": 0, "partition": 0, "cache_file": 0}
    for m in manifest["rows"]:
        r = by_source.get(m["source_id"])
        if r is None:
            continue
        if r["label"] != m["label"]:
            mismatches["label"] += 1
        if _content_hash(r["text"]) != m["content_hash"]:
            mismatches["content_hash"] += 1
        if str(r["meta"].get("domain")) != m["slice"]:
            mismatches["slice"] += 1
        if partition_of(m["group_key"]) != m["partition"]:
            mismatches["partition"] += 1
    cache_file_of = {r["source_id"]: "train.jsonl" for r in cache_by_file["train.jsonl"]}
    cache_file_of.update({r["source_id"]: "train-2000.jsonl" for r in cache_by_file["train-2000.jsonl"]})
    for m in manifest["rows"]:
        if cache_file_of.get(m["source_id"]) != m["cache_file"]:
            mismatches["cache_file"] += 1
    for field, count in mismatches.items():
        check(f"manifest {field} matches cache/rule for all rows", count == 0,
              f"{count} mismatches / {len(manifest['rows'])} rows")
    counts: dict[str, dict] = {}
    for m in manifest["rows"]:
        c = counts.setdefault(m["partition"], {"rows": 0, "n_human": 0, "n_ai": 0, "n_unlabelled": 0})
        c["rows"] += 1
        if m["label"] == 0:
            c["n_human"] += 1
        elif m["label"] == 1:
            c["n_ai"] += 1
        else:
            c["n_unlabelled"] += 1
    check("partition counts match manifest counts", counts == manifest["counts"],
          json.dumps(counts, sort_keys=True))
    check("partition manifest sha matches artifact record",
          manifest_sha == c_results["partition"]["manifest_sha256"],
          f"{manifest_sha[:12]} vs {c_results['partition']['manifest_sha256'][:12]}")
    group_partitions: dict[str, set] = defaultdict(set)
    for m in manifest["rows"]:
        group_partitions[m["group_key"]].add(m["partition"])
    spanning = {g: sorted(p) for g, p in group_partitions.items() if len(p) > 1}
    check("no near-duplicate group spans two partitions", not spanning,
          f"{len(group_partitions)} groups, {len(spanning)} spanning")
    check("artifact near_duplicate_groups is 2493",
          c_results["inclusion_drop_counts"]["near_duplicate_groups"] == 2493)

    # --- 5. Final-test disjoint from validation split ---
    dev_rows = load_cache_jsonl(CACHE_ROOT / "validation.jsonl")
    val_hashes = {_content_hash(r["text"]) for r in dev_rows}
    final_hashes = {m["content_hash"] for m in manifest["rows"] if m["partition"] == "final-test"}
    check("final-test disjoint from validation split by content hash",
          not (final_hashes & val_hashes), f"{len(final_hashes & val_hashes)} shared hashes")

    # --- 6. U1 registry reproduction check ---
    detector = BuiltinHeuristicDetector()
    u1_labelled = [r for r in cache_by_file["train.jsonl"] if r["label"] is not None]
    u1_verdicts = [detector.detect(r["text"]).verdict for r in u1_labelled]
    u1_counts = {"n_human": sum(1 for r in u1_labelled if r["label"] == 0),
                 "n_ai": sum(1 for r in u1_labelled if r["label"] == 1),
                 "abstentions": sum(1 for v in u1_verdicts if v == "abstain")}
    check("U1 registry counts reproduce (137 human / 210 AI / 162 abstentions)",
          u1_counts == {"n_human": 137, "n_ai": 210, "abstentions": 162},
          json.dumps(u1_counts))

    # --- 7. Score the final-test labelled rows ---
    final_labelled = [m for m in manifest["rows"]
                      if m["partition"] == "final-test" and m["label"] is not None]
    scored = []
    for m in final_labelled:
        r = by_source[m["source_id"]]
        pred = detector.detect(r["text"])
        scored.append({
            "source_id": m["source_id"],
            "label": int(m["label"]),
            "score": float(pred.score),
            "reliability": float(pred.reliability),
            "verdict": str(pred.verdict),
            "group": m["group_key"],
            "domain": str(r["meta"].get("domain")),
            "lang": str(r["meta"].get("lang")),
            "agent": str(r["meta"].get("agent")),
        })
    check("final-test labelled count is 861 (354 human / 507 AI)",
          len(scored) == 861
          and sum(1 for s in scored if s["label"] == 0) == 354
          and sum(1 for s in scored if s["label"] == 1) == 507,
          f"n={len(scored)}")

    # --- 8. Recompute slices exactly as Worker C grouped them ---
    human_rows = [s for s in scored if s["label"] == 0]
    by_domain: dict[str, list[dict]] = defaultdict(list)
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for item in scored:
        by_domain[item["domain"]].append(item)
        by_lang[item["lang"]].append(item)
    groupings: dict[str, list[dict]] = {
        "pooled": scored,
        **{f"domain-{k}": v for k, v in by_domain.items()},
        **{f"lang-{k}": v for k, v in by_lang.items()},
    }
    for agent in sorted({s["agent"] for s in scored if s["label"] == 1}):
        groupings[f"agent-{agent}"] = human_rows + [
            s for s in scored if s["label"] == 1 and s["agent"] == agent
        ]
    recomputed: dict[str, dict] = {}
    for name, items in sorted(groupings.items()):
        recomputed[name] = slice_metrics(
            f"ghostwriter-{name}",
            labels=[i["label"] for i in items],
            scores=[i["score"] for i in items],
            verdicts=[i["verdict"] for i in items],
            group_ids=[i["group"] for i in items],
        )
    # Worst slice: highest Wilson FPR upper among slices with n_human >= 10.
    # Ties keep the first slice in sorted-grouping order (stable sort by
    # the upper bound only, exactly as Worker C's summarize_slices does).
    ranked = [
        (m["fpr_native"]["ci_upper"], name) for name, m in recomputed.items()
        if m["n_human"] >= 10 and m["fpr_native"]["ci_upper"] is not None
    ]
    ranked.sort(key=lambda t: t[0], reverse=True)
    worst = {"slice_id": ranked[0][1], "fpr_wilson_upper": ranked[0][0],
             "n_human": recomputed[ranked[0][1]]["n_human"]} if ranked else None

    # Threshold sensitivity on final-test human rows.
    sensitivity = threshold_sensitivity(
        [s["score"] for s in human_rows],
        [s["reliability"] for s in human_rows],
    )

    # Sensitivity attribution (Worker C's sensitivity_attribution,
    # recomputed here from the freshly scored final-test human rows
    # plus the source_id -> cache-file map built in section 4): is the
    # top human row the known U1 row, or a fresh train-2000 row? The
    # interpretation string is rebuilt with Worker C's exact template
    # so the comparison is byte-for-byte.
    _top = max(human_rows, key=lambda r: r["score"])
    _top_cache = cache_file_of[_top["source_id"]]
    _new_human = [r for r in human_rows if cache_file_of[r["source_id"]] != "train.jsonl"]
    _new_scores = [r["score"] for r in _new_human]
    _new_max = round(max(_new_scores), 4) if _new_scores else None
    _new_k066 = sum(1 for r in _new_human
                    if r["score"] >= 0.66 and r["reliability"] >= RELIABILITY_FLOOR)
    sensitivity_detail = {
        "top_human_row": {
            "score": round(float(_top["score"]), 4),
            "reliability": round(float(_top["reliability"]), 4),
            "domain": _top["domain"],
            "lang": _top["lang"],
            "source_id": _top["source_id"],
            "cache_file": _top_cache,
            "is_u1_row": _top_cache == "train.jsonl",
        },
        "new_sample_human_rows_in_final_test": len(_new_human),
        "new_sample_max_human_score": _new_max,
        "new_sample_k_at_threshold_0_66": _new_k066,
        "interpretation": (
            f"The final-test top human score {round(float(_top['score']), 4)} "
            f"comes from cache file {_top_cache} "
            f"({'the U1 sample' if _top_cache == 'train.jsonl' else 'the new sample'}). "
            "If it is the U1 row, the -0.02 fragility (one row flips at "
            "0.66) is NOT independent confirmation on fresh data \u2014 it "
            "is that one known row. On fresh (train-2000) human rows "
            f"alone the maximum is {_new_max} and zero-FPR "
            f"{'DOES' if _new_k066 == 0 else 'does NOT'} survive a "
            f"-0.02 perturbation (k={_new_k066} at 0.66). Both facts "
            "are reported; the threshold is UNCHANGED either way."
        ),
    }

    # --- 9. Field-by-field comparison ---
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
        for field in ("slice_id", "n_human", "n_ai", "n_human_groups", "n_ai_groups",
                      "coverage", "abstention_rate", "abstentions"):
            compare(f"slices.{name}.{field}", mine[field], theirs[field])
        for rate in ("fpr_native", "tpr_native"):
            for sub in ("k", "n", "value", "ci_lower", "ci_upper"):
                compare(f"slices.{name}.{rate}.{sub}", mine[rate].get(sub), theirs[rate].get(sub))
            if "not_computed" in mine[rate] or "not_computed" in theirs[rate]:
                compare(f"slices.{name}.{rate}.not_computed",
                        mine[rate].get("not_computed"), theirs[rate].get("not_computed"))
        for lab in ("human", "machine"):
            for sub in ("n", "mean", "median", "min", "max"):
                compare(f"slices.{name}.score_by_label.{lab}.{sub}",
                        mine["score_by_label"][lab][sub], theirs["score_by_label"][lab][sub])
        for metric in ("auroc", "auprc", "tpr_at_1pct_fpr", "tpr_at_5pct_fpr"):
            if metric in mine and metric in theirs:
                for sub in ("value", "ci_lower", "ci_upper", "resamples", "resamples_skipped_no_class"):
                    compare(f"slices.{name}.{metric}.{sub}", mine[metric][sub], theirs[metric][sub])
            else:
                compare(f"slices.{name}.{metric}.present", metric in mine, metric in theirs)
                if "ranking_metrics_not_computed" in mine or "ranking_metrics_not_computed" in theirs:
                    compare(f"slices.{name}.ranking_metrics_not_computed",
                            mine.get("ranking_metrics_not_computed"),
                            theirs.get("ranking_metrics_not_computed"))
    # Threshold sensitivity.
    c_sens = c_results["threshold_sensitivity"]
    for field in ("native_threshold", "reliability_floor", "max_human_score",
                  "within_below_threshold", "human_scores_at_or_above_threshold"):
        compare(f"threshold_sensitivity.{field}", sensitivity[field], c_sens[field])
    for i, (my_e, th_e) in enumerate(zip(sensitivity["sensitivity"], c_sens["sensitivity"])):
        for sub in ("threshold", "k", "n", "rate", "ci_lower", "ci_upper"):
            compare(f"threshold_sensitivity.sensitivity[{i}].{sub}", my_e[sub], th_e[sub])
    # The detail dict (added by Worker C in aa7eb50) is fully
    # recomputable from the scored rows; compare every field.
    c_detail = c_results["threshold_sensitivity_detail"]
    for field in ("new_sample_human_rows_in_final_test", "new_sample_max_human_score",
                  "new_sample_k_at_threshold_0_66", "interpretation"):
        compare(f"threshold_sensitivity_detail.{field}", sensitivity_detail[field], c_detail[field])
    for sub in ("score", "reliability", "domain", "lang", "source_id", "cache_file", "is_u1_row"):
        compare(f"threshold_sensitivity_detail.top_human_row.{sub}",
                sensitivity_detail["top_human_row"][sub], c_detail["top_human_row"][sub])
    # The note is a hardcoded literal in Worker C's script, not a
    # computed value: it can only be checked for presence and for
    # consistency with the recomputed detail numbers (fresh max 0.6496
    # and the 1/354 flip count), not recomputed itself.
    _note = c_results["threshold_sensitivity_note"]
    _note_numbers_consistent = (
        f"{sensitivity_detail['new_sample_max_human_score']}" in _note
        and "1/354" in _note
    )
    compare("threshold_sensitivity_note.present", isinstance(_note, str) and len(_note) > 0, True)
    compare("threshold_sensitivity_note.numbers_consistent_with_detail",
            _note_numbers_consistent, True)
    n_agree = sum(1 for c in comparison if c["agree"])
    print(f"comparison: {n_agree}/{len(comparison)} fields agree; "
          f"{len(discrepancies)} discrepancies", flush=True)
    for d in discrepancies:
        print(f"  DISCREPANCY {d['field']}: reproduction={d['reproduction']} worker_c={d['worker_c']}",
              flush=True)

    all_checks_pass = all(c["passed"] for c in checks)
    verdict = "AGREE" if (not discrepancies and all_checks_pass) else "DISCREPANCY"
    print(f"reproduction verdict: {verdict}", flush=True)

    if args.check:
        print("check mode: no artifact file written")
        return 0 if verdict == "AGREE" else 1

    output = Path(args.output) if args.output else (
        REPO_ROOT / "docs" / "evidence" / "runs" / f"{ARTIFACT_ID}.json")
    environment_extras = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"], capture_output=True, text=True, check=True
    ).stdout.strip()
    artifact = {
        "schema": RUN_ARTIFACT_SCHEMA,
        "evidence_record_id": ARTIFACT_ID,
        "kind": "command",
        "command": "python scripts/reproduce_w8c_ghostwriter.py",
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
            "extras": environment_extras,
        },
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "reproduces": "EV-20261116-dataset-ghostwriter",
            "reproduces_artifact_sha256": c_artifact_sha,
            "reproduces_manifest": "EV-20261116-dataset-ghostwriter-partitions.json",
            "reproduces_manifest_sha256": manifest_sha,
            "detector": "textforensics/builtin-heuristic",
            "detector_family": "stylometric-heuristic",
            "detector_version": "0.1.0",
            "operating_point": "builtin-heuristic native verdict (analyze_text); no score threshold",
            "method": (
                "Independent reproduction: cache files read directly as JSONL; "
                "content dedup and near-duplicate grouping re-derived from "
                "scratch; partition re-derived row by row from "
                "sha256(group_key) mod 10; detector re-run on the 861 "
                "final-test labelled rows; Wilson/AUROC (pairwise "
                "Mann-Whitney)/AUPRC/TPR@FPR/cluster-bootstrap recomputed "
                "from scratch with independent implementations, plus the "
                "threshold sensitivity on final-test human rows. No tuning "
                "on the final holdout."
            ),
            "identity_checks": checks,
            "u1_registry_reproduction": u1_counts,
            "partition_counts": counts,
            "group_count": n_groups,
            "groups_spanning_partitions": spanning,
            "evaluation": {"slices": recomputed, "worst_slice": worst,
                           "n_final_test_labelled": len(scored)},
            "threshold_sensitivity": sensitivity,
            "threshold_sensitivity_detail": sensitivity_detail,
            "comparison": comparison,
            "discrepancies": discrepancies,
            "verdict": verdict,
        },
        "drops": [
            {"item": "Worker C fit/dev partitions",
             "reason": "reproduction scores the final-test holdout only; fit/dev rows are "
                       "verified for identity, grouping and partition correctness but not scored"},
            {"item": "Fusion (label 2 / unlabelled) chunk rows",
             "reason": "rows with no binary label are excluded from binary metrics, as in "
                       "Worker C's artifact"},
        ],
        "badge": "available",
        "detector_version": "0.1.0",
        "notes": (
            "Independent reproduction of Worker C's GhostWriter partitioned "
            "evaluation. Every compared field either agrees exactly or is "
            "listed in 'discrepancies'. "
            f"Reproduction verdict: {verdict}. Pooled final-test holdout as "
            "re-measured here: human FPR "
            f"{recomputed['pooled']['fpr_native']['k']}/{recomputed['pooled']['fpr_native']['n']} "
            f"(Wilson 95% upper {recomputed['pooled']['fpr_native']['ci_upper']}) and native TPR "
            f"{recomputed['pooled']['tpr_native']['k']}/{recomputed['pooled']['tpr_native']['n']}. "
            "A below-chance ranking result is reported as measured, not "
            "tuned around. The native 0.68 threshold is unchanged."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)[:12]}...)")
    return 0 if verdict == "AGREE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
