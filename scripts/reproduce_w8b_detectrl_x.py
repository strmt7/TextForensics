#!/usr/bin/env python3
"""reproduce_w8b_detectrl_x.py — W8 worker E (independent reproduction).

Independently reproduces Worker B's DetectRL-X expanded-sample
evaluation (docs/evidence/runs/EV-20261116-dataset-detectrl-x.json,
script scripts/measure_w8_b.py --only detectrl_x) from scratch, on the
W8 code base (audit-w7 @ 17b8951):

- Verifies the raw source file (Binary/binary_general_open.json, 878
  MB) by size + SHA-256 before any row is read, then re-streams it
  once with the frozen strided sample (8,000 train + 4,000 test source
  rows over 76,800 + 48,000) and re-maps every sampled row with the
  repo mapper, collecting mapper refusals as drops.
- Verifies the written normalised caches (train-w8.jsonl /
  test-w8.jsonl) by SHA-256 and by row-by-row comparison against the
  freshly mapped rows.
- Re-derives the inspection block (field sets, langs/models/domains,
  cells, distinct human texts, word counts, representative records).
- Re-derives the near-duplicate components (union-find over shared
  human-text identity plus word-8-shingle Jaccard >= 0.8, crc32 index
  proposes candidates, exact verification) and the partition
  assignment (whole components, stratified by language, deterministic
  hash order, greedy 60/20/20), and compares per-row cluster +
  partition against the frozen partition manifests.
- Re-scores all 24,000 rows with a FRESH detector at the native
  operating point, with the same 20-row determinism spot check.
- Recomputes every slice with Worker B's exact conventions: a SINGLE
  shared random.Random(20261116) stream consumed in the fixed call
  order (pooled -> final_test -> by_lang -> by_domain -> by_generator
  -> by_split -> by_lang_final_test -> by_domain_final_test), row
  bootstrap via rng.randrange, cluster bootstrap via rng.choice,
  percentile [int(0.025*m)] / [int(0.975*m)-1]. Wilson FPR/TPR as
  [lo, hi] lists rounded to 6 decimals (my own formula
  implementation, cross-checked against the repo wilson_ci). AUROC is
  the rank form, cross-checked against my pairwise Mann-Whitney
  implementation; AUPRC is the stepwise average precision over
  distinct score thresholds; TPR@FPR is the max TPR among
  distinct-score thresholds with FPR <= target.
- Compares EVERY field of Worker B's artifact recursively
  (provenance, inspection, drops, near-duplicates, partition,
  determinism, dependency lock, pooled, final-test, all group slices,
  worst-slice context) and the record drops. ANY discrepancy is a
  finding.

Usage:
    python scripts/reproduce_w8b_detectrl_x.py [--check]
    python scripts/reproduce_w8b_detectrl_x.py --output <path>

--check measures and compares only; it writes nothing.
The default output is docs/evidence/runs/EV-20261116-reproduction-detectrl-x.json.
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
import zlib
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
WORKER_B_ROOT = Path.home() / "workspace" / "TextForensics-w8-b"
sys.path.insert(0, str(REPO_ROOT / "src"))

from textforensics.datasets import (  # noqa: E402
    DETECTRL_X_BYTES,
    DETECTRL_X_FILE,
    DETECTRL_X_SHA256,
    DatasetFetchError,
    canonical_text_sha256,
    download_detectrl_x,
    map_row,
    sample_detectrl_x_rows,
    sample_offsets,
    verify_detectrl_x_file,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.ledger import canonical_text_sha256 as ledger_canonical_sha  # noqa: E402
from textforensics.probe_metrics import wilson_ci as repo_wilson_ci  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-reproduction-detectrl-x"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
BOOTSTRAP_SEED = 20261116
N_BOOTSTRAP = 1000
SHINGLE_N = 8
NEAR_DUP_JACCARD = 0.8
PARTITION_FRACTIONS = {"fit": 0.60, "validation": 0.20, "final-test": 0.20}
OPERATING_POINT = "builtin-heuristic native verdict (analyze_text); no score threshold"
DETECTRL_X_TRAIN_N = 8000
DETECTRL_X_TEST_N = 4000
DETECTRL_X_TRAIN_TOTAL = 76800
DETECTRL_X_TEST_TOTAL = 48000
CACHE_ROOT = Path.home() / ".cache" / "textforensics" / "datasets"


def _load_module(name: str, path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _code_version() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def _round6(value: float | None) -> float | None:
    return None if value is None else round(float(value), 6)


# --- Independent metric implementations (written here, from definitions) ---


def wilson(k: int, n: int, *, z: float = 1.96) -> tuple[float, float]:
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


def _self_test() -> list[str]:
    problems: list[str] = []
    if abs(auroc_pairwise([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) - 1.0) > 1e-12:
        problems.append("auroc_pairwise perfect != 1.0")
    lo, hi = wilson(0, 400)
    if abs(hi - 0.009513) > 1e-6:
        problems.append(f"wilson(0,400) upper {hi} != 0.009513")
    lo2, hi2 = repo_wilson_ci(0, 400, z=1.96)
    if abs(hi2 - hi) > 1e-12 or abs(lo2 - lo) > 1e-12:
        problems.append("repo wilson_ci disagrees with the formula implementation")
    if ledger_canonical_sha("a\r\nb") != canonical_text_sha256("a\r\nb"):
        problems.append("ledger canonical hash disagrees with datasets canonical hash")
    return problems


# --- Text utils + components (Worker B's algorithm, replicated) ---


def _norm_text(text: str) -> str:
    return " ".join(text.split())


def _word_count(text: str) -> int:
    return len(text.split())


def _tokens(text: str) -> list[str]:
    return _norm_text(text).lower().split()


def _shingles(text: str) -> set[str]:
    toks = _tokens(text)
    if len(toks) < SHINGLE_N:
        return {"\x00" + " ".join(toks)}
    return {" ".join(toks[i : i + SHINGLE_N]) for i in range(len(toks) - SHINGLE_N + 1)}


def _shingle_hashes(text: str) -> set[int]:
    return {zlib.crc32(s.encode("utf-8")) for s in _shingles(text)}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def build_components(rows: list[dict]) -> tuple[list[list[int]], list[dict]]:
    n = len(rows)
    uf = _UnionFind(n)
    by_group: dict[str, list[int]] = defaultdict(list)
    for i, row in enumerate(rows):
        by_group[row["group_key"]].append(i)
    for members in by_group.values():
        for j in members[1:]:
            uf.union(members[0], j)
    postings: dict[int, list[int]] = defaultdict(list)
    near_dup_pairs: list[dict] = []
    for i in range(n):
        row_hashes = _shingle_hashes(rows[i]["text"])
        need = math.ceil(NEAR_DUP_JACCARD * len(row_hashes))
        counts: Counter[int] = Counter()
        for h in row_hashes:
            for j in postings.get(h, ()):
                counts[j] += 1
        for j, shared in counts.items():
            if shared < need:
                continue
            exact = _jaccard(_shingles(rows[i]["text"]), _shingles(rows[j]["text"]))
            if exact >= NEAR_DUP_JACCARD:
                near_dup_pairs.append(
                    {
                        "row_a": rows[j]["source_id"],
                        "row_b": rows[i]["source_id"],
                        "jaccard": round(exact, 4),
                        "same_group": rows[j]["group_key"] == rows[i]["group_key"],
                    }
                )
                uf.union(i, j)
        for h in row_hashes:
            postings[h].append(i)
    comp_map: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        comp_map[uf.find(i)].append(i)
    return list(comp_map.values()), near_dup_pairs


def _component_id(rows: list[dict], members: list[int]) -> str:
    first = min(rows[i]["source_id"] for i in members)
    return "c:" + hashlib.sha256(first.encode("utf-8")).hexdigest()[:12]


def assign_partitions(
    dataset: str, rows: list[dict], components: list[list[int]]
) -> dict[int, str]:
    comp_stratum: list[str] = []
    for members in components:
        strata = Counter(rows[i]["stratum"] for i in members)
        comp_stratum.append(strata.most_common(1)[0][0])
    by_stratum: dict[str, list[int]] = defaultdict(list)
    for ci, s in enumerate(comp_stratum):
        by_stratum[s].append(ci)
    assignment: dict[int, str] = {}
    for stratum in sorted(by_stratum):
        cis = by_stratum[stratum]
        total = sum(len(components[ci]) for ci in cis)
        targets = {p: f * total for p, f in PARTITION_FRACTIONS.items()}
        placed: Counter[str] = Counter()
        ordered = sorted(
            cis,
            key=lambda ci: hashlib.sha256(
                f"w8-b:{dataset}:{_component_id(rows, components[ci])}".encode()
            ).hexdigest(),
        )
        for ci in ordered:
            part = min(
                PARTITION_FRACTIONS,
                key=lambda p: (placed[p] - targets[p], list(PARTITION_FRACTIONS).index(p)),
            )
            for i in components[ci]:
                assignment[i] = part
            placed[part] += len(components[ci])
    return assignment


# --- Metrics (Worker B's conventions, replicated; shared rng) ---


def _roc_metrics(labels: list[int], scores: list[float]) -> dict[str, float]:
    """AUROC (rank form), AUPRC (distinct-threshold stepwise AP),
    TPR@FPR 1%/5% (distinct-threshold ROC walk)."""
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    asc = sorted(range(len(scores)), key=lambda i: scores[i])
    rank_sum = 0.0
    i = 0
    while i < len(asc):
        j = i
        while j < len(asc) and scores[asc[j]] == scores[asc[i]]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            if labels[asc[k]] == 1:
                rank_sum += avg_rank
        i = j
    auroc = (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    best = {0.01: 0.0, 0.05: 0.0}
    idx = 0
    while idx < len(order):
        threshold = scores[order[idx]]
        while idx < len(order) and scores[order[idx]] == threshold:
            if labels[order[idx]] == 1:
                tp += 1
            else:
                fp += 1
            idx += 1
        precision = tp / (tp + fp)
        recall = tp / n_pos
        ap += (recall - prev_recall) * precision
        prev_recall = recall
        fpr = fp / n_neg
        for target in best:
            if fpr <= target and recall > best[target]:
                best[target] = recall
    return {
        "auroc": auroc,
        "auprc": ap,
        "tpr_at_fpr_0_01": best[0.01],
        "tpr_at_fpr_0_05": best[0.05],
    }


def _bootstrap_ci(
    labels: list[int],
    scores: list[float],
    rng: random.Random,
    *,
    n_resamples: int = N_BOOTSTRAP,
) -> dict[str, list[float]] | None:
    n = len(labels)
    if min(sum(labels), n - sum(labels)) < 10:
        return None
    keys = ("auroc", "auprc", "tpr_at_fpr_0_01", "tpr_at_fpr_0_05")
    draws: dict[str, list[float]] = {k: [] for k in keys}
    skipped = 0
    for _ in range(n_resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        sub_labels = [labels[i] for i in idx]
        if min(sum(sub_labels), n - sum(sub_labels)) == 0:
            skipped += 1
            continue
        m = _roc_metrics(sub_labels, [scores[i] for i in idx])
        for k in keys:
            draws[k].append(m[k])
    out = {}
    for k in keys:
        vals = sorted(draws[k])
        out[k] = [
            round(vals[int(0.025 * len(vals))], 4),
            round(vals[int(0.975 * len(vals)) - 1], 4),
        ]
    out["resamples"] = [len(draws["auroc"]), skipped]
    return out


def _cluster_bootstrap_ci(
    items: list[dict],
    rng: random.Random,
    *,
    n_resamples: int = N_BOOTSTRAP,
) -> dict[str, list[float]] | None:
    clusters: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        clusters[it["cluster"]].append(it)
    keys = sorted(clusters)
    if len(keys) < 10:
        return None
    fprs, tprs, aurocs = [], [], []
    skipped = 0
    for _ in range(n_resamples):
        picked = [clusters[rng.choice(keys)] for _ in range(len(keys))]
        flat = [it for group in picked for it in group]
        labels = [it["label"] for it in flat]
        if min(sum(labels), len(labels) - sum(labels)) == 0:
            skipped += 1
            continue
        scores = [it["score"] for it in flat]
        k_fp = sum(1 for it in flat if it["label"] == 0 and it["verdict"] == "ai_like")
        n_h = sum(1 for it in flat if it["label"] == 0)
        k_tp = sum(1 for it in flat if it["label"] == 1 and it["verdict"] == "ai_like")
        n_a = sum(1 for it in flat if it["label"] == 1)
        fprs.append(k_fp / n_h)
        tprs.append(k_tp / n_a)
        aurocs.append(_roc_metrics(labels, scores)["auroc"])
    if not fprs:
        return None

    def _ci(vals: list[float]) -> list[float]:
        vals = sorted(vals)
        return [round(vals[int(0.025 * len(vals))], 4), round(vals[int(0.975 * len(vals)) - 1], 4)]

    return {
        "fpr_native": _ci(fprs),
        "tpr_native": _ci(tprs),
        "auroc": _ci(aurocs),
        "resamples_kept": len(fprs),
        "resamples_skipped": skipped,
    }


def slice_metrics(
    items: list[dict],
    *,
    bootstrap: bool,
    cluster_bootstrap: bool,
    rng: random.Random,
) -> dict:
    labels = [it["label"] for it in items]
    scores = [it["score"] for it in items]
    n_human = sum(1 for x in labels if x == 0)
    n_ai = sum(1 for x in labels if x == 1)
    k_fp = sum(1 for it in items if it["label"] == 0 and it["verdict"] == "ai_like")
    k_tp = sum(1 for it in items if it["label"] == 1 and it["verdict"] == "ai_like")
    abstentions = sum(1 for it in items if it["verdict"] == "abstain")
    fpr_wilson = None
    if n_human:
        fpr_lo, fpr_hi = wilson(k_fp, n_human)
        fpr_wilson = [round(fpr_lo, 6), round(fpr_hi, 6)]
    tpr_wilson = None
    if n_ai:
        tpr_lo, tpr_hi = wilson(k_tp, n_ai)
        tpr_wilson = [round(tpr_lo, 6), round(tpr_hi, 6)]
    roc = _roc_metrics(labels, scores) if n_human and n_ai else None
    human_scores = [it["score"] for it in items if it["label"] == 0]
    ai_scores = [it["score"] for it in items if it["label"] == 1]
    out: dict = {
        "n": len(items),
        "n_human": n_human,
        "n_ai": n_ai,
        "k_fp_native": k_fp,
        "k_tp_native": k_tp,
        "fpr_native": round(k_fp / n_human, 4) if n_human else None,
        "fpr_native_wilson_95": fpr_wilson,
        "tpr_native": round(k_tp / n_ai, 4) if n_ai else None,
        "tpr_native_wilson_95": tpr_wilson,
        "auroc": round(roc["auroc"], 4) if roc else None,
        "auprc": round(roc["auprc"], 4) if roc else None,
        "auprc_baseline_prevalence": round(n_ai / len(items), 4) if items else None,
        "tpr_at_fpr_0_01": round(roc["tpr_at_fpr_0_01"], 4) if roc else None,
        "tpr_at_fpr_0_05": round(roc["tpr_at_fpr_0_05"], 4) if roc else None,
        "coverage": round(1 - abstentions / len(items), 4) if items else None,
        "abstentions": abstentions,
        "abstention_rate": round(abstentions / len(items), 4) if items else None,
        "max_human_score": round(max(human_scores), 4) if human_scores else None,
        "score_human": {
            "mean": round(statistics.fmean(human_scores), 4),
            "median": round(statistics.median(human_scores), 4),
            "min": round(min(human_scores), 4),
            "max": round(max(human_scores), 4),
        }
        if human_scores
        else None,
        "score_machine": {
            "mean": round(statistics.fmean(ai_scores), 4),
            "median": round(statistics.median(ai_scores), 4),
            "min": round(min(ai_scores), 4),
            "max": round(max(ai_scores), 4),
        }
        if ai_scores
        else None,
        "operating_point": OPERATING_POINT,
    }
    if bootstrap:
        ci = _bootstrap_ci(labels, scores, rng)
        out["bootstrap_95"] = ci
    if cluster_bootstrap:
        out["cluster_bootstrap_95"] = _cluster_bootstrap_ci(items, rng)
    return out


def _group_slices(
    rows: list[dict], *, key: str, bootstrap: bool, cluster_bootstrap: bool, rng: random.Random
) -> dict[str, dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[str(row[key])].append(row)
    out = {}
    for name in sorted(groups):
        items = groups[name]
        if (
            min(
                sum(1 for it in items if it["label"] == 0),
                sum(1 for it in items if it["label"] == 1),
            )
            < 10
        ):
            out[name] = slice_metrics(items, bootstrap=False, cluster_bootstrap=False, rng=rng)
            out[name]["note"] = (
                "bootstrap CIs omitted: a class has fewer than 10 rows in this slice"
            )
        else:
            out[name] = slice_metrics(items, bootstrap=bootstrap, cluster_bootstrap=False, rng=rng)
    return out


# --- Main reproduction ---


def _load_cache_jsonl(path: Path) -> list[dict]:
    # NOTE (W8-B recovery, 2026-11-16): split on "\n", NOT .splitlines().
    # The cache writer (write_sample_cache) joins lines with "\n" and
    # dumps with ensure_ascii=False, so raw U+0085 (NEL) bytes inside
    # source texts are legal file content — and .splitlines() splits on
    # U+0085, cutting two JSON lines mid-string in each W8 cache
    # (train-w8: 16,002 fragments for 16,000 rows; test-w8: 8,002 for
    # 8,000) and crashing json.loads with "Unterminated string".
    # Both caches are valid JSONL when split on "\n" (verified:
    # 16,000 + 8,000 lines, 0 parse errors) and their SHAs match the
    # manifests and B's artifact provenance. This is a reproducer
    # defect, not a cache/artifact defect. Original (Worker E,
    # cb6f6f0) used .splitlines().
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()
    ]


def _verify_partition(rows: list[dict], assignment: dict[int, str]) -> dict:
    by_part: dict[str, set[str]] = defaultdict(set)
    by_part_text: dict[str, set[str]] = defaultdict(set)
    for i, row in enumerate(rows):
        by_part[assignment[i]].add(row["cluster"])
        by_part_text[assignment[i]].add(row["text_sha256"])
    parts = sorted(by_part)
    shared_clusters = set()
    shared_texts = set()
    for a in range(len(parts)):
        for b in range(a + 1, len(parts)):
            shared_clusters |= by_part[parts[a]] & by_part[parts[b]]
            shared_texts |= by_part_text[parts[a]] & by_part_text[parts[b]]
    return {
        "partitions": parts,
        "rows_assigned": len(assignment),
        "rows_total": len(rows),
        "complete": len(assignment) == len(rows),
        "shared_components_across_partitions": len(shared_clusters),
        "shared_exact_texts_across_partitions": len(shared_texts),
    }


def validate_run_artifact(artifact: dict) -> list[str]:
    check_claims = _load_module(
        "check_claims_for_validation", REPO_ROOT / "scripts" / "check_claims.py"
    )
    schema = check_claims._load_schema(REPO_ROOT, "run-artifact.schema.json")
    return check_claims._schema_errors(schema, artifact)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="measure and compare only; write nothing"
    )
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    problems = _self_test()
    if problems:
        print("METRIC SELF-TEST FAILURE:", file=sys.stderr)
        for item in problems:
            print(f"  - {item}", file=sys.stderr)
        return 2

    b_artifact_path = (
        WORKER_B_ROOT / "docs" / "evidence" / "runs" / "EV-20261116-dataset-detectrl-x.json"
    )
    if not b_artifact_path.exists():
        raise ValueError(f"Worker B DetectRL-X artifact missing: {b_artifact_path}")
    b_artifact = json.loads(b_artifact_path.read_text(encoding="utf-8"))
    b = b_artifact["results"]
    b_sha = _sha256_file(b_artifact_path)

    checks: list[dict] = []
    comparison: list[dict] = []
    discrepancies: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(ok), "detail": str(detail)})
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)

    def compare(path: str, mine, theirs) -> None:
        same = mine == theirs
        comparison.append({"field": path, "reproduction": mine, "worker_b": theirs, "agree": same})
        if not same:
            discrepancies.append({"field": path, "reproduction": mine, "worker_b": theirs})

    def deep_compare(path: str, mine, theirs) -> None:
        if isinstance(mine, dict) and isinstance(theirs, dict):
            # NOTE (W8-B recovery, 2026-11-16): sort by str(key) so a
            # mixed-type key set (e.g. int keys vs JSON string keys)
            # degrades to reported "<missing>" mismatches instead of
            # crashing sorted() with TypeError. Original (Worker E,
            # cb6f6f0) used bare sorted().
            for k in sorted(set(mine) | set(theirs), key=str):
                if k not in mine:
                    compare(f"{path}.{k}", "<missing>", theirs[k])
                elif k not in theirs:
                    compare(f"{path}.{k}", mine[k], "<missing>")
                else:
                    deep_compare(f"{path}.{k}", mine[k], theirs[k])
        elif isinstance(mine, list) and isinstance(theirs, list):
            compare(f"{path}.__len__", len(mine), len(theirs))
            for i, (a, c) in enumerate(zip(mine, theirs, strict=False)):
                if i < min(len(mine), len(theirs)):
                    deep_compare(f"{path}[{i}]", a, c)
        else:
            compare(path, mine, theirs)

    # --- 1. Raw source file: size + SHA-256, then re-stream + sample ---
    print("[detectrl_x] verifying raw source file ...", flush=True)
    raw_path = download_detectrl_x()
    verify_detectrl_x_file(raw_path)
    check(
        "raw file size",
        raw_path.stat().st_size == DETECTRL_X_BYTES,
        f"{raw_path.stat().st_size} vs {DETECTRL_X_BYTES}",
    )
    check(
        "raw file sha256",
        _sha256_file(raw_path) == DETECTRL_X_SHA256,
        f"{_sha256_file(raw_path)[:12]} vs {DETECTRL_X_SHA256[:12]}",
    )
    print("[detectrl_x] streaming one pass: strided sample ...", flush=True)
    train_indexed, test_indexed, counts = sample_detectrl_x_rows(
        raw_path,
        sample_offsets(DETECTRL_X_TRAIN_TOTAL, DETECTRL_X_TRAIN_N),
        sample_offsets(DETECTRL_X_TEST_TOTAL, DETECTRL_X_TEST_N),
    )
    check(
        "file counts verified",
        counts["train"] == DETECTRL_X_TRAIN_TOTAL and counts["test"] == DETECTRL_X_TEST_TOTAL,
        json.dumps(counts, sort_keys=True),
    )
    check(
        "sampled source rows",
        len(train_indexed) == DETECTRL_X_TRAIN_N and len(test_indexed) == DETECTRL_X_TEST_N,
        f"train {len(train_indexed)} test {len(test_indexed)}",
    )

    # --- 2. Re-map every sampled row (drops collected, never hidden) ---
    rows: list[dict] = []
    drops: list[dict] = []
    field_sets: Counter[str] = Counter()
    langs: Counter[str] = Counter()
    models: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    cells: Counter[tuple] = Counter()
    human_text_hashes_train: set[str] = set()
    human_text_hashes_test: set[str] = set()
    for split, indexed in (("train", train_indexed), ("test", test_indexed)):
        for row_index, raw in indexed:
            field_sets[tuple(sorted(raw.keys()))] += 1
            try:
                mapped = map_row("detectrl_x", raw, "binary", split, row_index=row_index)
            except DatasetFetchError as exc:
                drops.append(
                    {
                        "item": f"source row file-index={row_index} split={split}",
                        "reason": f"mapper refused: {exc}",
                    }
                )
                continue
            group_key = "human-text:" + canonical_text_sha256(raw["human_written_text"])
            if split == "train":
                human_text_hashes_train.add(group_key)
            else:
                human_text_hashes_test.add(group_key)
            langs[str(raw.get("lang"))] += 1
            models[str(raw.get("model"))] += 1
            domains[str(raw.get("domain"))] += 1
            cells[(str(raw.get("lang")), str(raw.get("model")), str(raw.get("domain")), split)] += 1
            for norm in mapped:
                kind = "human" if norm.label == 0 else "llm"
                rows.append(
                    {
                        "source_id": norm.source_id,
                        "text": norm.text,
                        "label": int(norm.label),
                        "kind": kind,
                        "stratum": str(norm.meta.get("lang")),
                        "group_key": group_key,
                        "text_sha256": canonical_text_sha256(norm.text),
                        "words": _word_count(norm.text),
                        "split": split,
                        "lang": str(norm.meta.get("lang")),
                        "model": str(norm.meta.get("model")),
                        "domain": str(norm.meta.get("domain")),
                        "dataset_key": "detectrl_x",
                        "config": "binary",
                        "regime": "raw",
                        "meta": dict(norm.meta),
                    }
                )
    check(
        "mapped normalised rows",
        len(rows) == 24000 - 2 * len(drops),
        f"{len(rows)} rows, {len(drops)} mapper drops",
    )
    deep_compare("drops_from_mapping", drops, b["drops_from_mapping"])
    compare("n_mapping_drops", len(drops), b["n_mapping_drops"])

    # --- 3. Written caches: SHA + row-by-row equality with fresh mapping ---
    train_rows = [r for r in rows if r["split"] == "train"]
    test_rows = [r for r in rows if r["split"] == "test"]
    for split, split_rows, fname in (
        ("train", train_rows, "train-w8.jsonl"),
        ("test", test_rows, "test-w8.jsonl"),
    ):
        cache_path = CACHE_ROOT / "detectrl_x" / "binary" / fname
        manifest_path = (
            CACHE_ROOT / "detectrl_x" / "binary" / fname.replace(".jsonl", ".manifest.json")
        )
        cache_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        check(
            f"cache {fname} sha256 matches its manifest",
            _sha256_file(cache_path) == cache_manifest["file_sha256"],
            _sha256_file(cache_path)[:12],
        )
        check(
            f"cache {fname} sha256 matches artifact provenance",
            _sha256_file(cache_path) == b["provenance"]["cache"][split]["file_sha256"],
            _sha256_file(cache_path)[:12],
        )
        check(
            f"cache {fname} rows",
            cache_manifest["rows"] == len(split_rows),
            f"{cache_manifest['rows']} vs {len(split_rows)}",
        )
        cached = _load_cache_jsonl(cache_path)
        mismatches = 0
        for cached_row, mine in zip(cached, split_rows, strict=True):
            if (
                cached_row["source_id"] != mine["source_id"]
                or cached_row["text"] != mine["text"]
                or int(cached_row["label"]) != mine["label"]
                or dict(cached_row["meta"]) != mine["meta"]
            ):
                mismatches += 1
        check(
            f"cache {fname} rows identical to fresh mapping",
            mismatches == 0,
            f"{mismatches} mismatches / {len(cached)} rows",
        )

    # --- 4. Inspection block, re-derived ---
    shared_human_texts = human_text_hashes_train & human_text_hashes_test
    inspection = {
        "source_file": DETECTRL_X_FILE,
        "source_file_sha256": DETECTRL_X_SHA256,
        "source_file_bytes": DETECTRL_X_BYTES,
        "file_counts_verified": counts,
        "sampled_source_rows": {"train": len(train_indexed), "test": len(test_indexed)},
        "sampling": (
            f"strided (sample_offsets over {DETECTRL_X_TRAIN_TOTAL} train + "
            f"{DETECTRL_X_TEST_TOTAL} test rows); deterministic, no randomness"
        ),
        "field_sets_observed": {",".join(k): v for k, v in field_sets.items()},
        "langs": dict(sorted(langs.items())),
        "models": dict(sorted(models.items())),
        "domains": dict(sorted(domains.items())),
        "cells_sampled": {
            f"{lang}/{model}/{domain}/{split}": n
            for (lang, model, domain, split), n in sorted(cells.items())
        },
        "cells_expected_per_split": "192 (8 langs x 4 models x 6 domains)",
        "distinct_human_texts_sampled": {
            "train": len(human_text_hashes_train),
            "test": len(human_text_hashes_test),
            "shared_train_test": len(shared_human_texts),
        },
        "word_counts_by_label": {
            # NOTE (W8-B recovery, 2026-11-16): str(label) — B's artifact
            # is JSON, so its keys are the strings "0"/"1". Int keys
            # here made deep_compare's sorted() union {0,1,"0","1"}
            # raise TypeError ('<' not supported between 'str' and
            # 'int') at the inspection comparison. Original (Worker E,
            # cb6f6f0) used the bare int label.
            str(label): {
                "min": min(r["words"] for r in rows if r["label"] == label),
                "median": int(statistics.median([r["words"] for r in rows if r["label"] == label])),
                "max": max(r["words"] for r in rows if r["label"] == label),
            }
            for label in (0, 1)
        },
        "word_counts_by_lang": {
            lang: {
                "min": min(r["words"] for r in rows if r["lang"] == lang),
                "median": int(statistics.median([r["words"] for r in rows if r["lang"] == lang])),
                "max": max(r["words"] for r in rows if r["lang"] == lang),
            }
            for lang in sorted(langs)
        },
    }
    reps = [
        rows[0]["source_id"],
        next(r["source_id"] for r in rows if r["label"] == 1),
        next(r["source_id"] for r in rows if r["split"] == "test"),
        min(rows, key=lambda r: r["words"])["source_id"],
        max(rows, key=lambda r: r["words"])["source_id"],
    ]
    inspection["representative_records_inspected"] = reps
    deep_compare("inspection", inspection, b["inspection"])

    # --- 5. Near-duplicate components + partition assignment ---
    print("[detectrl_x] building near-duplicate components ...", flush=True)
    components, near_dup_pairs = build_components(rows)
    comp_sizes = Counter(len(c) for c in components)
    for members in components:
        cid = _component_id(rows, members)
        for j in members:
            rows[j]["cluster"] = cid
    assignment = assign_partitions("detectrl_x", rows, components)
    for i, part in assignment.items():
        rows[i]["partition"] = part
    partition_check = _verify_partition(rows, assignment)
    check(
        "partition complete and leak-free",
        partition_check["complete"]
        and partition_check["shared_components_across_partitions"] == 0
        and partition_check["shared_exact_texts_across_partitions"] == 0,
        json.dumps(partition_check, sort_keys=True),
    )
    near_duplicates = {
        "method": (
            "union-find over shared human-text identity plus word-8-shingle "
            "Jaccard >= 0.8 (exact verification; crc32 index proposes "
            "candidates only). Cross-language near-dup pairs are covered by "
            "the same global index; the shared-human-text check additionally "
            "catches train/test overlap of the underlying human texts."
        ),
        "n_components": len(components),
        "component_size_histogram": {str(k): v for k, v in sorted(comp_sizes.items())},
        "near_dup_pairs_jaccard_ge_0_8_total": len(near_dup_pairs),
        "near_dup_pairs_within_group": sum(1 for p in near_dup_pairs if p["same_group"]),
        "near_dup_pairs_across_groups": sum(1 for p in near_dup_pairs if not p["same_group"]),
        "exact_duplicate_pairs_jaccard_1_0_within_group": sum(
            1 for p in near_dup_pairs if p["jaccard"] == 1.0 and p["same_group"]
        ),
        "exact_duplicate_pairs_jaccard_1_0_across_groups": sum(
            1 for p in near_dup_pairs if p["jaccard"] == 1.0 and not p["same_group"]
        ),
        "near_dup_pairs_sample": near_dup_pairs[:5],
        "shared_human_texts_train_test_sampled": len(shared_human_texts),
    }
    deep_compare("near_duplicates", near_duplicates, b["near_duplicates"])

    # Partition manifests: per-row cluster + partition, counts, SHAs.
    manifest_refs = {}
    for part in ("fit", "validation", "final-test"):
        # NOTE (W8-B recovery, 2026-11-16): "detectrl_x" with an
        # UNDERSCORE — that is the real manifest stem (see B's artifact
        # partition.manifests paths and the files on disk). The original
        # (Worker E, cb6f6f0) used a hyphen ("detectrl-x-"), which made
        # the manifest-exists check FAIL and read_text raise
        # FileNotFoundError even though the manifests exist and their
        # SHAs match the artifact.
        mpath = (
            WORKER_B_ROOT
            / "docs"
            / "evidence"
            / "manifests"
            / f"EV-20261116-detectrl_x-{part}.json"
        )
        check(f"manifest {part} exists", mpath.exists(), str(mpath))
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
        manifest_refs[part] = {
            "path": str(mpath.relative_to(WORKER_B_ROOT)),
            "sha256": _sha256_file(mpath),
        }
        part_rows = [r for r in rows if r["partition"] == part]
        check(
            f"manifest {part} n_rows",
            manifest["n_rows"] == len(part_rows),
            f"{manifest['n_rows']} vs {len(part_rows)}",
        )
        check(
            f"manifest {part} n_human/n_ai",
            manifest["n_human"] == sum(1 for r in part_rows if r["label"] == 0)
            and manifest["n_ai"] == sum(1 for r in part_rows if r["label"] == 1),
            f"{manifest['n_human']}/{manifest['n_ai']}",
        )
        check(
            f"manifest {part} n_components",
            manifest["n_components"] == len({r["cluster"] for r in part_rows}),
            str(manifest["n_components"]),
        )
        by_sid = {r["source_id"]: r for r in part_rows}
        mismatches = 0
        for entry in manifest["entries"]:
            mine = by_sid.get(entry["source_id"])
            if (
                mine is None
                or entry["text_sha256"] != mine["text_sha256"]
                or entry["label"] != mine["label"]
                or entry["cluster_id"] != mine["cluster"]
                or entry["stratum"] != mine["stratum"]
                or entry["kind"] != mine["kind"]
            ):
                mismatches += 1
        check(
            f"manifest {part} entries match recomputation",
            mismatches == 0,
            f"{mismatches} mismatches / {len(manifest['entries'])} entries",
        )
        check(
            f"manifest {part} covers exactly its rows",
            set(by_sid) == {e["source_id"] for e in manifest["entries"]},
            f"{len(by_sid)} rows vs {len(manifest['entries'])} entries",
        )
    partition = {
        "method": (
            "whole components, stratified by language, deterministic hash order, "
            "greedy 60/20/20 by row count; partition uses text identity only, "
            "frozen before evaluation"
        ),
        "fractions": PARTITION_FRACTIONS,
        "counts": {
            part: {
                "n": sum(1 for r in rows if r["partition"] == part),
                "n_human": sum(1 for r in rows if r["partition"] == part and r["label"] == 0),
                "n_ai": sum(1 for r in rows if r["partition"] == part and r["label"] == 1),
                "n_components": len({r["cluster"] for r in rows if r["partition"] == part}),
            }
            for part in ("fit", "validation", "final-test")
        },
        "verification": partition_check,
        "manifests": manifest_refs,
    }
    deep_compare("partition", partition, b["partition"])

    # --- 6. Scoring (fresh detector) + determinism spot check ---
    print("[detectrl_x] evaluating detector at native operating point ...", flush=True)
    detector = BuiltinHeuristicDetector()
    for row in rows:
        prediction = detector.detect(row["text"])
        row["score"] = float(prediction.score)
        row["verdict"] = prediction.verdict
    sample = rows[:: max(1, len(rows) // 20)][:20]
    mismatches = 0
    for row in sample:
        again = detector.detect(row["text"])
        if float(again.score) != row["score"] or again.verdict != row["verdict"]:
            mismatches += 1
    determinism = {"rows_rechecked": len(sample), "mismatches": mismatches}
    check("determinism spot check", mismatches == 0, f"{mismatches} mismatches / {len(sample)}")
    deep_compare("determinism_spot_check", determinism, b["determinism_spot_check"])

    # --- 7. Slices: ONE shared rng, Worker B's exact call order ---
    rng = random.Random(BOOTSTRAP_SEED)
    final_test = [r for r in rows if r["partition"] == "final-test"]
    pooled = slice_metrics(rows, bootstrap=True, cluster_bootstrap=False, rng=rng)
    final_test_metrics = slice_metrics(final_test, bootstrap=True, cluster_bootstrap=True, rng=rng)
    by_lang_pooled = _group_slices(
        rows, key="lang", bootstrap=True, cluster_bootstrap=False, rng=rng
    )
    by_domain_pooled = _group_slices(
        rows, key="domain", bootstrap=True, cluster_bootstrap=False, rng=rng
    )
    by_generator_pooled = _group_slices(
        rows, key="model", bootstrap=True, cluster_bootstrap=False, rng=rng
    )
    by_split_pooled = _group_slices(
        rows, key="split", bootstrap=True, cluster_bootstrap=False, rng=rng
    )
    by_lang_final_test = _group_slices(
        final_test, key="lang", bootstrap=True, cluster_bootstrap=False, rng=rng
    )
    by_domain_final_test = _group_slices(
        final_test, key="domain", bootstrap=False, cluster_bootstrap=False, rng=rng
    )
    # Independent AUROC cross-check (pairwise vs rank form) on pooled + final-test.
    for tag, items in (("pooled", rows), ("final_test", final_test)):
        labels = [it["label"] for it in items]
        scores = [it["score"] for it in items]
        pw = round(auroc_pairwise(labels, scores), 6)
        rk = round(_roc_metrics(labels, scores)["auroc"], 6)
        check(f"{tag} AUROC pairwise == rank form", pw == rk, f"{pw} vs {rk}")
    deep_compare("pooled", pooled, b["pooled"])
    deep_compare("final_test", final_test_metrics, b["final_test"])
    deep_compare("by_lang_pooled", by_lang_pooled, b["by_lang_pooled"])
    deep_compare("by_domain_pooled", by_domain_pooled, b["by_domain_pooled"])
    deep_compare("by_generator_pooled", by_generator_pooled, b["by_generator_pooled"])
    deep_compare("by_split_pooled", by_split_pooled, b["by_split_pooled"])
    deep_compare("by_lang_final_test", by_lang_final_test, b["by_lang_final_test"])
    deep_compare("by_domain_final_test", by_domain_final_test, b["by_domain_final_test"])

    # --- 8. Fixed blocks: provenance, licence, worst-slice context, locks, drops ---
    compare("provenance.source_file", DETECTRL_X_FILE, b["provenance"]["source_file"])
    compare(
        "provenance.source_file_sha256", DETECTRL_X_SHA256, b["provenance"]["source_file_sha256"]
    )
    compare("provenance.source_file_bytes", DETECTRL_X_BYTES, b["provenance"]["source_file_bytes"])
    deep_compare("provenance.split_rows_verified", counts, b["provenance"]["split_rows_verified"])
    deep_compare(
        "provenance.sampled_source_rows",
        {"train": DETECTRL_X_TRAIN_N, "test": DETECTRL_X_TEST_N},
        b["provenance"]["sampled_source_rows"],
    )
    compare("detector", BuiltinHeuristicDetector.detector_id, b["detector"])
    compare("detector_version", BuiltinHeuristicDetector.detector_version, b["detector_version"])
    compare("detector_family", "stylometric-heuristic", b["detector_family"])
    compare("operating_point", OPERATING_POINT, b["operating_point"])
    # worst_slice_context: the two n_human counts are recomputed and
    # compared; the note is fixed prose (it references the OpAI-Bench
    # worst slice, already closed in Phase 5) — checked for presence
    # and content, not recomputed, because it contains no
    # DetectRL-X numbers of its own.
    compare(
        "worst_slice_context.detectrl_x_pooled_n_human",
        sum(1 for r in rows if r["label"] == 0),
        b["worst_slice_context"]["detectrl_x_pooled_n_human"],
    )
    compare(
        "worst_slice_context.detectrl_x_final_test_n_human",
        sum(1 for r in final_test if r["label"] == 0),
        b["worst_slice_context"]["detectrl_x_final_test_n_human"],
    )
    check(
        "worst_slice_context.note present and references OpAI-Bench",
        isinstance(b["worst_slice_context"]["note"], str)
        and "OpAI-Bench" in b["worst_slice_context"]["note"]
        and "0.064196" in b["worst_slice_context"]["note"],
    )
    lock = {}
    for name in ("requirements-pinned.txt", "requirements-hashed.txt"):
        p = REPO_ROOT / name
        if p.exists():
            lock[name] = _sha256_file(p)
    deep_compare("dependency_lock", lock, b["dependency_lock"])
    drops_out = [
        {
            "item": "full-corpus evaluation (249,600 normalised rows)",
            "reason": (
                "expanded stratified sample only: 12,000 source rows "
                "(8,000 train + 4,000 test) -> 24,000 normalised rows; a "
                "full-file run at ~54 rows/s plus a 250k-row near-duplicate "
                "graph is out of scope for this wave"
            ),
        },
        {
            "item": "15 of 16 Binary files + all Ternary files",
            "reason": (
                "single-file slice only: Binary/binary_general_open.json; the "
                "README states the train split is identical across all strategy "
                "files, so the general file is the representative slice; Ternary "
                "files are out of scope for this measurement"
            ),
        },
        {
            "item": "HF viewer / default dataset load",
            "reason": (
                "broken (DatasetGenerationCastError: perturbation files add a "
                "perturbation_info column); per-file load only"
            ),
        },
        {
            "item": "Python 3.11, 3.13, 3.14, 3.15",
            "reason": "measured on the local interpreter only; CI covers the matrix",
        },
        {
            "item": "train/test threshold selection and calibration",
            "reason": (
                "no threshold was fitted and no calibration was performed; "
                "AUROC/TPR@FPR/AUPRC are threshold-free ROC properties and the "
                "native FPR/TPR use the detector's fixed operating point"
            ),
        },
        {
            "item": "commercial use and redistribution of rows",
            "reason": (
                "three-way licence conflict; strictest reading (non-commercial "
                "academic research only) governs; local cache only, aggregate "
                "metrics only, no redistribution"
            ),
        },
        {
            "item": f"{len(drops)} source rows refused by the mapper",
            "reason": "each is listed in results.drops_from_mapping with its file index and cause",
        },
    ]
    deep_compare("drops", drops_out, b_artifact.get("drops"))
    # Licence: Worker B re-verified the three-way licence conflict
    # live on 2026-11-16 (HF card + GitHub repo + ACL paper). This
    # reproduction does NOT re-run a live licence check; it verifies
    # only that the record is dated today and records B's verdict
    # verbatim as un-re-verified provenance, not as an agreed field.
    compare("licence_reverified.date", RUN_DATE, b["licence_reverified"]["date"])
    check(
        "licence_reverified.verdict present (not independently re-verified)",
        isinstance(b["licence_reverified"].get("verdict"), str)
        and len(b["licence_reverified"]["verdict"]) > 0,
    )

    n_agree = sum(1 for c in comparison if c["agree"])
    print(
        f"comparison: {n_agree}/{len(comparison)} fields agree; {len(discrepancies)} discrepancies",
        flush=True,
    )
    for d in discrepancies:
        print(
            f"  DISCREPANCY {d['field']}: reproduction={d['reproduction']} worker_b={d['worker_b']}",
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

    env_lock: dict = {"platform": platform.system(), "python": platform.python_version()}
    try:
        freeze = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        env_lock["extras"] = freeze.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        env_lock["extras"] = f"pip freeze unavailable: {exc}"

    artifact = {
        "schema": RUN_ARTIFACT_SCHEMA,
        "evidence_record_id": ARTIFACT_ID,
        "kind": "command",
        "command": "python scripts/reproduce_w8b_detectrl_x.py",
        "environment": env_lock,
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "reproduces": "EV-20261116-dataset-detectrl-x",
            "reproduces_artifact_sha256": b_sha,
            "reproduces_artifact_code_version": b_artifact.get("code_version"),
            "detector": BuiltinHeuristicDetector.detector_id,
            "detector_family": "stylometric-heuristic",
            "detector_version": BuiltinHeuristicDetector.detector_version,
            "operating_point": OPERATING_POINT,
            "method": (
                "Independent reproduction of Worker B's DetectRL-X expanded-sample "
                "evaluation: raw source file verified by size + SHA-256, "
                "re-streamed once with the frozen strided sample and re-mapped; "
                "normalised caches verified by SHA-256 and row-by-row against "
                "the fresh mapping; inspection block re-derived; near-duplicate "
                "components and the language-stratified 60/20/20 partition "
                "re-derived and compared per-row against the frozen manifests; "
                "detector re-run fresh at its native operating point; every "
                "slice recomputed with Worker B's exact conventions (one shared "
                "Random(20261116) stream in the fixed call order, row bootstrap "
                "via randrange, cluster bootstrap via choice, Wilson FPR/TPR "
                "from my own formula implementation). AUROC cross-checked "
                "pairwise vs rank form. No tuning on the final holdout."
            ),
            "identity_checks": checks,
            "inspection": inspection,
            "near_duplicates": near_duplicates,
            "partition": partition,
            "pooled": pooled,
            "final_test": final_test_metrics,
            "by_lang_pooled": by_lang_pooled,
            "by_domain_pooled": by_domain_pooled,
            "by_generator_pooled": by_generator_pooled,
            "by_split_pooled": by_split_pooled,
            "by_lang_final_test": by_lang_final_test,
            "by_domain_final_test": by_domain_final_test,
            "determinism_spot_check": determinism,
            "comparison": comparison,
            "discrepancies": discrepancies,
            "verdict": verdict,
        },
        "drops": [
            {
                "item": "Worker B fit/validation partitions (scored, but headline is final-test)",
                "reason": "pooled metrics are reproduced; the headline comparison is the "
                "final-test holdout, which influenced no decision",
            },
            {
                "item": "Full-corpus evaluation (249,600 normalised rows)",
                "reason": "expanded stratified sample only; see the reproduced artifact's drops",
            },
        ],
        "badge": "available",
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "notes": (
            "Independent reproduction of Worker B's DetectRL-X expanded-sample "
            "evaluation. Every compared field either agrees exactly or is listed "
            "in 'discrepancies'. "
            f"Reproduction verdict: {verdict}. Pooled as re-measured here: human "
            f"FPR {pooled['k_fp_native']}/{pooled['n_human']} "
            f"(Wilson 95% {pooled['fpr_native_wilson_95']}), native TPR "
            f"{pooled['k_tp_native']}/{pooled['n_ai']}, AUROC {pooled['auroc']} "
            f"(bootstrap 95% CI {pooled['bootstrap_95']['auroc'] if pooled.get('bootstrap_95') else None}); "
            f"final-test human FPR {final_test_metrics['k_fp_native']}/{final_test_metrics['n_human']} "
            f"(Wilson 95% {final_test_metrics['fpr_native_wilson_95']}), native TPR "
            f"{final_test_metrics['k_tp_native']}/{final_test_metrics['n_ai']}, AUROC "
            f"{final_test_metrics['auroc']}. A below-chance or near-chance ranking "
            "result is reported as measured, not tuned around. The native "
            "operating point is unchanged."
        ),
    }
    errors = validate_run_artifact(artifact)
    print(f"run-artifact/v1 validation errors: {len(errors)}")
    for error in errors:
        print(f"  - {error}")
    if errors:
        return 2
    if args.check:
        print("check mode: no artifact file written")
        return 0 if verdict == "AGREE" else 1
    output = (
        Path(args.output)
        if args.output
        else REPO_ROOT / "docs" / "evidence" / "runs" / f"{ARTIFACT_ID}.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)})")
    return 0 if verdict == "AGREE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
