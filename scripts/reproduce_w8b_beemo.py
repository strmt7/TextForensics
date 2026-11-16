#!/usr/bin/env python3
"""reproduce_w8b_beemo.py — W8 worker E (independent reproduction).

Independently reproduces Worker B's Beemo full-split evaluation
(docs/evidence/runs/EV-20261116-dataset-beemo.json) from scratch:

- Reads the pinned cache file (beemo/default/train-full.jsonl) DIRECTLY
  as JSONL; no import of Worker B's script, no import of
  scripts/measure_datasets.py.
- Verifies the cache SHA-256, row count, and the inspection counts.
- Verifies every partition-manifest entry against the cache
  (source_id, canonical text SHA-256, label, kind, stratum).
- Recomputes the near-duplicate components INDEPENDENTLY (union-find
  over shared prompt identity plus exact word-8-shingle Jaccard >= 0.8
  via a crc32 candidate index, following the documented algorithm) and
  checks component count/size histogram, per-row cluster ids, and the
  near-duplicate pair counts — including whether any pair is genuinely
  cross-prompt.
- Re-derives the stratified greedy 60/20/20 whole-component partition
  and checks it row by row against the frozen manifests.
- Re-scores all 19,683 rows with a fresh BuiltinHeuristicDetector at
  its native operating point; re-runs the determinism spot check.
- Recomputes every reported point metric with INDEPENDENT
  implementations (Wilson interval from the formula; AUROC by pairwise
  Mann-Whitney counting AND by the rank walk — both must agree;
  stepwise average precision; TPR@FPR by the documented
  distinct-threshold convention) and every bootstrap CI by replicating
  the documented procedure (single shared rng, seed 20261116, 1000
  resamples, row bootstrap then cluster bootstrap, in the documented
  slice order) with independently written code.
- Compares every field of Worker B's artifact against the
  recomputation and reports agreement or ANY discrepancy, however
  small. A discrepancy is a finding, not something to smooth over.

Usage:
    python scripts/reproduce_w8b_beemo.py [--check]
    python scripts/reproduce_w8b_beemo.py --output <path>

--check measures and compares only; it writes nothing.
The default output is docs/evidence/runs/EV-20261116-reproduction-beemo.json.
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
sys.path.insert(0, str(REPO_ROOT / "src"))

from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-reproduction-beemo"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
B_ARTIFACT = REPO_ROOT / "docs" / "evidence" / "runs" / "EV-20261116-dataset-beemo.json"
# Host-neutral: the W8-B worker worktree the paths used to name is
# deleted; the artifacts live at these repo-relative paths on every
# checkout.
B_MANIFESTS = REPO_ROOT / "docs" / "evidence" / "manifests"
CACHE_FILE = (
    Path.home() / ".cache" / "textforensics" / "datasets" / "beemo" / "default" / "train-full.jsonl"
)
BOOTSTRAP_SEED = 20261116
N_BOOTSTRAP = 1000
SHINGLE_N = 8
NEAR_DUP_JACCARD = 0.8
PARTITION_FRACTIONS = {"fit": 0.60, "validation": 0.20, "final-test": 0.20}
OPERATING_POINT = "builtin-heuristic native verdict (analyze_text); no score threshold"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_text_sha256(text: str) -> str:
    """SHA-256 of the canonical-LF representation (CRLF/CR -> LF)."""
    return hashlib.sha256(
        text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    ).hexdigest()


def _code_version() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


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


def roc_metrics(labels: list[int], scores: list[float]) -> dict[str, float]:
    """AUROC (rank walk with average ranks), AUPRC (stepwise average
    precision), TPR@FPR 1%/5% (max TPR among distinct-score thresholds
    with empirical FPR <= target). One ascending sort; the descending
    walk reuses it. Mathematically identical to the pairwise AUROC
    (cross-checked on every slice below)."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        raise ValueError("roc_metrics needs both classes present")
    asc = sorted(zip(scores, labels, strict=True))  # (score, label), ascending
    rank_sum = 0.0
    i = 0
    n = len(asc)
    while i < n:
        j = i
        while j < n and asc[j][0] == asc[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            if asc[k][1] == 1:
                rank_sum += avg_rank
        i = j
    auroc = (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)
    tp = fp = 0
    ap = 0.0
    prev_recall = 0.0
    best = {0.01: 0.0, 0.05: 0.0}
    idx = n - 1
    while idx >= 0:
        threshold = asc[idx][0]
        while idx >= 0 and asc[idx][0] == threshold:
            if asc[idx][1] == 1:
                tp += 1
            else:
                fp += 1
            idx -= 1
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


def bootstrap_ci(labels: list[int], scores: list[float], rng: random.Random) -> dict | None:
    """Percentile row-bootstrap 95% CIs (1000 resamples, seed from the
    shared rng stream): resample row indices with replacement, recompute
    the ROC metrics, report the 2.5%/97.5% percentile interval with the
    documented index convention. None when a class has < 10 rows."""
    n = len(labels)
    if min(sum(labels), n - sum(labels)) < 10:
        return None
    keys = ("auroc", "auprc", "tpr_at_fpr_0_01", "tpr_at_fpr_0_05")
    draws: dict[str, list[float]] = {k: [] for k in keys}
    skipped = 0
    for _ in range(N_BOOTSTRAP):
        idx = [rng.randrange(n) for _ in range(n)]
        sub_labels = [labels[i] for i in idx]
        if min(sum(sub_labels), n - sum(sub_labels)) == 0:
            skipped += 1
            continue
        m = roc_metrics(sub_labels, [scores[i] for i in idx])
        for k in keys:
            draws[k].append(m[k])
    out: dict = {}
    for k in keys:
        vals = sorted(draws[k])
        out[k] = [
            round(vals[int(0.025 * len(vals))], 4),
            round(vals[int(0.975 * len(vals)) - 1], 4),
        ]
    out["resamples"] = [len(draws["auroc"]), skipped]
    return out


def cluster_bootstrap_ci(items: list[dict], rng: random.Random) -> dict | None:
    """Cluster-bootstrap 95% CIs (resample components with replacement):
    CIs for native FPR, native TPR and AUROC. None when fewer than 10
    components."""
    clusters: dict[str, list[dict]] = defaultdict(list)
    for it in items:
        clusters[it["cluster"]].append(it)
    keys = sorted(clusters)
    if len(keys) < 10:
        return None
    fprs, tprs, aurocs = [], [], []
    skipped = 0
    for _ in range(N_BOOTSTRAP):
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
        aurocs.append(roc_metrics(labels, scores)["auroc"])

    def _ci(vals: list[float]) -> list[float]:
        vals = sorted(vals)
        return [round(vals[int(0.025 * len(vals))], 4), round(vals[int(0.975 * len(vals)) - 1], 4)]

    if not fprs:
        return None
    return {
        "fpr_native": _ci(fprs),
        "tpr_native": _ci(tprs),
        "auroc": _ci(aurocs),
        "resamples_kept": len(fprs),
        "resamples_skipped": skipped,
    }


def slice_metrics(
    items: list[dict], *, bootstrap: bool, cluster_bootstrap: bool, rng: random.Random
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
        lo, hi = wilson(k_fp, n_human)
        fpr_wilson = [round(lo, 6), round(hi, 6)]
    tpr_wilson = None
    if n_ai:
        lo, hi = wilson(k_tp, n_ai)
        tpr_wilson = [round(lo, 6), round(hi, 6)]
    roc = roc_metrics(labels, scores) if n_human and n_ai else None
    # Cross-check the rank-walk AUROC against direct pairwise counting.
    if roc is not None:
        pairwise = auroc_pairwise(labels, scores)
        assert abs(pairwise - roc["auroc"]) < 1e-9, (
            f"AUROC implementations disagree: pairwise={pairwise} rank={roc['auroc']}"
        )
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
        out["bootstrap_95"] = bootstrap_ci(labels, scores, rng)
    if cluster_bootstrap:
        out["cluster_bootstrap_95"] = cluster_bootstrap_ci(items, rng)
    return out


def group_slices(
    rows: list[dict], *, key: str, bootstrap: bool, rng: random.Random
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


# --- Near-duplicate components (independent implementation) ---


def _tokens(text: str) -> list[str]:
    return " ".join(text.split()).lower().split()


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
    """Union (a) rows sharing a prompt group key and (b) row pairs with
    exact word-8-shingle Jaccard >= 0.8, candidates proposed by a crc32
    shingle index (a pair can only reach J >= 0.8 if it shares at least
    ceil(0.8 * |A|) hashed shingles) and verified exactly."""
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


def assign_partitions(rows: list[dict], components: list[list[int]]) -> dict[int, str]:
    """Whole components to fit/validation/final-test, stratified by
    majority stratum (category), deterministic hash order, greedy
    60/20/20 by row count (furthest below target; ties fit, validation,
    final-test)."""
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
                f"w8-b:beemo:{_component_id(rows, components[ci])}".encode()
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true", help="measure and compare only; write nothing"
    )
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    b_artifact = json.loads(B_ARTIFACT.read_text(encoding="utf-8"))
    b = b_artifact["results"]
    b_artifact_sha = _sha256_file(B_ARTIFACT)
    checks: list[dict] = []
    comparison: list[dict] = []
    discrepancies: list[dict] = []
    findings: list[dict] = []

    def check(name: str, ok: bool, detail: str = "", *, finding: bool = False) -> None:
        checks.append(
            {"check": name, "passed": bool(ok), "detail": str(detail), "finding": finding}
        )
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)
        if finding and not ok:
            findings.append({"check": name, "detail": str(detail)})

    def compare(path: str, mine, theirs) -> None:
        same = mine == theirs
        comparison.append({"field": path, "reproduction": mine, "worker_b": theirs, "agree": same})
        if not same:
            discrepancies.append({"field": path, "reproduction": mine, "worker_b": theirs})

    # --- 1. Cache file ---
    cache_sha = _sha256_file(CACHE_FILE)
    check(
        "cache sha256 train-full.jsonl",
        cache_sha == b["provenance"]["cache"]["file_sha256"],
        f"{cache_sha[:12]}... vs artifact {b['provenance']['cache']['file_sha256'][:12]}...",
    )
    raw_rows = [
        json.loads(line)
        for line in CACHE_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    check(
        "cache row count 19683",
        len(raw_rows) == 19683 == b["provenance"]["cache"]["rows"],
        f"{len(raw_rows)} rows",
    )
    check(
        "cache row count matches provenance rows", len(raw_rows) == b["provenance"]["cache"]["rows"]
    )
    rows: list[dict] = []
    for r in raw_rows:
        rows.append(
            {
                "source_id": r["source_id"],
                "text": r["text"],
                "label": int(r["label"]),
                "kind": str(r["meta"].get("kind")),
                "stratum": str(r["meta"].get("category")),
                "group_key": "prompt:" + str(r["meta"].get("prompt_id")),
                "text_sha256": _canonical_text_sha256(r["text"]),
                "category": str(r["meta"].get("category")),
                "generator": str(r["meta"].get("generator")),
            }
        )

    # --- 2. Manifests: entries vs cache; SHAs vs artifact ---
    manifests: dict[str, dict] = {}
    manifest_shas: dict[str, str] = {}
    for part in ("fit", "validation", "final-test"):
        path = B_MANIFESTS / f"EV-20261116-beemo-{part}.json"
        manifests[part] = json.loads(path.read_text(encoding="utf-8"))
        manifest_shas[part] = _sha256_file(path)
    by_source = {r["source_id"]: r for r in rows}
    manifest_mismatch = {"missing": 0, "text_sha256": 0, "label": 0, "kind": 0, "stratum": 0}
    all_entries = []
    for part, m in manifests.items():
        for e in m["entries"]:
            all_entries.append((part, e))
            r = by_source.get(e["source_id"])
            if r is None:
                manifest_mismatch["missing"] += 1
                continue
            if r["text_sha256"] != e["text_sha256"]:
                manifest_mismatch["text_sha256"] += 1
            if r["label"] != e["label"]:
                manifest_mismatch["label"] += 1
            if r["kind"] != e["kind"]:
                manifest_mismatch["kind"] += 1
            if r["stratum"] != e["stratum"]:
                manifest_mismatch["stratum"] += 1
    for field, count in manifest_mismatch.items():
        check(
            f"manifest entries {field}: 0 mismatches",
            count == 0,
            f"{count} / {len(all_entries)} entries",
        )
    check(
        "manifests cover all 19683 rows exactly once",
        len(all_entries) == 19683 and len({e["source_id"] for _, e in all_entries}) == 19683,
        f"{len(all_entries)} entries",
    )
    for part, m in manifests.items():
        ref = b["partition"]["manifests"][part]["sha256"]
        current_matches = manifest_shas[part] == ref
        recon = dict(m)
        recon["code_version"] = b_artifact["code_version"]
        recon_sha = hashlib.sha256(
            (json.dumps(recon, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ).hexdigest()
        # FINDING (not a metrics failure): the manifests on disk were
        # re-frozen under code_version 895577c after the artifact was
        # written at 4881e15, so the artifact's recorded SHA no longer
        # matches the current file. The entries are unchanged (see the
        # reconstruction check below, which reproduces the recorded SHA
        # exactly). The artifact's manifest pointers are therefore stale.
        check(
            f"manifest {part} sha matches artifact reference (current file)",
            current_matches,
            f"current {manifest_shas[part][:12]} vs recorded {ref[:12]}",
            finding=True,
        )
        check(
            f"manifest {part} entries identical to artifact-time file "
            f"(reconstructed with artifact code_version)",
            recon_sha == ref,
            f"reconstructed {recon_sha[:12]} vs recorded {ref[:12]}",
        )

    # --- 3. Components (independent recomputation) ---
    print("building near-duplicate components ...", flush=True)
    components, near_dup_pairs = build_components(rows)
    comp_sizes = Counter(len(c) for c in components)
    check("component count is 2187", len(components) == 2187, f"{len(components)}")
    check(
        "component size histogram is {9: 2187}",
        dict(comp_sizes) == {9: 2187},
        json.dumps(dict(comp_sizes), sort_keys=True),
    )
    comp_id_of: dict[int, str] = {}
    for members in components:
        cid = _component_id(rows, members)
        for j in members:
            comp_id_of[j] = cid
    manifest_cluster: dict[str, str] = {}
    for _part, m in manifests.items():
        for e in m["entries"]:
            manifest_cluster[e["source_id"]] = e["cluster_id"]
    cluster_mismatch = sum(
        1 for i, r in enumerate(rows) if manifest_cluster.get(r["source_id"]) != comp_id_of[i]
    )
    check(
        "per-row cluster_id matches recomputed components",
        cluster_mismatch == 0,
        f"{cluster_mismatch} mismatches / {len(rows)} rows",
    )
    total_pairs = len(near_dup_pairs)
    within = sum(1 for p in near_dup_pairs if p["same_group"])
    across = total_pairs - within
    exact_within = sum(1 for p in near_dup_pairs if p["jaccard"] == 1.0 and p["same_group"])
    exact_across = sum(1 for p in near_dup_pairs if p["jaccard"] == 1.0 and not p["same_group"])
    check("near-dup pairs J>=0.8 total is 311", total_pairs == 311, f"{total_pairs}")
    check(
        "near-dup pairs within-group is 311 (artifact says 'cross-prompt' 311)",
        within == 311,
        f"within={within} across={across}",
    )
    check("near-dup pairs across prompts is 0", across == 0, f"across={across}")
    check(
        "exact-duplicate (J=1.0) pairs within-group is 218", exact_within == 218, f"{exact_within}"
    )
    check("exact-duplicate (J=1.0) pairs across groups is 0", exact_across == 0, f"{exact_across}")
    sample = b["near_duplicates"]["near_dup_pairs_sample"]
    pair_set = {(p["row_a"], p["row_b"], p["jaccard"]) for p in near_dup_pairs}
    sample_present = all((s["row_a"], s["row_b"], s["jaccard"]) in pair_set for s in sample)
    check(
        "artifact near-dup sample pairs are all in recomputed pair set",
        sample_present,
        f"{len(sample)} sample pairs",
    )
    check(
        "artifact near_duplicates.n_components is 2187",
        b["near_duplicates"]["n_components"] == 2187,
    )
    check(
        "artifact near_duplicates.component_size_histogram is {9: 2187}",
        b["near_duplicates"]["component_size_histogram"] == {"9": 2187},
    )

    # --- 4. Partition (independent re-derivation) ---
    print("re-deriving partition assignment ...", flush=True)
    assignment = assign_partitions(rows, components)
    part_of = {}
    for part, m in manifests.items():
        for e in m["entries"]:
            part_of[e["source_id"]] = part
    part_mismatch = sum(
        1 for i, r in enumerate(rows) if part_of.get(r["source_id"]) != assignment[i]
    )
    check(
        "per-row partition matches frozen manifests",
        part_mismatch == 0,
        f"{part_mismatch} mismatches / {len(rows)} rows",
    )
    for part in ("fit", "validation", "final-test"):
        mine_n = sum(1 for i in range(len(rows)) if assignment[i] == part)
        mine_h = sum(1 for i in range(len(rows)) if assignment[i] == part and rows[i]["label"] == 0)
        mine_a = sum(1 for i in range(len(rows)) if assignment[i] == part and rows[i]["label"] == 1)
        mine_c = len({comp_id_of[i] for i in range(len(rows)) if assignment[i] == part})
        theirs = b["partition"]["counts"][part]
        check(
            f"partition counts {part}",
            (mine_n, mine_h, mine_a, mine_c)
            == (theirs["n"], theirs["n_human"], theirs["n_ai"], theirs["n_components"]),
            f"mine {(mine_n, mine_h, mine_a, mine_c)} vs artifact {(theirs['n'], theirs['n_human'], theirs['n_ai'], theirs['n_components'])}",
        )
    for i, r in enumerate(rows):
        r["cluster"] = comp_id_of[i]
        r["partition"] = assignment[i]

    # --- 5. Inspection counts ---
    insp = b["inspection"]
    check("inspection raw_rows_fetched 2187", insp["raw_rows_fetched"] == 2187)
    prompt_ids = {
        json.loads(line)["meta"]["prompt_id"]
        for line in CACHE_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    check(
        "inspection prompt_ids_unique 2187 (recomputed)",
        len(prompt_ids) == 2187,
        f"{len(prompt_ids)}",
    )
    # Inspection counts are per RAW row (2,187); the cache holds 9
    # normalised rows per raw row, so cache counts must be exactly 9x
    # the inspection counts (verified 2026-11-16: 1845/9=205, 5265/9=585,
    # ... — a direct equality check would be a script bug, not a
    # Worker B discrepancy).
    check(
        "inspection categories match cache at 9x (per-raw-row counts)",
        {k: v // 9 for k, v in sorted(Counter(r["category"] for r in rows).items())}
        == dict(sorted(insp["categories"].items()))
        and all(v % 9 == 0 for v in Counter(r["category"] for r in rows).values()),
        json.dumps(dict(sorted(Counter(r["category"] for r in rows).items()))),
    )
    check(
        "inspection generators match cache at 9x (per-raw-row counts)",
        {k: v // 9 for k, v in sorted(Counter(r["generator"] for r in rows).items())}
        == dict(sorted(insp["generators"].items()))
        and all(v % 9 == 0 for v in Counter(r["generator"] for r in rows).values()),
    )
    check(
        "inspection kinds match cache",
        dict(sorted(Counter(r["kind"] for r in rows).items()))
        == dict(sorted(insp["kinds"].items())),
    )
    check(
        "inspection actual_variants_per_raw_row is 9.0", insp["actual_variants_per_raw_row"] == 9.0
    )
    check(
        "drops_from_mapping is empty, n_mapping_drops 0",
        b["drops_from_mapping"] == [] and b["n_mapping_drops"] == 0,
    )

    # --- 6. Score all rows; determinism spot check ---
    print("scoring all rows with a fresh detector ...", flush=True)
    detector = BuiltinHeuristicDetector()
    for r in rows:
        pred = detector.detect(r["text"])
        r["score"] = float(pred.score)
        r["verdict"] = str(pred.verdict)
    step = max(1, len(rows) // 20)
    sample_rows = rows[::step][:20]
    mismatches = 0
    for r in sample_rows:
        again = detector.detect(r["text"])
        if float(again.score) != r["score"] or str(again.verdict) != r["verdict"]:
            mismatches += 1
    check(
        "determinism spot check: 20 rows, 0 mismatches",
        len(sample_rows) == 20 and mismatches == 0,
        f"{len(sample_rows)} rows, {mismatches} mismatches",
    )
    compare(
        "determinism_spot_check",
        {"rows_rechecked": len(sample_rows), "mismatches": mismatches},
        b["determinism_spot_check"],
    )

    # --- 7. Recompute slices in Worker B's exact rng order ---
    print("recomputing slices (shared rng, seed 20261116) ...", flush=True)
    rng = random.Random(BOOTSTRAP_SEED)
    final_test = [r for r in rows if r["partition"] == "final-test"]
    pooled_m = slice_metrics(rows, bootstrap=True, cluster_bootstrap=False, rng=rng)
    final_m = slice_metrics(final_test, bootstrap=True, cluster_bootstrap=True, rng=rng)
    by_kind_pooled = group_slices(rows, key="kind", bootstrap=True, rng=rng)
    by_cat_pooled = group_slices(rows, key="category", bootstrap=True, rng=rng)
    by_gen_pooled = group_slices(rows, key="generator", bootstrap=True, rng=rng)
    by_kind_ft = group_slices(final_test, key="kind", bootstrap=False, rng=rng)
    by_cat_ft = group_slices(final_test, key="category", bootstrap=True, rng=rng)

    def compare_slice(path: str, mine: dict, theirs: dict) -> None:
        for field in (
            "n",
            "n_human",
            "n_ai",
            "k_fp_native",
            "k_tp_native",
            "fpr_native",
            "fpr_native_wilson_95",
            "tpr_native",
            "tpr_native_wilson_95",
            "auroc",
            "auprc",
            "auprc_baseline_prevalence",
            "tpr_at_fpr_0_01",
            "tpr_at_fpr_0_05",
            "coverage",
            "abstentions",
            "abstention_rate",
            "max_human_score",
            "operating_point",
        ):
            compare(f"{path}.{field}", mine.get(field), theirs.get(field))
        for lab in ("score_human", "score_machine"):
            for sub in ("mean", "median", "min", "max"):
                mval = (mine.get(lab) or {}).get(sub)
                tval = (theirs.get(lab) or {}).get(sub)
                compare(f"{path}.{lab}.{sub}", mval, tval)
        for boot in ("bootstrap_95", "cluster_bootstrap_95"):
            compare(f"{path}.{boot}.present", boot in mine, boot in theirs)
            if boot in mine and boot in theirs:
                for k in sorted(set(mine[boot]) | set(theirs[boot])):
                    compare(f"{path}.{boot}.{k}", mine[boot].get(k), theirs[boot].get(k))
        compare(f"{path}.note", mine.get("note"), theirs.get("note"))

    compare_slice("pooled", pooled_m, b["pooled"])
    compare_slice("final_test", final_m, b["final_test"])
    for name in sorted(set(by_kind_pooled) | set(b["by_kind_pooled"])):
        compare_slice(f"by_kind_pooled.{name}", by_kind_pooled[name], b["by_kind_pooled"][name])
    for name in sorted(set(by_cat_pooled) | set(b["by_category_pooled"])):
        compare_slice(
            f"by_category_pooled.{name}", by_cat_pooled[name], b["by_category_pooled"][name]
        )
    for name in sorted(set(by_gen_pooled) | set(b["by_generator_pooled"])):
        compare_slice(
            f"by_generator_pooled.{name}", by_gen_pooled[name], b["by_generator_pooled"][name]
        )
    for name in sorted(set(by_kind_ft) | set(b["by_kind_final_test"])):
        compare_slice(f"by_kind_final_test.{name}", by_kind_ft[name], b["by_kind_final_test"][name])
    for name in sorted(set(by_cat_ft) | set(b["by_category_final_test"])):
        compare_slice(
            f"by_category_final_test.{name}", by_cat_ft[name], b["by_category_final_test"][name]
        )

    # --- 8. Dependency lock + partition verification block ---
    lock = {}
    for name in ("requirements-pinned.txt", "requirements-hashed.txt"):
        p = REPO_ROOT / name
        if p.exists():
            lock[name] = _sha256_file(p)
    compare("dependency_lock", lock, b["dependency_lock"])
    compare(
        "partition.verification",
        b["partition"]["verification"],
        {
            "partitions": ["final-test", "fit", "validation"],
            "rows_assigned": 19683,
            "rows_total": 19683,
            "complete": True,
            "shared_components_across_partitions": 0,
            "shared_exact_texts_across_partitions": 0,
        },
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

    # FINDING (only if the artifact still carries the old labels): the
    # 4881e15 artifact labelled all 311 near-duplicate pairs
    # "cross-prompt" and 218 exact duplicates "across groups", but the
    # independent recomputation shows every pair is WITHIN one prompt's
    # 9 variants (within=311, across=0). Worker B corrected the labels
    # in commit 895577c and regenerated the artifact; the finding below
    # fires only if the old labels are still present.
    if "cross_prompt_near_dup_pairs" in b["near_duplicates"]:
        findings.append(
            {
                "check": "near-duplicate pair labelling in artifact",
                "detail": (
                    "artifact reports 'cross_prompt_near_dup_pairs': 311 and "
                    "'exact_duplicate_texts_across_groups': 218, but all 311 "
                    "pairs (218 exact) are within one prompt's 9 variants; "
                    "0 pairs are across prompts"
                ),
            }
        )

    all_checks_pass = all(c["passed"] or c.get("finding") for c in checks)
    if discrepancies or not all_checks_pass:
        verdict = "DISCREPANCY"
    elif findings:
        verdict = "AGREE_WITH_FINDINGS"
    else:
        verdict = "AGREE"
    print(f"reproduction verdict: {verdict}", flush=True)

    if args.check:
        print("check mode: no artifact file written")
        return 0 if verdict in ("AGREE", "AGREE_WITH_FINDINGS") else 1

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
        "command": "python scripts/reproduce_w8b_beemo.py",
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
            "extras": environment_extras,
        },
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "reproduces": "EV-20261116-dataset-beemo",
            "reproduces_artifact_sha256": b_artifact_sha,
            "reproduces_artifact_code_version": b_artifact["code_version"],
            "reproduces_manifests": {
                p: manifest_shas[p] for p in ("fit", "validation", "final-test")
            },
            "detector": "textforensics/builtin-heuristic",
            "detector_family": "stylometric-heuristic",
            "detector_version": "0.1.0",
            "operating_point": OPERATING_POINT,
            "method": (
                "Independent reproduction: cache file read directly as JSONL; "
                "near-duplicate components and the stratified greedy 60/20/20 "
                "partition re-derived from scratch; all 19,683 rows re-scored with "
                "a fresh detector at its native operating point; Wilson/AUROC "
                "(pairwise cross-checked against the rank walk)/AUPRC/TPR@FPR and "
                "row + cluster bootstrap CIs recomputed with independent "
                "implementations, replicating the documented single-shared-rng "
                "order (seed 20261116). No tuning on the final holdout."
            ),
            "identity_checks": checks,
            "findings": findings,
            "near_duplicates_recomputed": {
                "n_components": len(components),
                "component_size_histogram": {str(k): v for k, v in sorted(comp_sizes.items())},
                "pairs_jaccard_ge_0_8_total": total_pairs,
                "pairs_within_group": within,
                "pairs_across_groups": across,
                "exact_duplicate_pairs_within_group": exact_within,
                "exact_duplicate_pairs_across_groups": exact_across,
            },
            "pooled": pooled_m,
            "final_test": final_m,
            "by_kind_pooled": by_kind_pooled,
            "by_category_pooled": by_cat_pooled,
            "by_generator_pooled": by_gen_pooled,
            "by_kind_final_test": by_kind_ft,
            "by_category_final_test": by_cat_ft,
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
        ],
        "badge": "available",
        "detector_version": "0.1.0",
        "notes": (
            "Independent reproduction of Worker B's Beemo full-split evaluation. "
            "Every compared field either agrees exactly or is listed in "
            "'discrepancies'. Verdict AGREE_WITH_FINDINGS means all numbers "
            "reproduce exactly and the only failed checks are the documented "
            "findings listed in 'findings' (possibly empty). The final-test "
            "headline is a negative result "
            "(AUROC 0.4027, below chance; AUPRC 0.7331 below the 0.7778 "
            "prevalence baseline; native TPR 0/3059, FPR 0/874) reported as "
            "measured, not tuned around. History: the first reproduction run "
            "targeted the 4881e15 artifact and found two provenance findings "
            "(stale manifest SHA references after the manifests were re-frozen, "
            "and all 311 near-duplicate pairs mislabelled 'cross-prompt' "
            "although every pair is within one prompt's 9 variants); Worker B "
            "has since regenerated the artifact at 895577c with corrected "
            "labels and current manifest references, and this reproduction "
            "targets the regenerated artifact."
        ),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)[:12]}...)")
    return 0 if verdict in ("AGREE", "AGREE_WITH_FINDINGS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
