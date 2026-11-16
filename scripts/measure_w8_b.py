#!/usr/bin/env python3
"""measure_w8_b.py — W8 Worker B: Beemo + DetectRL-X qualification.

Qualification wave (0 findings by design): produce scientific evidence
for the builtin-heuristic detector on Beemo (full train split) and
DetectRL-X (expanded stratified sample of the general Binary file).
No inference or provenance code is changed by this script, and no
threshold or calibration is fitted anywhere: the detector runs at its
native operating point (builtin-heuristic native verdict; no score
threshold), and the reported TPR@FPR / AUROC / AUPRC values are
threshold-free ROC properties of the scores, not adopted operating
points.

Licences re-verified live 2026-11-16 (before any row was used):
* Beemo (toloka/beemo) — HF card "License: MIT" with field-level
  carve-outs: prompts + human_output from No Robots are CC-BY-NC-4.0;
  model_output and LLM-edited versions follow the underlying LLM
  licences; human_edits MIT unless the underlying LLM terms say
  otherwise. This use (non-commercial research evaluation, local cache
  only, aggregate metrics only, no redistribution of rows) is permitted
  under every carve-out.
* DetectRL-X (WUJUNCHAO/DetectRL-X) — three-way conflict, unchanged
  since the U1 record: GitHub README (ATH-MaaS/Marco-LLM, formerly
  AIDC-AI/Marco-LLM) §License: "licensed under the Apache License 2.0.
  Usage is strictly restricted to non-commercial academic research
  purposes."; HF card: "This dataset is released under the MIT
  License."; ACL 2026 paper Ethical Considerations: use strictly
  restricted to noncommercial academic research purposes. The strictest
  reading (non-commercial academic research only) governs, and this use
  satisfies all three readings. No commercial use, no redistribution.

Method (per corpus):
1. Fetch/map every row in scope (Beemo: full 2,187-row train split via
   the datasets-server; DetectRL-X: strided sample of 8,000 train +
   4,000 test source rows from the SHA-256-verified whole file
   Binary/binary_general_open.json). Mapping failures are recorded as
   drops with row id + reason, never skipped silently.
2. Independent inspection: field presence, label/kind/stratum
   distributions, prompt/human-text uniqueness, word-count stats.
3. Near-duplicate graph: union-find over rows keyed by a shared
   identity (Beemo: prompt_id — all 9 variants of one prompt;
   DetectRL-X: the raw row's human text — both texts of a pair, and any
   other pair sharing that human text) PLUS word-8-shingle Jaccard
   >= 0.8 edges (exact verification; crc32 index only proposes
   candidates). Connected components are the partition atoms.
4. Partition BEFORE evaluation: components are assigned whole to fit
   (60%) / validation (20%) / final-test (20%), stratified by category
   (Beemo) or language (DetectRL-X), in deterministic hash order, by
   greedy deficit against per-stratum row targets. Partitioning uses
   text identity only — no score is seen before the manifests freeze.
   Manifests are written under docs/evidence/manifests/ with per-row
   text hashes (never raw text) and their file SHA-256 is recorded in
   the run artifact. The fit pool doubles as train/selection and the
   validation pool as dev; neither is used for any decision, because no
   threshold, calibration, or selection decision is made at all — the
   final-test set therefore cannot have influenced any decision.
5. Evaluate the deterministic detector over every row; report pooled
   metrics (reproduction/extension of the seed records) AND final-test
   metrics (the leak-free headline), plus per-slice metrics (Beemo:
   kind, category, generator; DetectRL-X: language, domain, generator,
   split). Per slice: human FPR with Wilson 95% CI, native TPR with
   Wilson 95% CI, AUROC, AUPRC (average precision), TPR@FPR 1%/5%,
   coverage/abstention. Bootstrap 95% CIs (1,000 resamples, seed
   20261116) for AUROC/AUPRC/TPR@FPR on headline and per-stratum
   slices; cluster-bootstrap 95% CIs (resampling components) for the
   final-test headline FPR/TPR/AUROC.
6. Write one run-artifact/v1 record per corpus. This script does NOT
   touch docs/validation/registry.json (Worker D owns the registry) and
   does NOT call rebuild_registry().

The n=56 slice (EV-20261110-human-fpr, Wilson upper 0.064196) is the
OpAI-Bench document slice (evr-20261106-opai-bench-builtin-heuristic),
NOT Beemo or DetectRL-X — verified from the registry and the run
artifact before this run. It is also already closed: Phase 5 expanded
OpAI-Bench to n_human=218 (evr-20261110-opai-bench-builtin-heuristic,
supported, Wilson upper 0.0173). Neither of this worker's corpora is
the bottleneck.

Usage:
    python scripts/measure_w8_b.py [--only beemo,detectrl_x] [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
import sys
import zlib
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from seed_evidence import _base_record, _git_sha, _write_record  # noqa: E402

from textforensics.datasets import (  # noqa: E402
    DETECTRL_X_BYTES,
    DETECTRL_X_FILE,
    DETECTRL_X_SHA256,
    DatasetFetchError,
    DatasetsServerClient,
    download_detectrl_x,
    fetch_sample,
    get_spec,
    map_row,
    sample_detectrl_x_rows,
    sample_offsets,
    verify_detectrl_x_file,
    write_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.ledger import canonical_text_sha256  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402

BOOTSTRAP_SEED = 20261116
N_BOOTSTRAP = 1000
SHINGLE_N = 8
NEAR_DUP_JACCARD = 0.8
PARTITION_FRACTIONS = {"fit": 0.60, "validation": 0.20, "final-test": 0.20}
OPERATING_POINT = "builtin-heuristic native verdict (analyze_text); no score threshold"
RUN_DATE = date.today().isoformat()
RUN_ID_DATE = date.today().strftime("%Y%m%d")

# DetectRL-X expanded sample: 8,000 train + 4,000 test source rows,
# strided across the full file (76,800 train + 48,000 test rows) ->
# 24,000 normalised rows, 30x the seed sample (800). A full-file
# evaluation (249,600 normalised rows at ~54 rows/s, plus a 250k-row
# near-duplicate graph) is out of scope for this wave and stays an
# explicit documented gap; the sampling definition is frozen here so
# it can be extended deterministically.
DETECTRL_X_TRAIN_N = 8000
DETECTRL_X_TEST_N = 4000
DETECTRL_X_TRAIN_TOTAL = 76800
DETECTRL_X_TEST_TOTAL = 48000

MANIFESTS_DIR = REPO_ROOT / "docs" / "evidence" / "manifests"


# ---------------------------------------------------------------- text utils


def _norm_text(text: str) -> str:
    """Whitespace-collapsed text (the unit hashed and shingled)."""
    return " ".join(text.split())


def _word_count(text: str) -> int:
    return len(text.split())


def _tokens(text: str) -> list[str]:
    return _norm_text(text).lower().split()


def _shingles(text: str) -> set[str]:
    """Word 8-shingles; texts under 8 words get one whole-text shingle.

    Short texts cannot form an 8-gram; the whole-text shingle makes
    Jaccard >= 0.8 require near-identity for them instead of silently
    treating them as incomparable.
    """
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


# ------------------------------------------------------------- union-find


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
    """Group rows into near-duplicate components.

    Unions (a) rows sharing a group key (same prompt / same human
    text) and (b) row pairs with exact word-8-shingle Jaccard >= 0.8.
    Candidate pairs come from a crc32 shingle index: a pair can only
    reach Jaccard >= 0.8 if it shares >= ceil(0.8 * |A|) hashed
    shingles, so pairs below that bound are skipped without an exact
    check (no false negatives; crc32 collisions only add candidates,
    and every candidate is verified exactly on string shingles).
    Returns (components, near_dup_pairs) where each pair records the
    two source_ids and the exact Jaccard.
    """
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
        # Hashed shingles are computed per row and discarded after the
        # row is indexed: only the postings index is retained, so a
        # 24k-row run holds ~9M posting references, not ~9M live sets.
        row_hashes = _shingle_hashes(rows[i]["text"])
        need = math.ceil(NEAR_DUP_JACCARD * len(row_hashes))
        counts: Counter[int] = Counter()
        for h in row_hashes:
            for j in postings.get(h, ()):  # j < i: already indexed
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
    """Assign whole components to fit/validation/final-test.

    Stratified by each row's ``stratum`` (Beemo category, DetectRL-X
    language): a component's stratum is its majority stratum by row
    count. Within a stratum, components are visited in deterministic
    hash order and each goes to the partition furthest below its
    60/20/20 row target (greedy deficit). Returns {row_index: partition}.
    """
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
            # Furthest below target (ties: fit, then validation, then final-test).
            part = min(
                PARTITION_FRACTIONS,
                key=lambda p: (placed[p] - targets[p], list(PARTITION_FRACTIONS).index(p)),
            )
            for i in components[ci]:
                assignment[i] = part
            placed[part] += len(components[ci])
    return assignment


# ---------------------------------------------------------------- metrics


def _roc_metrics(labels: list[int], scores: list[float]) -> dict[str, float]:
    """AUROC, AUPRC (average precision), TPR@FPR 1%/5% from one sort.

    AUROC is the rank form with average ranks for ties (identical to
    measure_datasets.auroc); AUPRC is average precision over distinct
    score thresholds; TPR@FPR is the max TPR among thresholds with
    empirical FPR <= target (identical to measure_datasets.tpr_at_fpr).
    """
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    # AUROC via average ranks on the ascending order.
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
    # Precision-recall + ROC walk over distinct thresholds, descending.
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
    """Percentile bootstrap 95% CIs for AUROC/AUPRC/TPR@FPR.

    Returns None when a class is too small for resampling to be
    meaningful (fewer than 10 rows of either class).
    """
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
    out["resamples"] = [len(draws["auroc"]), skipped]  # [kept, skipped]
    return out


def _cluster_bootstrap_ci(
    items: list[dict],
    rng: random.Random,
    *,
    n_resamples: int = N_BOOTSTRAP,
) -> dict[str, list[float]] | None:
    """Cluster-bootstrap 95% CIs (resample components, not rows).

    ``items`` are row dicts with ``label``, ``score`` and ``cluster``
    keys. Returns CIs for native FPR, native TPR and AUROC, or None
    when the slice has fewer than 10 components per class side.
    """
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
    """All headline metrics for one slice of scored rows.

    Single-class slices (e.g. a Beemo kind, which determines its label)
    report only the rate that applies to them: FPR for human-only
    slices, TPR for AI-only slices; AUROC/AUPRC/TPR@FPR are None there
    because a ROC needs both classes.
    """
    labels = [it["label"] for it in items]
    scores = [it["score"] for it in items]
    n_human = sum(1 for x in labels if x == 0)
    n_ai = sum(1 for x in labels if x == 1)
    k_fp = sum(1 for it in items if it["label"] == 0 and it["verdict"] == "ai_like")
    k_tp = sum(1 for it in items if it["label"] == 1 and it["verdict"] == "ai_like")
    abstentions = sum(1 for it in items if it["verdict"] == "abstain")
    fpr_wilson = None
    if n_human:
        fpr_lo, fpr_hi = wilson_ci(k_fp, n_human)
        fpr_wilson = [round(fpr_lo, 6), round(fpr_hi, 6)]
    tpr_wilson = None
    if n_ai:
        tpr_lo, tpr_hi = wilson_ci(k_tp, n_ai)
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


# -------------------------------------------------------------- manifests


def write_manifest(
    dataset: str,
    partition: str,
    rows: list[dict],
    *,
    source_cache: dict,
    code_version: str,
) -> tuple[Path, str]:
    """Freeze one partition manifest (row hashes, never raw text)."""
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
    entries = [
        {
            "source_id": r["source_id"],
            "text_sha256": r["text_sha256"],
            "label": r["label"],
            "cluster_id": r["cluster"],
            "stratum": r["stratum"],
            "kind": r["kind"],
        }
        for r in sorted(rows, key=lambda x: x["source_id"])
    ]
    manifest = {
        "schema": "textforensics.w8-partition-manifest/v1",
        "dataset": dataset,
        "partition": partition,
        "partition_role": {
            "fit": "train + selection pool (unused: no threshold, calibration or selection decision is made)",
            "validation": "dev pool (unused for any decision)",
            "final-test": "held-out headline slice; influenced no threshold, calibration or selection decision",
        }[partition],
        "run_date": RUN_DATE,
        "code_version": code_version,
        "source_cache": source_cache,
        "row_hash_method": "sha256 of canonical-LF text (textforensics.ledger.canonical_text_sha256)",
        "partition_method": (
            "whole near-duplicate components (shared prompt/human-text identity + "
            "word-8-shingle Jaccard >= 0.8), stratified by "
            + ("category" if dataset == "beemo" else "language")
            + ", deterministic hash order, greedy 60/20/20 by row count"
        ),
        "n_rows": len(entries),
        "n_human": sum(1 for r in rows if r["label"] == 0),
        "n_ai": sum(1 for r in rows if r["label"] == 1),
        "n_components": len({r["cluster"] for r in rows}),
        "entries": entries,
    }
    path = MANIFESTS_DIR / f"EV-{RUN_ID_DATE}-{dataset}-{partition}.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------------ shared runner


def _evaluate(rows: list[dict], detector: BuiltinHeuristicDetector) -> None:
    """Score every row in place at the native operating point."""
    for row in rows:
        prediction = detector.detect(row["text"])
        row["score"] = float(prediction.score)
        row["verdict"] = prediction.verdict


def _determinism_spot_check(rows: list[dict], detector: BuiltinHeuristicDetector) -> dict:
    """Re-run the detector on a fixed 20-row sample; scores must repeat exactly."""
    sample = rows[:: max(1, len(rows) // 20)][:20]
    mismatches = 0
    for row in sample:
        again = detector.detect(row["text"])
        if float(again.score) != row["score"] or again.verdict != row["verdict"]:
            mismatches += 1
    return {"rows_rechecked": len(sample), "mismatches": mismatches}


def _verify_partition(rows: list[dict], assignment: dict[int, str]) -> dict:
    """Assert the frozen partition is leak-free and complete."""
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


def _group_slices(
    rows: list[dict], *, key: str, bootstrap: bool, cluster_bootstrap: bool, rng: random.Random
) -> dict[str, dict]:
    """Per-value metrics for one grouping key (kind/category/lang/...)."""
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


def _dependency_lock_sha() -> dict:
    out = {}
    for name in ("requirements-pinned.txt", "requirements-hashed.txt"):
        path = REPO_ROOT / name
        if path.exists():
            out[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def _write_artifact(record_id: str, command: str, results: dict, drops: list[dict]) -> Path:
    record = _base_record(record_id, "command", command)
    record["results"] = results
    record["drops"] = drops
    record["badge"] = "available"
    record["notes"] = (
        "W8 qualification run (Worker B). Native operating point only; no threshold, "
        "calibration or selection decision was made, so the frozen final-test set "
        "influenced no decision. This artifact is evidence only: it does not change "
        "docs/validation/registry.json and does not change the report-card lead. "
        "No dataset text is stored in this artifact or in the partition manifests — "
        "only SHA-256 hashes, counts and aggregate metrics."
    )
    return _write_record(record, force=True)


# ------------------------------------------------------------------- beemo


def run_beemo() -> dict:
    print("[beemo] verifying licence gate + server total ...")
    spec = get_spec("beemo")
    client = DatasetsServerClient()
    sizes = client.size(spec.hf_id)
    total = None
    for entry in sizes.get("splits", []):
        if entry.get("config") == "default" and entry.get("split") == "train":
            total = entry.get("num_rows")
    if total != 2187:
        raise ValueError(f"beemo: server reports {total} train rows, plan expects 2187")
    print(f"[beemo] server total verified: {total} train rows; fetching full split ...")
    raw_rows = fetch_sample(spec, "default", "train", 2187, client=client)
    print(f"[beemo] fetched {len(raw_rows)} raw rows")

    rows: list[dict] = []
    drops: list[dict] = []
    kind_counts: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    generators: Counter[str] = Counter()
    prompt_ids: set[str] = set()
    raw_ids_seen: set[str] = set()
    empty_human_edits = 0
    for raw in raw_rows:
        base_id = str(raw.get("id"))
        raw_ids_seen.add(base_id)
        categories[str(raw.get("category"))] += 1
        generators[str(raw.get("model"))] += 1
        prompt_ids.add(str(raw.get("prompt_id")))
        if isinstance(raw.get("human_edits"), str) and not raw["human_edits"].strip():
            empty_human_edits += 1
        try:
            mapped = map_row("beemo", raw, "default", "train")
        except DatasetFetchError as exc:
            drops.append({"item": f"raw row id={base_id}", "reason": f"mapper refused: {exc}"})
            continue
        for norm in mapped:
            kind = str(norm.meta.get("kind"))
            kind_counts[kind] += 1
            rows.append(
                {
                    "source_id": norm.source_id,
                    "text": norm.text,
                    "label": int(norm.label),
                    "kind": kind,
                    "stratum": str(norm.meta.get("category")),
                    "group_key": "prompt:" + str(norm.meta.get("prompt_id")),
                    "text_sha256": canonical_text_sha256(norm.text),
                    "words": _word_count(norm.text),
                    "split": "train",
                    "category": str(norm.meta.get("category")),
                    "generator": str(norm.meta.get("generator")),
                    "dataset_key": "beemo",
                    "config": "default",
                    "regime": "beemo",
                    "meta": dict(norm.meta),
                }
            )
    print(f"[beemo] mapped to {len(rows)} normalised rows; drops: {len(drops)}")
    cache_path, manifest_path = write_sample_cache(
        spec, "default", "train", _rows_to_normalized(rows), filename="train-full.jsonl"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(f"[beemo] full cache -> {cache_path} (sha {manifest['file_sha256'][:12]}...)")

    inspection = {
        "raw_rows_fetched": len(raw_rows),
        "raw_rows_expected": 2187,
        "raw_row_ids_unique": len(raw_ids_seen),
        "prompt_ids_unique": len(prompt_ids),
        "prompt_ids_expected": 2187,
        "categories": dict(sorted(categories.items())),
        "generators": dict(sorted(generators.items())),
        "kinds": dict(sorted(kind_counts.items())),
        "empty_human_edits_fields": empty_human_edits,
        "expected_variants_per_raw_row": 9,
        "actual_variants_per_raw_row": round(len(rows) / len(raw_rows), 4) if raw_rows else None,
        "word_counts_by_kind": {
            kind: {
                "min": min(r["words"] for r in rows if r["kind"] == kind),
                "median": int(statistics.median([r["words"] for r in rows if r["kind"] == kind])),
                "max": max(r["words"] for r in rows if r["kind"] == kind),
            }
            for kind in sorted(kind_counts)
        },
    }
    # Representative records inspected (identified by source_id only; no raw text stored).
    reps = [
        rows[0]["source_id"],
        next(r["source_id"] for r in rows if r["kind"] == "model_output"),
        next(r["source_id"] for r in rows if r["kind"] == "human_edits"),
        min(rows, key=lambda r: r["words"])["source_id"],
        max(rows, key=lambda r: r["words"])["source_id"],
    ]
    inspection["representative_records_inspected"] = reps

    print("[beemo] building near-duplicate components ...")
    components, near_dup_pairs = build_components(rows)
    comp_sizes = Counter(len(c) for c in components)
    print(
        f"[beemo] {len(components)} components "
        f"(singletons {comp_sizes[1]}, largest {max(comp_sizes)}); "
        f"cross-prompt near-dup pairs (J>=0.8): {len(near_dup_pairs)}"
    )
    for members in components:
        cid = _component_id(rows, members)
        for j in members:
            rows[j]["cluster"] = cid
    assignment = assign_partitions("beemo", rows, components)
    for i, part in assignment.items():
        rows[i]["partition"] = part
    partition_check = _verify_partition(rows, assignment)
    print(f"[beemo] partition check: {partition_check}")
    if not partition_check["complete"] or partition_check["shared_components_across_partitions"]:
        raise ValueError(f"beemo: partition failed verification: {partition_check}")

    code_version = _git_sha()
    source_cache = {
        "file": "train-full.jsonl",
        "path": "beemo/default/train-full.jsonl (XDG datasets cache)",
        "file_sha256": manifest["file_sha256"],
        "rows": manifest["rows"],
        "source_split_rows": 2187,
        "source": "https://datasets-server.huggingface.co (toloka/beemo, default/train)",
    }
    manifest_refs = {}
    for part in ("fit", "validation", "final-test"):
        path, sha = write_manifest(
            "beemo",
            part,
            [r for i, r in enumerate(rows) if assignment[i] == part],
            source_cache=source_cache,
            code_version=code_version,
        )
        manifest_refs[part] = {"path": str(path.relative_to(REPO_ROOT)), "sha256": sha}
        print(f"[beemo] manifest {part} -> {path.name} ({sha[:12]}...)")

    print("[beemo] evaluating detector at native operating point ...")
    detector = BuiltinHeuristicDetector()
    _evaluate(rows, detector)
    determinism = _determinism_spot_check(rows, detector)
    print(f"[beemo] determinism spot check: {determinism}")
    if determinism["mismatches"]:
        raise ValueError("beemo: detector is not deterministic on re-run")

    rng = random.Random(BOOTSTRAP_SEED)
    final_test = [r for r in rows if r["partition"] == "final-test"]
    results: dict = {
        "dataset": "beemo",
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "licence_reverified": {
            "date": RUN_DATE,
            "sources": [
                "https://huggingface.co/datasets/toloka/beemo (card: License MIT; "
                "Licensing Information: prompts + human_output CC-BY-NC-4.0, "
                "model_output/LLM-edited follow underlying LLM licences, "
                "human_edits MIT unless underlying LLM terms say otherwise)",
                "No Robots source licence CC-BY-NC-4.0 "
                "(https://huggingface.co/datasets/HuggingFaceH4/no_robots)",
            ],
            "verdict": (
                "permitted for this use (non-commercial research evaluation, "
                "local cache only, aggregate metrics only, no redistribution)"
            ),
        },
        "provenance": {
            "source_split": "default/train (2,187 rows, full split — no sampling)",
            "raw_source": "https://datasets-server.huggingface.co",
            "fetch_date": RUN_DATE,
            "cache": source_cache,
            "seed_sample_superseded": (
                "EV-20261106-dataset-beemo (900 normalised rows from a 100-row "
                "strided sample) is superseded by this full-split run"
            ),
        },
        "inspection": inspection,
        "drops_from_mapping": drops,
        "n_mapping_drops": len(drops),
        "near_duplicates": {
            "method": (
                "union-find over shared prompt_id plus word-8-shingle Jaccard >= 0.8 "
                "(exact verification; crc32 index proposes candidates only)"
            ),
            "n_components": len(components),
            "component_size_histogram": {str(k): v for k, v in sorted(comp_sizes.items())},
            "cross_prompt_near_dup_pairs": len(near_dup_pairs),
            "near_dup_pairs_sample": near_dup_pairs[:5],
            "exact_duplicate_texts_across_groups": sum(
                1 for p in near_dup_pairs if p["jaccard"] == 1.0
            ),
        },
        "partition": {
            "method": (
                "whole components, stratified by category, deterministic hash order, "
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
        },
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_family": "stylometric-heuristic",
        "operating_point": OPERATING_POINT,
        "determinism_spot_check": determinism,
        "dependency_lock": _dependency_lock_sha(),
        "pooled": slice_metrics(rows, bootstrap=True, cluster_bootstrap=False, rng=rng),
        "final_test": slice_metrics(final_test, bootstrap=True, cluster_bootstrap=True, rng=rng),
        "by_kind_pooled": _group_slices(
            rows, key="kind", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_category_pooled": _group_slices(
            rows, key="category", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_generator_pooled": _group_slices(
            rows, key="generator", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_kind_final_test": _group_slices(
            final_test, key="kind", bootstrap=False, cluster_bootstrap=False, rng=rng
        ),
        "by_category_final_test": _group_slices(
            final_test, key="category", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "worst_slice_context": {
            "note": (
                "The n=56 worst-slice human FPR (Wilson upper 0.064196, "
                "EV-20261110-human-fpr) is the OpAI-Bench document slice "
                "(evr-20261106-opai-bench-builtin-heuristic), NOT Beemo. "
                "It is already closed: Phase 5 expanded OpAI-Bench to "
                "n_human=218 (evr-20261110-opai-bench-builtin-heuristic, "
                "supported, Wilson upper 0.0173). Beemo's pooled human n "
                "here is far above the 100-row minimum."
            ),
            "beemo_pooled_n_human": sum(1 for r in rows if r["label"] == 0),
            "beemo_final_test_n_human": sum(1 for r in final_test if r["label"] == 0),
        },
    }
    drops_out = [
        {
            "item": "strided 100-row sample (EV-20261106-dataset-beemo)",
            "reason": "superseded by this full-split run (2,187 raw rows)",
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
            "item": "split disjointness check against a second split",
            "reason": "Beemo ships a single train split; there is no second split to check against",
        },
        {
            "item": "commercial use and redistribution of rows",
            "reason": (
                "human_output is CC-BY-NC-4.0; this run is non-commercial research "
                "evaluation with aggregate metrics only and no row redistribution"
            ),
        },
        {
            "item": f"{len(drops)} raw rows refused by the mapper",
            "reason": "each is listed in results.drops_from_mapping with its row id and cause",
        },
    ]
    record_id = f"EV-{RUN_ID_DATE}-dataset-beemo"
    path = _write_artifact(
        record_id, "python scripts/measure_w8_b.py --only beemo", results, drops_out
    )
    print(f"[beemo] wrote {path}")
    return results


def _rows_to_normalized(rows: list[dict]):
    """Rebuild NormalizedRow objects for the cache writer from row dicts."""
    from textforensics.datasets import NormalizedRow

    return [
        NormalizedRow(
            text=r["text"],
            label=r["label"],
            dataset=r["dataset_key"],
            config=r["config"],
            split=r["split"],
            source_id=r["source_id"],
            regime=r["regime"],
            meta=dict(r["meta"]),
        )
        for r in rows
    ]


# -------------------------------------------------------------- detectrl-x


def run_detectrl_x() -> dict:
    print("[detectrl_x] verifying whole file (size + SHA-256) ...")
    spec = get_spec("detectrl_x")
    raw_path = download_detectrl_x()  # verified copy returned without re-downloading
    verify_detectrl_x_file(raw_path)
    print(f"[detectrl_x] file verified: {raw_path} ({DETECTRL_X_BYTES} bytes)")
    print(
        "[detectrl_x] streaming one pass: count splits + strided sample "
        f"train {DETECTRL_X_TRAIN_N}/{DETECTRL_X_TRAIN_TOTAL} + "
        f"test {DETECTRL_X_TEST_N}/{DETECTRL_X_TEST_TOTAL} ..."
    )
    train_indexed, test_indexed, counts = sample_detectrl_x_rows(
        raw_path,
        sample_offsets(DETECTRL_X_TRAIN_TOTAL, DETECTRL_X_TRAIN_N),
        sample_offsets(DETECTRL_X_TEST_TOTAL, DETECTRL_X_TEST_N),
    )
    if counts["train"] != DETECTRL_X_TRAIN_TOTAL or counts["test"] != DETECTRL_X_TEST_TOTAL:
        raise ValueError(
            "detectrl_x: file holds "
            f"{counts['train']} train + {counts['test']} test rows, plan expects "
            f"{DETECTRL_X_TRAIN_TOTAL} + {DETECTRL_X_TEST_TOTAL}"
        )
    print(
        f"[detectrl_x] file counts verified: train {counts['train']}, "
        f"test {counts['test']}, total {counts['total']}; sampled "
        f"{len(train_indexed)} train + {len(test_indexed)} test source rows"
    )

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
            # Group key: the raw row's human text. Both texts of a pair,
            # and any other pair sharing that human text (train/test
            # overlap, or the same human text under another model), land
            # in one component and therefore one partition.
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
    print(f"[detectrl_x] mapped to {len(rows)} normalised rows; drops: {len(drops)}")
    train_rows = [r for r in rows if r["split"] == "train"]
    test_rows = [r for r in rows if r["split"] == "test"]
    cache_train, manifest_train_path = write_sample_cache(
        spec,
        "binary",
        "train",
        _rows_to_normalized(train_rows),
        filename="train-w8.jsonl",
        fetched_from="local file Binary/binary_general_open.json (SHA-256 verified)",
    )
    cache_test, manifest_test_path = write_sample_cache(
        spec,
        "binary",
        "test",
        _rows_to_normalized(test_rows),
        filename="test-w8.jsonl",
        fetched_from="local file Binary/binary_general_open.json (SHA-256 verified)",
    )
    manifest_train = json.loads(manifest_train_path.read_text(encoding="utf-8"))
    manifest_test = json.loads(manifest_test_path.read_text(encoding="utf-8"))
    print(f"[detectrl_x] caches -> {cache_train.name}, {cache_test.name}")

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
            label: {
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

    print("[detectrl_x] building near-duplicate components ...")
    components, near_dup_pairs = build_components(rows)
    comp_sizes = Counter(len(c) for c in components)
    print(
        f"[detectrl_x] {len(components)} components "
        f"(singletons {comp_sizes[1]}, largest {max(comp_sizes)}); "
        f"near-dup pairs (J>=0.8, any group): {len(near_dup_pairs)}"
    )
    for members in components:
        cid = _component_id(rows, members)
        for j in members:
            rows[j]["cluster"] = cid
    assignment = assign_partitions("detectrl_x", rows, components)
    for i, part in assignment.items():
        rows[i]["partition"] = part
    partition_check = _verify_partition(rows, assignment)
    print(f"[detectrl_x] partition check: {partition_check}")
    if not partition_check["complete"] or partition_check["shared_components_across_partitions"]:
        raise ValueError(f"detectrl_x: partition failed verification: {partition_check}")

    code_version = _git_sha()
    source_cache = {
        "train": {
            "file": "train-w8.jsonl",
            "path": "detectrl_x/binary/train-w8.jsonl (XDG datasets cache)",
            "file_sha256": manifest_train["file_sha256"],
            "rows": manifest_train["rows"],
        },
        "test": {
            "file": "test-w8.jsonl",
            "path": "detectrl_x/binary/test-w8.jsonl (XDG datasets cache)",
            "file_sha256": manifest_test["file_sha256"],
            "rows": manifest_test["rows"],
        },
        "source_file": DETECTRL_X_FILE,
        "source_file_sha256": DETECTRL_X_SHA256,
        "source_file_bytes": DETECTRL_X_BYTES,
    }
    manifest_refs = {}
    for part in ("fit", "validation", "final-test"):
        path, sha = write_manifest(
            "detectrl_x",
            part,
            [r for i, r in enumerate(rows) if assignment[i] == part],
            source_cache=source_cache,
            code_version=code_version,
        )
        manifest_refs[part] = {"path": str(path.relative_to(REPO_ROOT)), "sha256": sha}
        print(f"[detectrl_x] manifest {part} -> {path.name} ({sha[:12]}...)")

    print("[detectrl_x] evaluating detector at native operating point ...")
    detector = BuiltinHeuristicDetector()
    _evaluate(rows, detector)
    determinism = _determinism_spot_check(rows, detector)
    print(f"[detectrl_x] determinism spot check: {determinism}")
    if determinism["mismatches"]:
        raise ValueError("detectrl_x: detector is not deterministic on re-run")

    rng = random.Random(BOOTSTRAP_SEED)
    final_test = [r for r in rows if r["partition"] == "final-test"]
    results: dict = {
        "dataset": "detectrl_x",
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "licence_reverified": {
            "date": RUN_DATE,
            "sources": [
                "GitHub README (ATH-MaaS/Marco-LLM, DetectRL-X) §License: "
                "'This dataset is licensed under the Apache License 2.0. Usage is "
                "strictly restricted to non-commercial academic research purposes.' "
                "(https://github.com/AIDC-AI/Marco-LLM/tree/main/DetectRL-X; "
                "repo org renamed AIDC-AI -> ATH-MaaS since the U1 record)",
                "HF card: 'This dataset is released under the MIT License.' "
                "(https://huggingface.co/datasets/WUJUNCHAO/DetectRL-X)",
                "ACL 2026 paper Ethical Considerations: use strictly restricted to "
                "noncommercial academic research purposes (as recorded in the U1 "
                "registry note, verified 2026-11-07; the governing restriction is "
                "unchanged by the re-verification)",
            ],
            "verdict": (
                "three-way conflict unchanged; strictest reading (non-commercial "
                "academic research only) governs, and this use satisfies all three "
                "readings (non-commercial research evaluation, local cache only, "
                "aggregate metrics only, no redistribution)"
            ),
        },
        "provenance": {
            "source_file": DETECTRL_X_FILE,
            "source_file_sha256": DETECTRL_X_SHA256,
            "source_file_bytes": DETECTRL_X_BYTES,
            "split_rows_verified": counts,
            "sampled_source_rows": {"train": DETECTRL_X_TRAIN_N, "test": DETECTRL_X_TEST_N},
            "cache": source_cache,
            "seed_sample_superseded": (
                "EV-20261107-dataset-detectrl-x (800 normalised rows from a 400-row "
                "strided train sample) is superseded by this 24,000-row expanded sample"
            ),
        },
        "inspection": inspection,
        "drops_from_mapping": drops,
        "n_mapping_drops": len(drops),
        "near_duplicates": {
            "method": (
                "union-find over shared human-text identity plus word-8-shingle "
                "Jaccard >= 0.8 (exact verification; crc32 index proposes "
                "candidates only). Cross-language near-dup pairs are covered by "
                "the same global index; the shared-human-text check additionally "
                "catches train/test overlap of the underlying human texts."
            ),
            "n_components": len(components),
            "component_size_histogram": {str(k): v for k, v in sorted(comp_sizes.items())},
            "near_dup_pairs_jaccard_ge_0_8": len(near_dup_pairs),
            "near_dup_pairs_sample": near_dup_pairs[:5],
            "shared_human_texts_train_test_sampled": len(shared_human_texts),
        },
        "partition": {
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
        },
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_family": "stylometric-heuristic",
        "operating_point": OPERATING_POINT,
        "determinism_spot_check": determinism,
        "dependency_lock": _dependency_lock_sha(),
        "pooled": slice_metrics(rows, bootstrap=True, cluster_bootstrap=False, rng=rng),
        "final_test": slice_metrics(final_test, bootstrap=True, cluster_bootstrap=True, rng=rng),
        "by_lang_pooled": _group_slices(
            rows, key="lang", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_domain_pooled": _group_slices(
            rows, key="domain", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_generator_pooled": _group_slices(
            rows, key="model", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_split_pooled": _group_slices(
            rows, key="split", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_lang_final_test": _group_slices(
            final_test, key="lang", bootstrap=True, cluster_bootstrap=False, rng=rng
        ),
        "by_domain_final_test": _group_slices(
            final_test, key="domain", bootstrap=False, cluster_bootstrap=False, rng=rng
        ),
        "worst_slice_context": {
            "note": (
                "The n=56 worst-slice human FPR (Wilson upper 0.064196, "
                "EV-20261110-human-fpr) is the OpAI-Bench document slice "
                "(evr-20261106-opai-bench-builtin-heuristic), NOT DetectRL-X. "
                "It is already closed: Phase 5 expanded OpAI-Bench to "
                "n_human=218 (evr-20261110-opai-bench-builtin-heuristic, "
                "supported, Wilson upper 0.0173). DetectRL-X pooled human n "
                "here is far above the 100-row minimum."
            ),
            "detectrl_x_pooled_n_human": sum(1 for r in rows if r["label"] == 0),
            "detectrl_x_final_test_n_human": sum(1 for r in final_test if r["label"] == 0),
        },
    }
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
    record_id = f"EV-{RUN_ID_DATE}-dataset-detectrl-x"
    path = _write_artifact(
        record_id, "python scripts/measure_w8_b.py --only detectrl_x", results, drops_out
    )
    print(f"[detectrl_x] wrote {path}")
    return results


# --------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        default="beemo,detectrl_x",
        help="comma-separated dataset keys (default: beemo,detectrl_x)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing artifacts (accepted; _write_record always forces)",
    )
    args = parser.parse_args()
    keys = [k.strip() for k in args.only.split(",") if k.strip()]
    unknown = set(keys) - {"beemo", "detectrl_x"}
    if unknown:
        print(f"unknown dataset keys: {sorted(unknown)} (known: beemo, detectrl_x)")
        return 2
    # Cross-check the in-script ROC implementation against the repo's own
    # measure_datasets functions once, on synthetic data with heavy ties.
    from measure_datasets import auroc as _repo_auroc  # noqa: E402
    from measure_datasets import tpr_at_fpr as _repo_tpr_at_fpr  # noqa: E402

    labels = [0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0]
    scores = [0.1, 0.2, 0.2, 0.3, 0.3, 0.3, 0.4, 0.5, 0.5, 0.6, 0.7, 0.7]
    mine = _roc_metrics(labels, scores)
    assert abs(mine["auroc"] - _repo_auroc(labels, scores)) < 1e-9, "AUROC mismatch vs repo"
    assert abs(mine["tpr_at_fpr_0_01"] - _repo_tpr_at_fpr(labels, scores, 0.01)) < 1e-9, (
        "TPR@FPR1% mismatch vs repo"
    )
    assert abs(mine["tpr_at_fpr_0_05"] - _repo_tpr_at_fpr(labels, scores, 0.05)) < 1e-9, (
        "TPR@FPR5% mismatch vs repo"
    )
    print("ROC cross-check vs scripts/measure_datasets.py: OK")
    if "beemo" in keys:
        run_beemo()
    if "detectrl_x" in keys:
        run_detectrl_x()
    print("W8-B done. Registry NOT touched (Worker D owns it).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
