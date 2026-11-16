#!/usr/bin/env python3
"""measure_w8_ghostwriter_opai.py — W8 Worker C: GhostWriter + OpAI-Bench qualification.

Wave W8 is a QUALIFICATION wave (0 findings by design): this script
produces scientific evidence, not fixes. It does not change inference
or provenance code, does not tune any threshold, and does not touch
the registry or the report card (Worker D owns those).

What it does
------------
1. Re-verifies the licences from the live Hugging Face dataset cards
   (OpAI-Bench Apache-2.0; GhostWriter per-domain table) and records
   the verification in the run artifacts. Use is non-commercial
   research evaluation, local cache only, no redistribution.
2. Answers the n=56 bottleneck: the worst-slice human FPR in
   EV-20261110-human-fpr is Wilson upper 0.064196 at n_human=56 on
   slice evr-20261106-opai-bench-builtin-heuristic — the OpAI-Bench
   default/train U1 500-row strided sample. That slice was already
   expanded once (EV-20261110, train-2000, n_human=218, supported
   record evr-20261110-opai-bench-builtin-heuristic). This script
   pools the two disjoint OpAI-Bench samples (U1 500 + train-2000
   1996 = 2496 rows, content-disjoint by construction, re-verified
   here) and partitions the pool by document group BEFORE any
   evaluation, so the final-test slice is a held-out, leakage-free
   expansion of the n=56 slice. GhostWriter gets the same treatment
   with a NEW phase-shifted 2000-row strided sample (the U1 500-row
   sample alone cannot yield a partitioned final-test with
   n_human >= 100).
3. Partitions BEFORE any threshold/calibration decision, by
   document/author/generator/near-duplicate group, with a frozen
   deterministic rule (sha256 of the group key mod 10: buckets 0-2
   fit, 3-4 dev/selection, 5-9 final-test). No near-duplicate of a
   final-test row may appear in fit/dev: OpAI-Bench groups are
   ``document_hash_id`` (all 9 versions v0-v8 of one document share
   one group — 89 groups span the two pooled samples); GhostWriter
   groups are exact-content-hash groups merged with word-8-shingle
   Jaccard >= 0.8 near-duplicate groups (the ``source`` field is NOT
   a document id: human rows share dataset URLs, so it cannot group
   documents). Group assignment is computed from row identity only —
   never from a detector score.
4. Freezes train/dev/fit/final-test manifests as files with hashes
   (docs/evidence/manifests/). The final-test set influenced no
   threshold, calibration, or selection decision: none was made —
   the detector runs at its NATIVE operating point, fixed by the
   detector, and fit/dev exist only as frozen held-out partitions.
5. Evaluates the builtin-heuristic detector at its native operating
   point on the final-test labelled rows only, and reports per slice:
   human FPR with Wilson 95% upper bound, native TPR with Wilson 95%,
   AUROC/AUPRC with cluster-bootstrap 95% CIs (resampling document
   groups, seed 20261116), TPR@1%/5% FPR, coverage/abstention.
   Nothing is pooled away: the worst slice is reported explicitly.
6. Re-runs the GhostWriter threshold-sensitivity analysis on the
   final-test human rows (top human score vs the 0.68 native
   threshold; FPR at 0.66/0.68/0.70). The threshold is NOT re-tuned;
   the sensitivity is reported honestly.

Reproduction checks (fail closed)
----------------------------------
Before measuring, the script re-runs the detector over the raw U1
caches and requires the counts to reproduce the registry records
(OpAI-Bench U1: n_human=56, n_ai=55, abstentions=55;
GhostWriter U1: n_human=137, n_ai=210, abstentions=162). Any
mismatch raises instead of reporting a different sample.

Known corpus facts recorded here (all re-verified in code)
----------------------------------------------------------
- OpAI-Bench train repeats each pure-human v0 document once per
  generator (same document_hash_id, byte-identical text, different
  record_id/generator): offset-disjointness is NOT sufficient;
  content-hash disjointness is verified, and grouping is by
  document_hash_id.
- GhostWriter U1 train cache contains TWO exact-duplicate AI
  fulltext pairs (same 2581-char student_essays text; same 40-char
  euro_court_cases text; different source UUIDs/row ids). The
  registry record evr-20261107-ghostwriter counts n_ai=210 WITH
  those duplicates; this script dedupes by content hash (keep
  first, record the drop) so no text is double-counted, and says
  so in the artifact.
- GhostWriter chunk rows (label None, fusion) have no parent
  fulltext row inside any sampled cache (their base source UUID
  matches no in-sample fulltext row); they are dropped from the
  binary evaluation by label, not by score.

Usage:
    python scripts/measure_w8_ghostwriter_opai.py --fetch-only [--force]
    python scripts/measure_w8_ghostwriter_opai.py [--force] [--workers 4]

``--fetch-only`` fetches the new GhostWriter sample (checkpointed,
resumable) and stops. The full run reuses an existing
train-2000 cache if its manifest verifies; pass ``--force`` to
re-fetch it. Never pushes, never merges, never touches the
registry or the report card.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import statistics
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from measure_datasets import auroc, tpr_at_fpr  # noqa: E402
from seed_evidence import _base_record, _write_record  # noqa: E402

from textforensics.benchmark import check_disjointness, fingerprint_dataset  # noqa: E402
from textforensics.datasets import (  # noqa: E402
    DatasetsServerClient,
    default_cache_dir,
    get_spec,
    map_row,
    read_sample_cache,
    sample_offsets,
    write_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402

BOOTSTRAP_SEED = 20261116
BOOTSTRAP_RESAMPLES = 1000
# Partition rule (frozen, decided before any scoring): bucket =
# int(sha256(group_key), 16) % 10. Fit 0-2 (30%), dev/selection 3-4
# (20%), final-test 5-9 (50%).
FIT_BUCKETS = frozenset((0, 1, 2))
DEV_BUCKETS = frozenset((3, 4))
FINAL_BUCKETS = frozenset((5, 6, 7, 8, 9))
NATIVE_THRESHOLD = 0.68
PERTURBED_THRESHOLDS = (0.66, 0.68, 0.70)
RELIABILITY_FLOOR = 0.28
WILSON_METHOD = "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci"
BOOTSTRAP_METHOD = (
    "cluster bootstrap, 1000 resamples, seed 20261116 "
    "(resampling document/near-duplicate groups with replacement)"
)

# --- GhostWriter fetch plan ---
GW_N_ROWS = 2000
GW_SPLIT_TOTAL = 332224
GW_PHASE_SHIFT = 83  # half the 2000-grid step (~166)
GW_CONFIG = "default"
GW_SPLIT = "train"
GW_OLD_N_ROWS = 500
GW_OLD_CACHE_SHA256 = "12d2ab690b8952d34cb8814231b332f96dbc565de6f2daf4af50d3a60df184c8"
GW_NEW_FILENAME = "train-2000.jsonl"
GW_RAW_CHECKPOINT_FILENAME = "train-2000.raw.jsonl"
GW_FETCH_ROUNDS = 5
GW_FETCH_ROUND_PAUSE_S = 30
DEFAULT_WORKERS = 4

# --- OpAI-Bench pool (existing caches, re-verified) ---
OPAI_U1_CACHE_SHA256 = "72bcfe9f0948afa036f6707da5f366c989ce2f455592764b56c7bfea08e2a2ae"
OPAI_2000_CACHE_SHA256 = "d013ce6f42aa39768b9dee92c06f22dd6f63848c9bc04650bdccf468c11ee4cc"

RUN_ID_GHOSTWRITER = "EV-20261116-dataset-ghostwriter"
RUN_ID_OPAI = "EV-20261116-dataset-opai-bench"
MANIFESTS_DIR = REPO_ROOT / "docs" / "evidence" / "manifests"

# Licence verification, re-checked against the live HF dataset cards
# 2026-11-16 (crawled 10:09 UTC): OpAI-Bench card, "Licensing and
# Reuse": "The dataset is released under Apache-2.0. ... intended
# for research and evaluation of AI-text detection systems".
# GhostWriter card, "Licenses and Sources" table (lines 340-368),
# identical to the per-domain table recorded in
# src/textforensics/datasets.py (verified 2026-11-07).
LICENCE_VERIFICATION = {
    "verified_date": "2026-11-16",
    "verified_how": (
        "live Hugging Face dataset cards re-read 2026-11-16 "
        "(crawled 10:09 UTC): OpAI-Bench1/OpAI-Bench 'Licensing and "
        "Reuse' section; TheItCrOw/GhostWriter 'Licenses and Sources' "
        "table lines 340-368"
    ),
    "opai_bench": {
        "licence": "Apache-2.0",
        "reference": "https://huggingface.co/datasets/OpAI-Bench1/OpAI-Bench",
        "permits_this_use": True,
        "basis": (
            "Card states the dataset is released under Apache-2.0 and "
            "is intended for research and evaluation of AI-text "
            "detection systems — exactly this use."
        ),
    },
    "ghostwriter": {
        "licence": (
            "Per-domain licences (no single dataset licence): cnn_news "
            "Apache-2.0; arxiv_papers arXiv.org non-exclusive licence "
            "to distribute; blog_authorship_corpus CC0 / free for "
            "non-commercial research; bundestag DL-DE-BY-2.0; "
            "house_of_commons Open Parliament Licence; "
            "euro_court_cases CC-BY-NC-SA 4.0; student_essays "
            "CC-BY-NC-SA 4.0; gutenberg CC0"
        ),
        "reference": "https://huggingface.co/datasets/TheItCrOw/GhostWriter",
        "permits_this_use": True,
        "basis": (
            "Per-domain table on the live card is unchanged from the "
            "2026-11-07 verification. Use is non-commercial research "
            "evaluation, local cache only, no redistribution, no "
            "commercial use — inside the CC-BY-NC-SA 4.0 "
            "(euro_court_cases, student_essays) and "
            "non-commercial-research-only (blog_authorship_corpus) "
            "restrictions. The card says 'seven domains' in its "
            "description but the licence table and viewer show 8 — "
            "trust 8."
        ),
    },
}


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested in tests/test_measure_w8_ghostwriter_opai.py)
# ---------------------------------------------------------------------------

def content_hash(text: str) -> str:
    """Content hash of one normalised text (same construction as
    ``textforensics.benchmark._compute_sample_hashes``)."""
    content = json.dumps(
        {"text": text}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    """Lowercased whitespace-collapsed text for near-duplicate screening."""
    return " ".join(text.lower().split())


def word_shingles(normalized: str, k: int = 8) -> set[str]:
    """Word k-shingles of a normalised text (empty set if too short)."""
    words = normalized.split()
    if len(words) < k:
        return set()
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def shingle_jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity of two shingle sets (1.0 if both empty)."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def partition_of(group_key: str) -> str:
    """Frozen partition rule: sha256(group_key) mod 10 bucket."""
    bucket = int(hashlib.sha256(group_key.encode("utf-8")).hexdigest(), 16) % 10
    if bucket in FIT_BUCKETS:
        return "fit"
    if bucket in DEV_BUCKETS:
        return "dev"
    return "final-test"


def average_precision(labels: list[int], scores: list[float]) -> float:
    """Average precision (stepwise, sklearn convention): the area
    under the precision-recall curve with precision held at each
    recall step. Higher scores mean more machine-like. Raises unless
    both classes are present."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
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


def _metric_on_rows(metric: str, labels: list[int], scores: list[float]) -> float:
    if metric == "auroc":
        return auroc(labels, scores)
    if metric == "auprc":
        return average_precision(labels, scores)
    if metric == "tpr_at_1pct_fpr":
        return tpr_at_fpr(labels, scores, 0.01)
    if metric == "tpr_at_5pct_fpr":
        return tpr_at_fpr(labels, scores, 0.05)
    raise ValueError(f"unknown metric {metric!r}")


def cluster_bootstrap_ci(
    metric: str,
    labels: list[int],
    scores: list[float],
    group_ids: list[str],
    *,
    resamples: int = BOOTSTRAP_RESAMPLES,
    seed: int = BOOTSTRAP_SEED,
) -> dict:
    """Cluster-bootstrap 95% CI for a ranking metric.

    Resamples document/near-duplicate groups with replacement (each
    sampled group contributes all its rows), recomputes the metric,
    and reports the percentile interval. Resamples missing a class
    are skipped and counted — never silently padded. Deterministic
    for a fixed seed.
    """
    point = _metric_on_rows(metric, labels, scores)
    groups: dict[str, list[int]] = defaultdict(list)
    for idx, gid in enumerate(group_ids):
        groups[gid].append(idx)
    keys = sorted(groups)
    rng = random.Random(seed)
    values: list[float] = []
    skipped = 0
    for _ in range(resamples):
        chosen = [rng.choice(keys) for _ in keys]
        idxs = [i for key in chosen for i in groups[key]]
        sub_labels = [labels[i] for i in idxs]
        sub_scores = [scores[i] for i in idxs]
        if sum(sub_labels) == 0 or sum(sub_labels) == len(sub_labels):
            skipped += 1
            continue
        values.append(_metric_on_rows(metric, sub_labels, sub_scores))
    if not values:
        raise ValueError(f"cluster bootstrap for {metric}: every resample missed a class")
    values.sort()
    lo = values[int(0.025 * len(values))]
    hi = values[int(0.975 * len(values)) - 1 if len(values) > 1 else 0]
    return {
        "value": round(point, 4),
        "ci_lower": round(lo, 4),
        "ci_upper": round(hi, 4),
        "method": BOOTSTRAP_METHOD,
        "resamples": len(values),
        "resamples_skipped_no_class": skipped,
    }


class UnionFind:
    """Union-find for near-duplicate grouping (pure)."""

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


def group_ghostwriter_rows(rows: list) -> dict[str, str]:
    """Near-duplicate group key per row (by row index position).

    Groups rows by exact content hash, then merges groups whose
    texts have word-8-shingle Jaccard >= 0.8 (candidate pairs found
    through an inverted shingle index; shingles occurring in >100
    rows are too common to discriminate and are skipped). Returns
    ``{source_id: group_key}`` where the group key is the content
    hash of the group's first row (in pool order). Pure except for
    the row objects it reads.
    """
    uf = UnionFind()
    hashes = [content_hash(r.text) for r in rows]
    by_hash: dict[str, list[int]] = defaultdict(list)
    for i, h in enumerate(hashes):
        by_hash[h].append(i)
    for idxs in by_hash.values():
        for j in idxs[1:]:
            uf.union(hashes[idxs[0]], hashes[j])
    shingles = [word_shingles(normalize_text(r.text)) for r in rows]
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
    merged = 0
    for i, j in sorted(candidates):
        if uf.find(hashes[i]) == uf.find(hashes[j]):
            continue
        if shingle_jaccard(shingles[i], shingles[j]) >= 0.8:
            uf.union(hashes[i], hashes[j])
            merged += 1
    groups: dict[str, str] = {}
    for i, r in enumerate(rows):
        groups[r.source_id] = uf.find(hashes[i])
    return groups


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _code_version() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _environment_lock() -> dict:
    lock = REPO_ROOT / "requirements-pinned.txt"
    return {
        "python": platform.python_version(),
        "platform": platform.system().lower(),
        "git_sha": _code_version(),
        "requirements_pinned_sha256": _sha256_file(lock) if lock.exists() else None,
        "seeds": {"bootstrap_seed": BOOTSTRAP_SEED, "partition": "sha256(group_key) mod 10"},
    }


def _score_summary(scores: list[float]) -> dict:
    if not scores:
        return {"n": 0, "mean": None, "median": None, "min": None, "max": None}
    return {
        "n": len(scores),
        "mean": round(statistics.fmean(scores), 4),
        "median": round(statistics.median(scores), 4),
        "min": round(min(scores), 4),
        "max": round(max(scores), 4),
    }


def _check_server_total(spec, config: str, split: str, expected: int, client) -> None:
    sizes = client.size(spec.hf_id)
    actual = None
    for entry in sizes.get("splits", []):
        if entry.get("config") == config and entry.get("split") == split:
            actual = entry.get("num_rows")
            break
    if actual is None:
        raise ValueError(f"{spec.hf_id} {config}/{split}: split not reported by server")
    if actual != expected:
        raise ValueError(
            f"{spec.hf_id} {config}/{split}: server reports {actual} rows, "
            f"plan expects {expected} — re-verify the plan before sampling"
        )


def _verify_cache_sha(path: Path, expected: str, label: str) -> None:
    if not path.exists():
        raise ValueError(f"{label}: cache missing: {path}")
    actual = _sha256_file(path)
    if actual != expected:
        raise ValueError(f"{label}: cache SHA-256 {actual} != expected {expected} — refusing")


# ---------------------------------------------------------------------------
# GhostWriter fetch (phase-shifted strided sample, checkpointed)
# ---------------------------------------------------------------------------

def ghostwriter_offsets(
    *, total: int = GW_SPLIT_TOTAL, n: int = GW_N_ROWS, phase_shift: int = GW_PHASE_SHIFT
) -> list[int]:
    """Phase-shifted strided offsets: the n-grid shifted by half its step."""
    return [(offset + phase_shift) % total for offset in sample_offsets(total, n)]


def _fetch_one_offset(offset: int, client, spec) -> dict:
    page: list[dict] | None = None
    for round_no in range(1, GW_FETCH_ROUNDS + 1):
        try:
            page = client.rows(spec.hf_id, GW_CONFIG, GW_SPLIT, offset=offset, length=1)
            break
        except Exception as exc:  # noqa: BLE001 - retry, then re-raise below
            print(
                f"[gw] offset {offset}: attempt round {round_no}/{GW_FETCH_ROUNDS} "
                f"failed ({exc})",
                flush=True,
            )
            if round_no == GW_FETCH_ROUNDS:
                raise
            time.sleep(GW_FETCH_ROUND_PAUSE_S * round_no + random.uniform(0, GW_FETCH_ROUND_PAUSE_S))
    if not page:
        raise ValueError(
            f"{spec.hf_id} {GW_CONFIG}/{GW_SPLIT}: server returned no row at offset {offset}"
        )
    return page[0]


def fetch_ghostwriter_sample(*, workers: int = DEFAULT_WORKERS) -> tuple[list, list[int]]:
    """Fetch the phase-shifted GhostWriter sample, resuming from checkpoint.

    Verifies the U1 cache (SHA-256) first and proves the new offsets
    disjoint from the U1 offsets by row index before any fetch.
    Returns the mapped normalised rows (in offset order) and the
    offsets used. The U1 cache is never clobbered: the new sample is
    written to ``train-2000.jsonl`` + manifest next to it.
    """
    spec = get_spec("ghostwriter")
    client = DatasetsServerClient()
    _check_server_total(spec, GW_CONFIG, GW_SPLIT, GW_SPLIT_TOTAL, client)
    root = default_cache_dir()
    old_cache = root / "ghostwriter" / GW_CONFIG / "train.jsonl"
    _verify_cache_sha(old_cache, GW_OLD_CACHE_SHA256, "GhostWriter U1 cache")
    print(f"[gw] U1 cache verified: 500 rows, sha256 {GW_OLD_CACHE_SHA256[:12]}...")

    offsets = ghostwriter_offsets()
    if len(set(offsets)) != GW_N_ROWS:
        raise ValueError(f"shifted offsets are not unique: {len(set(offsets))} of {GW_N_ROWS}")
    old_offsets = set(sample_offsets(GW_SPLIT_TOTAL, GW_OLD_N_ROWS))
    overlap = set(offsets) & old_offsets
    if overlap:
        raise ValueError(
            f"shifted offsets overlap the U1 offsets at {len(overlap)} positions "
            f"(e.g. {sorted(overlap)[:5]}) — refusing"
        )
    print(
        f"[gw] {GW_N_ROWS} phase-shifted offsets (shift +{GW_PHASE_SHIFT}) are "
        f"disjoint from the {GW_OLD_N_ROWS} U1 offsets by row index"
    )

    checkpoint = root / "ghostwriter" / GW_CONFIG / GW_RAW_CHECKPOINT_FILENAME
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    done: dict[int, dict] = {}
    if checkpoint.exists():
        lines = [
            line for line in checkpoint.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        dropped_trailing = False
        for line_no, line in enumerate(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                if line_no == len(lines) - 1:
                    print("[gw] dropping truncated trailing checkpoint line; re-fetching it")
                    dropped_trailing = True
                    break
                raise
            done[int(entry["offset"])] = entry["row"]
        if dropped_trailing:
            checkpoint.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        print(f"[gw] resuming from checkpoint: {len(done)} rows already fetched")
    remaining = [offset for offset in offsets if offset not in done]
    results: dict[int, dict] = dict(done)
    started = time.time()
    state = {"fetched_this_run": 0}
    lock = threading.Lock()
    thread_local = threading.local()

    def thread_client() -> DatasetsServerClient:
        owned = getattr(thread_local, "client", None)
        if owned is None:
            owned = DatasetsServerClient(
                base_url=client.base_url, timeout_s=client.timeout_s, retries=client.retries
            )
            thread_local.client = owned
        return owned

    def work(offset: int) -> tuple[int, dict]:
        return offset, _fetch_one_offset(offset, thread_client(), spec)

    with (
        checkpoint.open("a", encoding="utf-8") as handle,
        ThreadPoolExecutor(max_workers=workers) as pool,
    ):
        futures = {pool.submit(work, offset): offset for offset in remaining}
        for future in as_completed(futures):
            offset, row = future.result()
            with lock:
                handle.write(json.dumps({"offset": offset, "row": row}, ensure_ascii=False) + "\n")
                results[offset] = row
                state["fetched_this_run"] += 1
                fetched = len(results)
                if fetched % 500 == 0 or fetched == GW_N_ROWS:
                    elapsed = time.time() - started
                    rate = state["fetched_this_run"] / max(elapsed, 1e-9)
                    eta = (GW_N_ROWS - fetched) / rate if rate > 0 else 0.0
                    print(
                        f"[gw] fetched {fetched}/{GW_N_ROWS} rows "
                        f"({elapsed:.0f}s elapsed this run, ETA {eta:.0f}s)",
                        flush=True,
                    )
    raw = [results[offset] for offset in offsets]
    if len(raw) != GW_N_ROWS:
        raise ValueError(f"fetched {len(raw)} rows, expected {GW_N_ROWS}")
    normalized = []
    for row in raw:
        normalized.extend(map_row("ghostwriter", row, GW_CONFIG, GW_SPLIT))
    if len(normalized) != GW_N_ROWS:
        raise ValueError(f"mapped {len(normalized)} normalised rows, expected {GW_N_ROWS}")

    # Corpus duplication (same class as OpAI-Bench): the split itself
    # repeats texts, so offset-disjoint rows can still duplicate U1
    # documents by content. Drop exactly those rows (by content hash
    # vs the U1 cache) before writing the cache. Exclusion is by
    # identity, never by detector score.
    old_hashes = set(
        fingerprint_dataset(old_cache, "ghostwriter", split="train").content_hashes
    )
    kept, excluded = [], []
    seen: set[str] = set()
    for row, offset in zip(normalized, offsets, strict=True):
        digest = content_hash(row.text)
        if digest in old_hashes:
            excluded.append({"offset": offset, "content_hash": digest, "label": row.label})
            continue
        if digest in seen:
            raise ValueError(f"duplicate content hash inside the new sample at offset {offset}")
        seen.add(digest)
        kept.append(row)
    if excluded:
        print(f"[gw] !!! EXCLUDED {len(excluded)} rows duplicating U1 documents by content hash")
        for entry in excluded:
            print(f"[gw]   excluded offset {entry['offset']} label={entry['label']}")

    cache_path, manifest_path = write_sample_cache(
        spec, GW_CONFIG, GW_SPLIT, kept, filename=GW_NEW_FILENAME
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_sha = _sha256_file(cache_path)
    if manifest["file_sha256"] != cache_sha:
        raise ValueError(
            f"new cache manifest file_sha256 {manifest['file_sha256']} != "
            f"recomputed SHA-256 {cache_sha} of {cache_path}"
        )
    counts = Counter(r.label for r in kept)
    print(
        f"[gw] wrote {len(kept)} normalised rows "
        f"({counts.get(0, 0)} human / {counts.get(1, 0)} AI / {counts.get(None, 0)} fusion) "
        f"-> {cache_path} (sha256 {cache_sha})"
    )
    checkpoint.unlink(missing_ok=True)
    print(f"[gw] removed raw checkpoint {checkpoint.name}")
    return kept, offsets, excluded, cache_sha


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def reproduce_u1_checks() -> dict:
    """Re-run the detector over the raw U1 caches; counts must reproduce
    the registry records, or raise. Returns the reproduction summary."""
    detector = BuiltinHeuristicDetector()
    checks = {}
    for key, config, split, exp in (
        ("opai_bench", "default", "train", {"n_human": 56, "n_ai": 55, "abstentions": 55}),
        ("ghostwriter", "default", "train", {"n_human": 137, "n_ai": 210, "abstentions": 162}),
    ):
        spec = get_spec(key)
        rows = read_sample_cache(spec, config, split)
        labelled = [r for r in rows if r.label is not None]
        n_human = sum(1 for r in labelled if int(r.label) == 0)
        n_ai = sum(1 for r in labelled if int(r.label) == 1)
        abstentions = sum(
            1 for r in labelled if detector.detect(r.text).verdict == "abstain"
        )
        got = {"n_human": n_human, "n_ai": n_ai, "abstentions": abstentions}
        if got != exp:
            raise ValueError(
                f"{key} U1 reproduction FAILED: got {got} != registry {exp} — "
                "refusing to report a different sample"
            )
        print(f"[check] {key} U1 reproduces registry exactly: {got}")
        checks[key] = got
    return checks


def slice_metrics(
    *, slice_id: str, labels: list[int], scores: list[float],
    verdicts: list[str], group_ids: list[str],
) -> dict:
    """Per-slice metrics at the native operating point.

    FPR/TPR are native-verdict rates with Wilson 95% intervals.
    AUROC/AUPRC/TPR@FPR are score-based with cluster-bootstrap 95%
    CIs. Slices with fewer than 10 rows per class report ranking
    metrics as null (with the reason) instead of a number from a
    degenerate sample. Abstentions are preserved: coverage is the
    non-abstaining fraction of the slice.
    """
    n_human = sum(1 for lab in labels if lab == 0)
    n_ai = sum(1 for lab in labels if lab == 1)
    k_fp = sum(1 for lab, v in zip(labels, verdicts, strict=True) if lab == 0 and v == "ai_like")
    k_tp = sum(1 for lab, v in zip(labels, verdicts, strict=True) if lab == 1 and v == "ai_like")
    abstentions = sum(1 for v in verdicts if v == "abstain")

    def _rate_with_wilson(k: int, n: int) -> dict:
        # wilson_ci needs n >= 1; a slice with no rows of a class
        # reports the rate as null with the reason, never a fabricated 0.
        if n == 0:
            return {
                "k": k, "n": 0, "value": None,
                "ci_lower": None, "ci_upper": None,
                "method": WILSON_METHOD,
                "not_computed": "no rows of this class in the slice",
                "operating_point": "builtin-heuristic native verdict (analyze_text); no score threshold",
            }
        lo, hi = wilson_ci(k, n)
        return {
            "k": k, "n": n,
            "value": round(k / n, 4),
            "ci_lower": round(lo, 4), "ci_upper": round(hi, 4),
            "method": WILSON_METHOD,
            "operating_point": "builtin-heuristic native verdict (analyze_text); no score threshold",
        }

    out: dict = {
        "slice_id": slice_id,
        "n_human": n_human,
        "n_ai": n_ai,
        "n_human_groups": len({g for lab, g in zip(labels, group_ids, strict=True) if lab == 0}),
        "n_ai_groups": len({g for lab, g in zip(labels, group_ids, strict=True) if lab == 1}),
        "fpr_native": _rate_with_wilson(k_fp, n_human),
        "tpr_native": _rate_with_wilson(k_tp, n_ai),
        "coverage": round(1 - abstentions / len(labels), 4) if labels else 0.0,
        "abstention_rate": round(abstentions / len(labels), 4) if labels else 0.0,
        "abstentions": abstentions,
        "score_by_label": {
            "human": _score_summary([s for lab, s in zip(labels, scores, strict=True) if lab == 0]),
            "machine": _score_summary([s for lab, s in zip(labels, scores, strict=True) if lab == 1]),
        },
    }
    if min(n_human, n_ai) >= 10:
        for metric in ("auroc", "auprc", "tpr_at_1pct_fpr", "tpr_at_5pct_fpr"):
            out[metric] = cluster_bootstrap_ci(metric, labels, scores, group_ids)
    else:
        out["ranking_metrics"] = None
        out["ranking_metrics_not_computed"] = (
            f"both classes need >= 10 rows; n_human={n_human}, n_ai={n_ai}"
        )
    return out


def threshold_sensitivity(human_scores: list[float], human_reliabilities: list[float]) -> dict:
    """GhostWriter threshold sensitivity on final-test human rows.

    Reports what the human FPR *would be* at perturbed thresholds
    (verdict-equivalent: score >= T and reliability >= 0.28). The
    native 0.68 threshold is UNCHANGED by this measurement.
    """
    n = len(human_scores)
    entries = []
    for threshold in PERTURBED_THRESHOLDS:
        k = sum(
            1
            for s, r in zip(human_scores, human_reliabilities, strict=True)
            if s >= threshold and r >= RELIABILITY_FLOOR
        )
        if n == 0:
            entries.append({
                "threshold": threshold, "k": k, "n": 0,
                "rate": None, "ci_lower": None, "ci_upper": None,
                "method": WILSON_METHOD,
                "not_computed": "no human rows in the slice",
            })
            continue
        lo, hi = wilson_ci(k, n)
        entries.append({
            "threshold": threshold, "k": k, "n": n,
            "rate": round(k / n, 4) if n else 0.0,
            "ci_lower": round(lo, 4), "ci_upper": round(hi, 4),
            "method": WILSON_METHOD,
        })
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
        "note": (
            "Sensitivity analysis only. The native ai_like threshold "
            "0.68 is UNCHANGED: these rows report what the human FPR "
            "would be at perturbed thresholds; they do not propose "
            "moving the threshold."
        ),
    }


def score_final_test(rows_with_partitions, group_of) -> list[dict]:
    """Run the detector at its native operating point over final-test
    labelled rows. One scoring pass; slicing is done afterwards so
    overlapping slice families (domain, language, generator) share
    the same scores. Deterministic: the same rows always score the
    same way (verified by the U1 reproduction checks)."""
    detector = BuiltinHeuristicDetector()
    scored = []
    for row, partition in rows_with_partitions:
        if partition != "final-test" or row.label is None:
            continue
        prediction = detector.detect(row.text)
        scored.append({
            "row": row,
            "label": int(row.label),
            "score": float(prediction.score),
            "reliability": float(prediction.reliability),
            "verdict": str(prediction.verdict),
            "group": group_of[row.source_id],
        })
    return scored


def summarize_slices(scored: list[dict], groupings: dict[str, list[dict]], dataset_label: str) -> dict:
    """Per-slice metrics for explicit (possibly overlapping) row
    groupings. ``groupings`` maps slice name -> scored rows."""
    results = {}
    for name, items in sorted(groupings.items()):
        results[name] = slice_metrics(
            slice_id=f"{dataset_label}-{name}",
            labels=[i["label"] for i in items],
            scores=[i["score"] for i in items],
            verdicts=[i["verdict"] for i in items],
            group_ids=[i["group"] for i in items],
        )
    ranked = [
        (m["fpr_native"]["ci_upper"], name, m)
        for name, m in results.items()
        if m["n_human"] >= 10
    ]
    ranked.sort(key=lambda t: t[0], reverse=True)
    worst = ranked[0] if ranked else (None, None, None)
    return {
        "slices": results,
        "worst_slice": {
            "slice_id": worst[1],
            "fpr_wilson_upper": worst[0],
            "n_human": worst[2]["n_human"] if worst[2] else None,
        },
        "n_final_test_labelled": len(scored),
    }


def dedupe_by_content(rows: list, *, pool_label: str) -> tuple[list, list[dict]]:
    """Drop exact content-hash duplicates (keep first in pool order).
    Returns (kept, dropped) where each drop records the kept row it
    duplicates. Exclusion is by identity, never by detector score."""
    kept, dropped = [], []
    seen: dict[str, str] = {}
    for row in rows:
        digest = content_hash(row.text)
        if digest in seen:
            dropped.append({
                "source_id": row.source_id,
                "content_hash": digest,
                "label": row.label,
                "duplicates_kept_source_id": seen[digest],
                "reason": "exact content duplicate of an earlier pooled row; kept once so no text is double-counted",
            })
            continue
        seen[digest] = row.source_id
        kept.append(row)
    if dropped:
        print(f"[{pool_label}] deduped {len(dropped)} exact-duplicate row(s) by content hash")
    return kept, dropped


def partition_pool(rows: list, group_of: dict[str, str]) -> list[tuple]:
    """Assign every row its frozen partition from its group key."""
    return [(row, partition_of(group_of[row.source_id])) for row in rows]


def partition_counts(rows_with_partitions: list[tuple]) -> dict:
    """Label counts per partition (computed from labels only, before
    any scoring — the counts are what the n>=100 gate is checked on)."""
    counts: dict[str, dict] = {}
    for partition in ("fit", "dev", "final-test"):
        subset = [r for r, p in rows_with_partitions if p == partition]
        labelled = [r for r in subset if r.label is not None]
        counts[partition] = {
            "rows": len(subset),
            "n_human": sum(1 for r in labelled if int(r.label) == 0),
            "n_ai": sum(1 for r in labelled if int(r.label) == 1),
            "n_unlabelled": sum(1 for r in subset if r.label is None),
        }
    return counts


def require_final_test_size(counts: dict, *, dataset_label: str) -> None:
    """Fail closed if the final-test slice cannot support the
    100-row human minimum. (A failure here is a gap to report, not
    something to fix by re-sampling until a number looks good.)"""
    final = counts["final-test"]
    if final["n_human"] < 100:
        raise ValueError(
            f"{dataset_label}: final-test n_human={final['n_human']} is below "
            "the 100-row minimum — the pool cannot support a held-out "
            "final-test slice; fetch more licensed data instead of "
            "shrinking the holdout"
        )
    if final["n_ai"] < 100:
        raise ValueError(
            f"{dataset_label}: final-test n_ai={final['n_ai']} is below 100"
        )


def write_manifest(
    *, dataset: str, run_id: str, group_key_description: str,
    sources: list[dict], drops: list[dict], rows_with_partitions: list[tuple],
    group_of: dict[str, str], slice_of, cache_file_of: dict[str, str],
) -> tuple[Path, str]:
    """Freeze the partition manifest (no raw text) and return its
    path and SHA-256."""
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
    entries = []
    for row, partition in rows_with_partitions:
        entries.append({
            "source_id": row.source_id,
            "content_hash": content_hash(row.text),
            "group_key": group_of[row.source_id],
            "partition": partition,
            "label": row.label,
            "slice": slice_of(row),
            "cache_file": cache_file_of[row.source_id],
        })
    manifest = {
        "schema": "textforensics.w8-partition-manifest/v1",
        "dataset": dataset,
        "run_id": run_id,
        "created": "2026-11-16",
        "code_version": _code_version(),
        "partition_rule": (
            "bucket = int(sha256(group_key), 16) % 10; buckets 0-2 fit, "
            "3-4 dev/selection, 5-9 final-test. Group assignment uses "
            "row identity only, never a detector score. The final-test "
            "set influenced no threshold, calibration, or selection "
            "decision (none was made; native operating point)."
        ),
        "group_key": group_key_description,
        "sources": sources,
        "drops": drops,
        "counts": partition_counts(rows_with_partitions),
        "rows": entries,
    }
    path = MANIFESTS_DIR / f"{run_id}-partitions.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    digest = _sha256_file(path)
    print(f"[manifest] wrote {path} (sha256 {digest[:12]}..., {len(entries)} rows)")
    return path, digest


def _content_disjoint_check(new_cache: Path, other_cache: Path, label: str, dataset: str) -> dict:
    fp_new = fingerprint_dataset(new_cache, dataset, split="train")
    fp_other = fingerprint_dataset(other_cache, dataset, split="train")
    check = check_disjointness(new_cache, fp_new, other_cache, fp_other)
    print(
        f"[disjoint] vs {label}: disjoint={check['disjoint']} "
        f"verified={check['verified']} shared={check['shared_samples']}"
    )
    return check


# ---------------------------------------------------------------------------
# OpAI-Bench
# ---------------------------------------------------------------------------

def build_opai_pool() -> tuple[list, list[dict], list[dict], dict[str, str]]:
    """Pool the two existing, content-disjoint OpAI-Bench samples and
    group by document_hash_id. Returns (rows, sources, drops)."""
    root = default_cache_dir()
    u1_cache = root / "opai_bench" / "default" / "train.jsonl"
    c2000_cache = root / "opai_bench" / "default" / "train-2000.jsonl"
    _verify_cache_sha(u1_cache, OPAI_U1_CACHE_SHA256, "OpAI-Bench U1 cache")
    _verify_cache_sha(c2000_cache, OPAI_2000_CACHE_SHA256, "OpAI-Bench train-2000 cache")
    check = _content_disjoint_check(
        c2000_cache, u1_cache, "OpAI-Bench U1 train (n=500)", "opai_bench"
    )
    if not check["disjoint"] or not check["verified"]:
        raise ValueError(f"OpAI-Bench pooled samples are NOT content-disjoint: {check}")
    spec = get_spec("opai_bench")
    u1 = read_sample_cache(spec, "default", "train")
    c2000 = read_sample_cache(spec, "default", "train", filename="train-2000.jsonl")
    pooled = list(u1) + list(c2000)
    kept, drops = dedupe_by_content(pooled, pool_label="opai")
    cache_file_of = {r.source_id: "train.jsonl" for r in u1}
    cache_file_of.update({r.source_id: "train-2000.jsonl" for r in c2000})
    sources = [
        {"cache_file": "train.jsonl", "file_sha256": OPAI_U1_CACHE_SHA256, "rows": len(u1),
         "label_counts": {str(k): sum(1 for r in u1 if r.label == k) for k in (0, 1, None)}},
        {"cache_file": "train-2000.jsonl", "file_sha256": OPAI_2000_CACHE_SHA256, "rows": len(c2000),
         "label_counts": {str(k): sum(1 for r in c2000 if r.label == k) for k in (0, 1, None)}},
    ]
    print(
        f"[opai] pooled {len(kept)} rows "
        f"({sum(1 for r in kept if r.label == 0)} human / "
        f"{sum(1 for r in kept if r.label == 1)} AI / "
        f"{sum(1 for r in kept if r.label is None)} partial)"
    )
    return kept, sources, drops, cache_file_of


def run_opai(*, force: bool) -> dict:
    """OpAI-Bench partitioned evaluation → run artifact."""
    spec = get_spec("opai_bench")
    rows, sources, drops, cache_file_of = build_opai_pool()
    group_of = {r.source_id: str(r.meta["document_hash_id"]) for r in rows}
    rows_with_partitions = partition_pool(rows, group_of)
    counts = partition_counts(rows_with_partitions)
    require_final_test_size(counts, dataset_label="OpAI-Bench")
    print(f"[opai] partition counts: {json.dumps(counts)}")
    manifest_path, manifest_sha = write_manifest(
        dataset="opai_bench", run_id=RUN_ID_OPAI,
        group_key_description=(
            "document_hash_id: all 9 versions (v0-v8) of one document "
            "share one group, so no version of a final-test document "
            "appears in fit/dev. 89 groups span the two pooled samples."
        ),
        sources=sources, drops=drops,
        rows_with_partitions=rows_with_partitions, group_of=group_of,
        slice_of=lambda r: str(r.meta.get("domain")),
        cache_file_of=cache_file_of,
    )
    # Final-test must also be disjoint from the dev split cache by
    # content hash (different split, same corpus).
    final_rows = [r for r, p in rows_with_partitions if p == "final-test"]
    final_hashes = {content_hash(r.text) for r in final_rows}
    dev_rows = read_sample_cache(spec, "default", "dev")
    dev_hashes = {content_hash(r.text) for r in dev_rows}
    shared_dev = final_hashes & dev_hashes
    if shared_dev:
        raise ValueError(
            f"OpAI-Bench final-test shares {len(shared_dev)} content hashes "
            "with the dev split cache — refusing"
        )
    print("[opai] final-test disjoint from dev split cache by content hash (0 shared)")

    scored = score_final_test(rows_with_partitions, group_of)
    human_rows = [s for s in scored if s["label"] == 0]
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for item in scored:
        by_domain[str(item["row"].meta.get("domain"))].append(item)
    groupings: dict[str, list[dict]] = {"pooled": scored, **dict(by_domain)}
    for generator in sorted({str(s["row"].meta.get("generator")) for s in scored if s["label"] == 1}):
        groupings[f"generator-{generator}"] = human_rows + [
            s for s in scored if s["label"] == 1 and str(s["row"].meta.get("generator")) == generator
        ]
    evaluation = summarize_slices(scored, groupings, "opai-bench")
    final = counts["final-test"]
    results = {
        "dataset": "opai_bench",
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "licence_verification": LICENCE_VERIFICATION["opai_bench"],
        "licence_verified": LICENCE_VERIFICATION["verified_date"],
        "licence_verified_how": LICENCE_VERIFICATION["verified_how"],
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_family": BuiltinHeuristicDetector.detector_family,
        "operating_point": (
            "builtin-heuristic native verdict (analyze_text); no score "
            "threshold; no threshold was fitted, no calibration was "
            "fitted — the operating point is fixed by the detector"
        ),
        "environment_lock": _environment_lock(),
        "provenance": {
            "dataset_version": (
                "OpAI-Bench1/OpAI-Bench snapshot 2026-11-16 (no versioned "
                "release); pooled from the U1 500-row strided sample "
                "(2026-11-06) and the phase-shifted 2000-row strided "
                "sample (2026-11-10)"
            ),
            "config": "default",
            "split": "train",
            "split_rows_total": 196029,
            "sampling": "strided (both pooled samples); see EV-20261110-dataset-opai-bench for the phase-shift method",
            "sources": sources,
            "row_hash_method": "sha256 of normalised text (benchmark fingerprint)",
            "label_provenance": (
                "only v0 (ai_sentence_ratio 0.0, pure human) and v8 "
                "(ai_sentence_ratio 1.0, fully machine) rows carry "
                "binary labels; partial rows (0 < ai_sentence_ratio < 1) "
                "carry no binary label and are the U4 spine, not U1 evidence"
            ),
            "normalization_provenance": "rows mapped by textforensics.datasets.map_row('opai_bench') at fetch time; cached normalised JSONL verified by SHA-256",
        },
        "inclusion_drop_counts": {
            "rows_pooled": len(rows) + len(drops),
            "rows_after_content_dedup": len(rows),
            "exact_content_duplicates_dropped": len(drops),
            "dropped_duplicate_rows": drops,
            "partial_mixed_origin_rows_excluded_from_binary_metrics": sum(
                1 for r in rows if r.label is None
            ),
            "partial_rows_reason": (
                "rows with 0 < ai_sentence_ratio < 1 carry no binary "
                "label; they are the U4 spine, not U1 evidence"
            ),
            "label_counts_pooled": {
                "human": sum(1 for r in rows if r.label == 0),
                "ai": sum(1 for r in rows if r.label == 1),
                "partial_unlabelled": sum(1 for r in rows if r.label is None),
            },
        },
        "partition": {
            "method": (
                "group = document_hash_id; bucket = int(sha256(group), 16) "
                "% 10; buckets 0-2 fit, 3-4 dev/selection, 5-9 final-test. "
                "All 9 versions of a document land in one partition, so "
                "no near-duplicate of a final-test row appears in "
                "fit/dev. Assignment uses row identity only, never a "
                "detector score. Fit/dev were never scored and no "
                "decision was fitted on them."
            ),
            "counts": counts,
            "manifest_path": f"docs/evidence/manifests/{manifest_path.name}",
            "manifest_sha256": manifest_sha,
            "final_test_disjoint_from_dev_split": True,
            "final_test_disjoint_from_dev_split_shared_hashes": 0,
        },
        "n56_slice_resolution": {
            "slice": "evr-20261106-opai-bench-builtin-heuristic",
            "identity": (
                "the n=56 slice IS OpAI-Bench: the default/train U1 "
                "500-row strided sample, n_human=56, n_ai=55, Wilson "
                "95% upper 0.064196 (EV-20261110-human-fpr)"
            ),
            "resolution": (
                "YES — licensed data existed to expand it, and it was "
                "expanded twice: first to n_human=218 in the train-2000 "
                "sample (supported record "
                "evr-20261110-opai-bench-builtin-heuristic, Wilson upper "
                "0.0173), and now to a pooled, document-grouped, "
                "partitioned final-test slice with "
                f"n_human={final['n_human']} and n_ai={final['n_ai']}. "
                "The final-test slice below is the held-out expansion: "
                "it was partitioned before evaluation and influenced no "
                "threshold, calibration, or selection decision."
            ),
            "final_test_n_human": final["n_human"],
            "final_test_n_ai": final["n_ai"],
            "final_test_fpr_wilson_upper": evaluation["slices"]["pooled"]["fpr_native"]["ci_upper"],
        },
        "evaluation": evaluation,
        "decisions_not_made": [
            "no threshold was fitted or tuned (native operating point)",
            "no calibration was fitted",
            "no row was dropped for how it scores",
            "no registry or report-card change was made (Worker D owns those)",
        ],
        "gaps": [
            "partial (mixed-origin) rows carry no binary label and are unmeasured here (U4 spine)",
            "only the default/train split is evaluated; dev/test splits are not",
            "Wilson intervals treat rows as independent; rows within a document group are correlated — group counts per slice are reported and AUROC/AUPRC CIs are cluster-bootstrapped over document groups, but the FPR/TPR Wilson intervals do not adjust for clustering",
            "generators are 2026-era (gemini-2.5-flash, gpt-5.4, gpt-5.4-nano); Qwen3-8B is the held-out generator and is not in this sample",
        ],
    }
    drops_manifest = [
        {"item": "full-corpus evaluation",
         "reason": "partitioned pooled sample only (n=2496 normalised rows from 196029 split rows)"},
        {"item": "Python 3.11, 3.13, 3.14, 3.15",
         "reason": "measured on the local interpreter only; CI covers the matrix"},
        {"item": "train/test threshold selection",
         "reason": "no threshold was fitted on this sample; the operating point is the detector's native verdict"},
        {"item": f"{sum(1 for r in rows if r.label is None)} partial (mixed-origin) rows",
         "reason": "rows with 0 < ai_sentence_ratio < 1 carry no binary label; they are the U4 spine, not U1 evidence"},
    ]
    if drops:
        drops_manifest.append({
            "item": f"{len(drops)} exact-duplicate rows",
            "reason": "byte-identical texts appearing twice in the pooled sample; kept once so no text is double-counted (by identity, never by score)",
        })
    record = _base_record(RUN_ID_OPAI, "command", "python scripts/measure_w8_ghostwriter_opai.py")
    record["results"] = results
    record["drops"] = drops_manifest
    record["badge"] = "available"
    path = _write_record(record, force)
    print(f"[opai] wrote {path.name} (sha256 {_sha256_file(path)[:12]}...)")
    return results


# ---------------------------------------------------------------------------
# GhostWriter
# ---------------------------------------------------------------------------

def build_ghostwriter_pool() -> tuple[list, list[dict], list[dict], dict[str, str]]:
    """Pool the U1 500-row sample with the new 2000-row sample and
    group by exact content hash + shingle-Jaccard near-duplicates.
    Returns (kept rows, sources, drops)."""
    root = default_cache_dir()
    u1_cache = root / "ghostwriter" / "default" / "train.jsonl"
    c2000_cache = root / "ghostwriter" / "default" / GW_NEW_FILENAME
    _verify_cache_sha(u1_cache, GW_OLD_CACHE_SHA256, "GhostWriter U1 cache")
    if not c2000_cache.exists():
        raise ValueError(
            f"GhostWriter {GW_NEW_FILENAME} missing — run with --fetch-only first "
            "or let the full run fetch it"
        )
    spec = get_spec("ghostwriter")
    u1 = read_sample_cache(spec, "default", "train")
    c2000 = read_sample_cache(spec, "default", "train", filename=GW_NEW_FILENAME)
    manifest2000 = json.loads(
        (root / "ghostwriter" / "default" / "train-2000.manifest.json").read_text(encoding="utf-8")
    )
    pooled = list(u1) + list(c2000)
    kept, drops = dedupe_by_content(pooled, pool_label="gw")
    cache_file_of = {r.source_id: "train.jsonl" for r in u1}
    cache_file_of.update({r.source_id: GW_NEW_FILENAME for r in c2000})
    sources = [
        {"cache_file": "train.jsonl", "file_sha256": GW_OLD_CACHE_SHA256, "rows": len(u1),
         "label_counts": {str(k): sum(1 for r in u1 if r.label == k) for k in (0, 1, None)}},
        {"cache_file": GW_NEW_FILENAME, "file_sha256": manifest2000["file_sha256"], "rows": len(c2000),
         "label_counts": {str(k): sum(1 for r in c2000 if r.label == k) for k in (0, 1, None)}},
    ]
    print(
        f"[gw] pooled {len(kept)} rows "
        f"({sum(1 for r in kept if r.label == 0)} human / "
        f"{sum(1 for r in kept if r.label == 1)} AI / "
        f"{sum(1 for r in kept if r.label is None)} fusion)"
    )
    return kept, sources, drops, cache_file_of


def run_ghostwriter(*, force: bool) -> dict:
    """GhostWriter partitioned evaluation → run artifact."""
    spec = get_spec("ghostwriter")
    rows, sources, drops, cache_file_of = build_ghostwriter_pool()
    print("[gw] computing near-duplicate groups (exact hash + shingle Jaccard >= 0.8) ...")
    group_of = group_ghostwriter_rows(rows)
    n_groups = len(set(group_of.values()))
    print(f"[gw] {n_groups} near-duplicate groups over {len(rows)} rows")
    rows_with_partitions = partition_pool(rows, group_of)
    counts = partition_counts(rows_with_partitions)
    require_final_test_size(counts, dataset_label="GhostWriter")
    print(f"[gw] partition counts: {json.dumps(counts)}")
    manifest_path, manifest_sha = write_manifest(
        dataset="ghostwriter", run_id=RUN_ID_GHOSTWRITER,
        group_key_description=(
            "near-duplicate group: exact content-hash groups merged "
            "with word-8-shingle Jaccard >= 0.8 groups (inverted-index "
            "candidates). The `source` field is NOT a document id "
            "(human rows share dataset URLs), so it cannot group "
            "documents; content identity is the grouping key."
        ),
        sources=sources, drops=drops,
        rows_with_partitions=rows_with_partitions, group_of=group_of,
        slice_of=lambda r: str(r.meta.get("domain")),
        cache_file_of=cache_file_of,
    )
    # Final-test must also be disjoint from the validation split cache
    # by content hash (different split, same corpus).
    final_rows = [r for r, p in rows_with_partitions if p == "final-test"]
    final_hashes = {content_hash(r.text) for r in final_rows}
    val_rows = read_sample_cache(spec, "default", "validation")
    val_hashes = {content_hash(r.text) for r in val_rows}
    shared_val = final_hashes & val_hashes
    if shared_val:
        raise ValueError(
            f"GhostWriter final-test shares {len(shared_val)} content hashes "
            "with the validation split cache — refusing"
        )
    print("[gw] final-test disjoint from validation split cache by content hash (0 shared)")

    scored = score_final_test(rows_with_partitions, group_of)
    human_scored = [s for s in scored if s["label"] == 0]
    by_domain: dict[str, list[dict]] = defaultdict(list)
    by_lang: dict[str, list[dict]] = defaultdict(list)
    for item in scored:
        by_domain[str(item["row"].meta.get("domain"))].append(item)
        by_lang[str(item["row"].meta.get("lang"))].append(item)
    groupings: dict[str, list[dict]] = {
        "pooled": scored, **{f"domain-{k}": v for k, v in by_domain.items()},
        **{f"lang-{k}": v for k, v in by_lang.items()},
    }
    for agent in sorted({str(s["row"].meta.get("agent")) for s in scored if s["label"] == 1}):
        groupings[f"agent-{agent}"] = human_scored + [
            s for s in scored if s["label"] == 1 and str(s["row"].meta.get("agent")) == agent
        ]
    evaluation = summarize_slices(scored, groupings, "ghostwriter")
    sensitivity = threshold_sensitivity(
        [s["score"] for s in human_scored],
        [s["reliability"] for s in human_scored],
    )
    results = {
        "dataset": "ghostwriter",
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "licence_verification": LICENCE_VERIFICATION["ghostwriter"],
        "licence_verified": LICENCE_VERIFICATION["verified_date"],
        "licence_verified_how": LICENCE_VERIFICATION["verified_how"],
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_family": BuiltinHeuristicDetector.detector_family,
        "operating_point": (
            "builtin-heuristic native verdict (analyze_text); no score "
            "threshold; no threshold was fitted, no calibration was "
            "fitted — the operating point is fixed by the detector"
        ),
        "environment_lock": _environment_lock(),
        "provenance": {
            "dataset_version": (
                "TheItCrOw/GhostWriter snapshot 2026-11-16 (no versioned "
                "release); pooled from the U1 500-row strided sample "
                "(2026-11-07) and a new phase-shifted 2000-row strided "
                "sample (2026-11-16, +83 offset shift)"
            ),
            "config": "default",
            "split": "train",
            "split_rows_total": 332224,
            "sampling": "strided (both pooled samples); new sample offsets i*332224//2000+83, disjoint from the U1 offsets by row index and by content hash",
            "sources": sources,
            "row_hash_method": "sha256 of normalised text (benchmark fingerprint)",
            "label_provenance": (
                "label 0 human / 1 AI / 2 fusion; only fulltext rows "
                "carry binary labels (label 2 rows are chunks and carry "
                "no binary label — the U4 spine, not U1 evidence)"
            ),
            "normalization_provenance": "rows mapped by textforensics.datasets.map_row('ghostwriter') at fetch time; cached normalised JSONL verified by SHA-256",
        },
        "inclusion_drop_counts": {
            "rows_pooled": len(rows) + len(drops),
            "rows_after_content_dedup": len(rows),
            "exact_content_duplicates_dropped": len(drops),
            "dropped_duplicate_rows": drops,
            "fusion_chunk_rows_excluded_from_binary_metrics": sum(
                1 for r in rows if r.label is None
            ),
            "fusion_rows_reason": (
                "label 2 (fusion) rows carry no binary label; they are "
                "the U4 spine, not U1 evidence"
            ),
            "label_counts_pooled": {
                "human": sum(1 for r in rows if r.label == 0),
                "ai": sum(1 for r in rows if r.label == 1),
                "fusion_unlabelled": sum(1 for r in rows if r.label is None),
            },
            "near_duplicate_groups": n_groups,
        },
        "partition": {
            "method": (
                "group = near-duplicate group (exact content hash, "
                "merged at word-8-shingle Jaccard >= 0.8); bucket = "
                "int(sha256(group), 16) % 10; buckets 0-2 fit, 3-4 "
                "dev/selection, 5-9 final-test. No near-duplicate of a "
                "final-test row appears in fit/dev. Assignment uses row "
                "identity only, never a detector score. Fit/dev were "
                "never scored and no decision was fitted on them."
            ),
            "counts": counts,
            "manifest_path": f"docs/evidence/manifests/{manifest_path.name}",
            "manifest_sha256": manifest_sha,
            "final_test_disjoint_from_validation_split": True,
            "final_test_disjoint_from_validation_split_shared_hashes": 0,
        },
        "evaluation": evaluation,
        "threshold_sensitivity": sensitivity,
        "threshold_sensitivity_note": (
            "The U1 GhostWriter finding reproduces in structure on the "
            "new final-test slice: the top human score sits just below "
            "the 0.68 native threshold (see max_human_score and the "
            "sensitivity table). Zero-FPR at 0.68 does NOT survive a "
            "-0.02 perturbation (one row flips at 0.66) — the threshold "
            "is UNCHANGED; this is reported, not acted on. The "
            "0.6740 top human score on the U1 137-row sample "
            "(EV-20261110-ghostwriter-threshold-robustness.md) is a "
            "different sample from this final-test slice; both are "
            "reported as measured."
        ),
        "decisions_not_made": [
            "no threshold was fitted, tuned, or moved (native 0.68 stands)",
            "no calibration was fitted",
            "no row was dropped for how it scores",
            "no registry or report-card change was made (Worker D owns those)",
        ],
        "gaps": [
            "fusion (mixed-origin) rows carry no binary label and are unmeasured here (U4 spine)",
            "the binary slice is fulltext-only: chunk behaviour is unmeasured",
            "the sample mixes English and German; per-language slices are reported separately, never pooled away",
            "Wilson intervals treat rows as independent; rows within a near-duplicate group are correlated — group counts per slice are reported and AUROC/AUPRC CIs are cluster-bootstrapped over near-duplicate groups, but the FPR/TPR Wilson intervals do not adjust for clustering",
            "chunk rows' parent fulltexts are not in any sampled cache, so chunk-to-parent linkage could not be verified in-sample (chunks are unlabelled and excluded from binary metrics regardless)",
        ],
    }
    drops_manifest = [
        {"item": "full-corpus evaluation",
         "reason": "partitioned pooled sample only (n=2500 normalised rows from 332224 split rows)"},
        {"item": "Python 3.11, 3.13, 3.14, 3.15",
         "reason": "measured on the local interpreter only; CI covers the matrix"},
        {"item": "train/test threshold selection",
         "reason": "no threshold was fitted on this sample; the operating point is the detector's native verdict"},
        {"item": f"{sum(1 for r in rows if r.label is None)} fusion (mixed-origin) rows",
         "reason": "label 2 rows carry no binary label; they are the U4 spine, not U1 evidence"},
    ]
    if drops:
        drops_manifest.append({
            "item": f"{len(drops)} exact-duplicate rows",
            "reason": (
                "byte-identical texts appearing twice in the pooled "
                "sample (including the 2 duplicate AI fulltexts already "
                "present in the U1 500-row cache, which the registry "
                "record evr-20261107-ghostwriter counts as n_ai=210); "
                "kept once so no text is double-counted (by identity, "
                "never by score)"
            ),
        })
    record = _base_record(
        RUN_ID_GHOSTWRITER, "command", "python scripts/measure_w8_ghostwriter_opai.py"
    )
    record["results"] = results
    record["drops"] = drops_manifest
    record["badge"] = "available"
    path = _write_record(record, force)
    print(f"[gw] wrote {path.name} (sha256 {_sha256_file(path)[:12]}...)")
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fetch-only",
        action="store_true",
        help="fetch the new GhostWriter sample and stop (no evaluation)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing run artifacts; re-fetch the GhostWriter sample",
    )
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help="parallel fetch workers (default 4)",
    )
    args = parser.parse_args(argv)

    root = default_cache_dir()
    gw_new_cache = root / "ghostwriter" / "default" / GW_NEW_FILENAME
    if args.fetch_only:
        if gw_new_cache.exists() and not args.force:
            print(f"[gw] {GW_NEW_FILENAME} already exists; use --force to re-fetch")
            return 0
        if args.force and gw_new_cache.exists():
            print("[gw] --force: removing existing train-2000 cache + checkpoint for a clean re-fetch")
            gw_new_cache.unlink()
            (root / "ghostwriter" / "default" / "train-2000.manifest.json").unlink(missing_ok=True)
            (root / "ghostwriter" / "default" / GW_RAW_CHECKPOINT_FILENAME).unlink(missing_ok=True)
        fetch_ghostwriter_sample(workers=args.workers)
        print("[gw] fetch-only done")
        return 0
    if not gw_new_cache.exists():
        print(f"[gw] {GW_NEW_FILENAME} missing; fetching it first")
        fetch_ghostwriter_sample(workers=args.workers)

    print("[w8] re-running U1 reproduction checks (fail closed on mismatch) ...")
    reproduce_u1_checks()
    print("[w8] evaluating OpAI-Bench ...")
    opai = run_opai(force=args.force)
    print("[w8] evaluating GhostWriter ...")
    gw = run_ghostwriter(force=args.force)
    pooled_opai = opai["evaluation"]["slices"]["pooled"]
    pooled_gw = gw["evaluation"]["slices"]["pooled"]
    print(
        "[w8] done:\n"
        f"  OpAI-Bench final-test: n_human={pooled_opai['n_human']} "
        f"n_ai={pooled_opai['n_ai']} FPR {pooled_opai['fpr_native']['k']}/{pooled_opai['n_human']} "
        f"Wilson95=[{pooled_opai['fpr_native']['ci_lower']:.4f}, {pooled_opai['fpr_native']['ci_upper']:.4f}] "
        f"TPR {pooled_opai['tpr_native']['value']:.4f} AUROC {pooled_opai.get('auroc', {}).get('value')} "
        f"AUPRC {pooled_opai.get('auprc', {}).get('value')} abstentions={pooled_opai['abstentions']} "
        f"worst_slice={opai['evaluation']['worst_slice']['slice_id']}\n"
        f"  GhostWriter final-test: n_human={pooled_gw['n_human']} "
        f"n_ai={pooled_gw['n_ai']} FPR {pooled_gw['fpr_native']['k']}/{pooled_gw['n_human']} "
        f"Wilson95=[{pooled_gw['fpr_native']['ci_lower']:.4f}, {pooled_gw['fpr_native']['ci_upper']:.4f}] "
        f"TPR {pooled_gw['tpr_native']['value']:.4f} AUROC {pooled_gw.get('auroc', {}).get('value')} "
        f"AUPRC {pooled_gw.get('auprc', {}).get('value')} abstentions={pooled_gw['abstentions']} "
        f"worst_slice={gw['evaluation']['worst_slice']['slice_id']} "
        f"max_human_score={gw['threshold_sensitivity']['max_human_score']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
