#!/usr/bin/env python3
"""qualify_w8_raid_mage.py — W8 Worker A: independently qualify RAID + MAGE.

Qualification wave (0 findings by design): this script produces scientific
evidence, not fixes. It does NOT change inference/provenance code and does
NOT touch the registry or the report card (Worker D owns those).

Predeclared design (fixed BEFORE any final-test row is fetched or scored)
-------------------------------------------------------------------------
Detector: textforensics/builtin-heuristic 0.1.0, deterministic. Operating
point: the detector's NATIVE categorical verdict
(``BuiltinHeuristicDetector().detect`` -> ai_like / human_like / abstain;
no score threshold exists and none is fitted anywhere in this script).
FPR = P(verdict=ai_like | human); native TPR = P(verdict=ai_like | AI).
AUROC / AUPRC / TPR@FPR are threshold-free, computed from raw scores.
Coverage = 1 - abstention rate; abstentions are never dropped, never
counted as a verdict, and still contribute their score to AUROC/AUPRC.

No fitting happens at all: train / dev / selection / fit partitions are
EMPTY BY DESIGN (no threshold, no calibration, no selection decision is
made from any data). Validation = the frozen prior samples (re-measured
here on the W7 code for a reproduction check). Final-test = fresh samples
fetched by this script from offsets fixed before fetching.

Partitions (RAID, liamdugan/raid, MIT; train total 2,270,000):
- validation: cached ``train-6000.jsonl`` (6000 rows, 171 human), the
  EV-20261108 sample. Re-measured, not re-fetched.
- final-test: NEW phase-shifted strided sample, n=4000, from raid/train.
  The shift is the smallest s in 0..566 whose offset grid is disjoint BY
  ROW INDEX from both the U1 3000-grid and the phase-shifted (+189)
  6000-grid. Disjointness is then proven BY CONTENT HASH against the
  validation cache, the U1 cache and raid_test/test.
- raid_test/test (50 rows) is UNLABELLED: coverage/abstention probe only,
  never scored as a class; disjointness target only.
- TOP-UP RULE (predeclared): if final-test n_human < 100, fetch a second
  predeclared grid (n=2000, next valid shift by the same search) and pool
  it into final-test. Expected humans at 2.85% density: ~114 in 4000.

Partitions (MAGE, yaful/MAGE, Apache-2.0; test total 60,743):
- validation: cached ``train.jsonl`` (400 rows, 117 human), the
  EV-20261106 sample. Re-measured, not re-fetched.
- final-test: NEW strided sample, n=600, from default/test — the dataset's
  own held-out split, never sampled before. Disjointness proven BY CONTENT
  HASH against train-400 and validation-50 (MAGE source_id IS the text
  hash, so content-hash disjointness is source disjointness).
- TOP-UP RULE (predeclared): if final-test n_human < 100, fetch a second
  predeclared grid (n=400, shift = half the grid step, index-disjoint
  from the first grid) and pool it into final-test.

Leakage rules (enforced, fail-closed):
1. Exact normalised-text SHA-256 overlap between final-test and any other
   partition must be 0, else the run refuses to report final-test metrics.
2. RAID human-source overlap: a final-test human row whose
   meta.source_id is among the validation human meta.source_ids is the
   SAME human text evaluated twice — it is EXCLUDED from final-test FPR
   (listed in exclusions, with its hash prefix) and the exclusion is
   reported, never silent.
3. Near-duplicates: for cross-partition row pairs sharing a RAID
   meta.source_id, word-8-gram Jaccard is computed; any pair > 0.8 is a
   near-duplicate leak and the final-test row is EXCLUDED (listed).
   The max Jaccard and the count > 0.5 are always reported.

Gates (predeclared): a slice supports an FPR claim only if n_human >= 100
AND the Wilson 95% upper bound on human FPR is <= 0.05. The worst slice
is reported explicitly; nothing is pooled away.

Uncertainty: Wilson 95% (z=1.96) for every FPR/TPR rate (rare-event
bounds; bootstrap CIs over an all-zero sample are degenerate [0,0] and
are NOT used for rates). AUROC/AUPRC/TPR@FPR get bootstrap 95% CIs
(1000 resamples, seed 20261116). Where k_fp > 0, a cluster bootstrap
(resampling source-document clusters) is reported alongside Wilson.
Clusters: RAID meta.source_id (source document); MAGE src testbed.

Licence re-verification (2026-11-16, live, before fetching):
- RAID: HF API cardData license ``mit`` + GitHub liamdugan/raid MIT.
  Caveat stands: MIT covers the distribution; underlying human source
  texts carry their own upstream licences.
- MAGE: HF API cardData license ``apache-2.0`` (tag license:apache-2.0)
  + GitHub yafuly/MAGE Apache-2.0 (note: the README links yafuly/MAGE;
  the 2026-11-06 note's "yaful/MAGE" GitHub path was a typo — the repo
  lives under yafuly). The CC BY 4.0 badge conflict recorded in 2026-11-06
  is NOT reproduced in the current README (frontmatter says apache-2.0,
  no badge present); both readings are permissive, so local evaluation
  is permitted under either. Authors are attributed in any case.
Both corpora are used under their permissive licences for local,
non-commercial evaluation only; no data is redistributed and no raw text
is written to the repo (caches live outside it, artifacts carry counts,
hashes and metrics only).

The n=56 finding (task brief): the n=56 slice in EV-20261110-human-fpr
is the OpAI-Bench DOCUMENT slice (evr-20261106-opai-bench), NOT RAID or
MAGE. It was already expanded to n=218 human rows (evr-20261110-opai-
bench, supported, Wilson upper 0.0173). No RAID/MAGE expansion is owed
for it; this is verified in the part-report, not assumed.

Usage:
    python scripts/qualify_w8_raid_mage.py [--force] [--workers N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from measure_datasets import auroc, tpr_at_fpr  # noqa: E402
from seed_evidence import _base_record, _write_record  # noqa: E402

from textforensics.benchmark import check_disjointness, fingerprint_dataset  # noqa: E402
from textforensics.datasets import (  # noqa: E402
    LICENCE_VERIFIED,
    DatasetsServerClient,
    canonical_text_sha256,
    default_cache_dir,
    get_spec,
    map_row,
    sample_offsets,
    write_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402

BOOTSTRAP_SEED = 20261116
BOOTSTRAP_RESAMPLES = 1000
MIN_N_HUMAN = 100
FPR_UPPER_MAX = 0.05
DEFAULT_WORKERS = 4
FETCH_ROUNDS = 5
FETCH_ROUND_PAUSE_S = 30
MANIFESTS_DIR = REPO_ROOT / "docs" / "evidence" / "manifests"

RAID_TRAIN_TOTAL = 2_270_000
RAID_TEST_TOTAL = 672_000
RAID_FINAL_N = 4000
RAID_TOPUP_N = 2000
RAID_OLD_SHIFT = 189  # phase shift of the EV-20261108 6000-grid
RAID_OLD_N = 6000
RAID_U1_N = 3000
MAGE_TEST_TOTAL = 60_743
MAGE_FINAL_N = 600
MAGE_TOPUP_N = 400
UNMEASURED_VERSIONS = ["3.11", "3.13", "3.14", "3.15"]

# Frozen prior samples (validation partitions). SHA-256 verified before use.
FROZEN = {
    "raid": {
        "cache_rel": ("raid", "raid", "train-6000.jsonl"),
        "manifest_rel": ("raid", "raid", "train-6000.manifest.json"),
        "sha256": "59cf57c4db6778dad065cc78c4b4f92c54544d57652aa30606c307c3f81d44d3",
        "rows": 6000,
        "n_human": 171,
        "n_ai": 5829,
        "prior_run": "EV-20261108-dataset-raid",
        "prior_auroc": 0.5958,
        "prior_tpr_at_1pct": 0.0571,
        "prior_tpr_at_5pct": 0.1414,
    },
    "mage": {
        "cache_rel": ("mage", "default", "train.jsonl"),
        "manifest_rel": ("mage", "default", "train.manifest.json"),
        "sha256": "8969989f35f6affbfc07d1b6846e9acdb481790b964563289342aa075d06eba3",
        "rows": 400,
        "n_human": 117,
        "n_ai": 283,
        "prior_run": "EV-20261106-dataset-mage",
        "prior_auroc": 0.5567,
        "prior_tpr_at_1pct": None,
        "prior_tpr_at_5pct": None,
    },
}
# Extra disjointness targets (already cached, verified, never re-fetched).
EXTRA_TARGETS = {
    "raid": [
        {
            "cache_rel": ("raid", "raid", "train.jsonl"),
            "sha256": "f689a30963024b2dc1fa159f2888e1d2ba36e68263d467ab7f73db5d9e780c00",
            "label": "raid/train U1 sample (n=3000)",
            "split": "train",
        },
        {
            "cache_rel": ("raid", "raid_test", "test.jsonl"),
            "sha256": "bf2b73d5a45c299b3ce0dae8f9369b80fc08f165fa5f5b7173f35754bdec570a",
            "label": "raid_test/test (n=50, unlabelled)",
            "split": "test",
        },
    ],
    "mage": [
        {
            "cache_rel": ("mage", "default", "validation.jsonl"),
            "sha256": "dbb5ca488ad3b5f4929063c2bc761d2c742bee02a82ae93bfa433fa25578ce12",
            "label": "mage/default validation sample (n=50)",
            "split": "validation",
        },
    ],
}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_cache_rows(path: Path) -> list[dict]:
    return [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


def _check_server_total(
    spec, config: str, split: str, expected: int, client: DatasetsServerClient
) -> None:
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


def _find_shift(total: int, n: int, forbidden: list[set[int]]) -> int:
    """Smallest shift s with the s-shifted n-grid disjoint from every forbidden set."""
    base = sample_offsets(total, n)
    for shift in range(0, total // n + 1):
        cand = {(offset + shift) % total for offset in base}
        if len(cand) != n:
            continue
        if any(cand & other for other in forbidden):
            continue
        return shift
    raise ValueError(f"no disjoint shift found for total={total} n={n}")


def _shifted_offsets(total: int, n: int, shift: int) -> list[int]:
    return [(offset + shift) % total for offset in sample_offsets(total, n)]


def _fetch_one_offset(
    offset: int, client: DatasetsServerClient, spec, config: str, split: str
) -> dict:
    page: list[dict] | None = None
    for round_no in range(1, FETCH_ROUNDS + 1):
        try:
            page = client.rows(spec.hf_id, config, split, offset=offset, length=1)
            break
        except Exception as exc:  # noqa: BLE001 - retry, then re-raise below
            print(
                f"[fetch] offset {offset}: round {round_no}/{FETCH_ROUNDS} failed ({exc})",
                flush=True,
            )
            if round_no == FETCH_ROUNDS:
                raise
            time.sleep(FETCH_ROUND_PAUSE_S * round_no + random.uniform(0, FETCH_ROUND_PAUSE_S))
    if not page:
        raise ValueError(
            f"{spec.hf_id} {config}/{split}: server returned no row at offset {offset}"
        )
    return page[0]


def fetch_shifted_sample(
    *,
    key: str,
    config: str,
    split: str,
    total: int,
    n: int,
    shift: int,
    cache_filename: str,
    checkpoint_filename: str,
    workers: int = DEFAULT_WORKERS,
) -> tuple[list[dict], list[int]]:
    """Fetch a phase-shifted strided sample, resuming from the checkpoint.

    Returns raw rows in offset order plus the offsets used. The checkpoint
    preserves fetched rows across runs; it is deleted once the normalised
    cache is written and verified.
    """
    spec = get_spec(key)
    if spec.licence_status != LICENCE_VERIFIED:
        raise ValueError(
            f"{key}: licence_status is {spec.licence_status!r}, not verified — refusing to fetch"
        )
    client = DatasetsServerClient()
    _check_server_total(spec, config, split, total, client)
    offsets = _shifted_offsets(total, n, shift)
    if len(set(offsets)) != n:
        raise ValueError(f"{key}: shifted offsets are not unique: {len(set(offsets))} of {n}")
    root = default_cache_dir()
    checkpoint = root / key / config / checkpoint_filename
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
                    print(
                        "[fetch] dropping truncated trailing checkpoint line; offset will be re-fetched"
                    )
                    dropped_trailing = True
                    break
                raise
            done[int(entry["offset"])] = entry["row"]
        if dropped_trailing:
            checkpoint.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        print(
            f"[fetch] {key}/{config}/{split}: resuming from checkpoint: {len(done)} rows already fetched"
        )
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
                base_url=client.base_url,
                timeout_s=client.timeout_s,
                retries=client.retries,
                user_agent=client.user_agent,
            )
            thread_local.client = owned
        return owned

    def work(offset: int) -> tuple[int, dict]:
        return offset, _fetch_one_offset(offset, thread_client(), spec, config, split)

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
                if fetched % 500 == 0 or fetched == n:
                    elapsed = time.time() - started
                    rate = state["fetched_this_run"] / max(elapsed, 1e-9)
                    eta = (n - fetched) / rate if rate > 0 else 0.0
                    print(
                        f"[fetch] {key}: {fetched}/{n} rows "
                        f"({elapsed:.0f}s elapsed this run, ETA {eta:.0f}s)",
                        flush=True,
                    )
    rows = [results[offset] for offset in offsets]
    if len(rows) != n:
        raise ValueError(f"{key}: fetched {len(rows)} rows, expected {n}")
    return rows, offsets


def auprc(labels: list[int], scores: list[float]) -> float:
    """Average precision (area under the precision-recall curve).

    Rank-based, no third-party deps: sort by score descending, walk the
    ranking, and accumulate precision gains at each positive. Raises
    unless both classes are present.
    """
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


def _bootstrap_ci(
    pairs: list[tuple[int, float]],
    fn,
    *,
    seed: int = BOOTSTRAP_SEED,
    resamples: int = BOOTSTRAP_RESAMPLES,
) -> dict | None:
    """Percentile bootstrap 95% CI for a statistic over (label, score) pairs.

    Returns None when the statistic is undefined on the full sample.
    Resamples missing a class are skipped and counted; the CI is None
    when too few resamples survive (< 100).
    """
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


def _wilson_entry(k: int, n: int) -> dict:
    lo, hi = wilson_ci(k, n)
    return {
        "k": k,
        "n": n,
        "value": round(k / n, 4) if n else None,
        "ci_lower": round(lo, 4),
        "ci_upper": round(hi, 4),
        "method": "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci",
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


def _cluster_bootstrap_fpr(
    human_clusters: list[tuple[str, int]],
    *,
    seed: int = BOOTSTRAP_SEED,
    resamples: int = BOOTSTRAP_RESAMPLES,
) -> dict | None:
    """Cluster bootstrap 95% CI for the human FPR, resampling clusters.

    ``human_clusters`` is (cluster_id, 1-if-false-positive-else-0) per
    human row. Returns None when k_fp == 0: every resample is 0, so the
    interval is the degenerate [0, 0] and Wilson is the honest bound.
    """
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


def _length_bucket(words: int) -> str:
    if words < 80:
        return "<80 words (below detector floor)"
    if words < 200:
        return "80-199 words"
    if words < 500:
        return "200-499 words"
    return "500+ words"


def _mage_testbed(src: str) -> str:
    return src.split("_human")[0].split("_machine")[0]


def _mage_task(src: str) -> str | None:
    if "_machine_" not in src:
        return None
    rest = src.split("_machine_", 1)[1]
    return rest.split("_", 1)[0]


def _mage_generator_family(src: str) -> str | None:
    if "_machine_" not in src:
        return None
    rest = src.split("_machine_", 1)[1]
    gen = rest.split("_", 1)[1] if "_" in rest else rest
    if gen.startswith("opt"):
        return "OPT"
    if gen.startswith("flan_t5"):
        return "Flan-T5"
    if gen.startswith("gpt-3.5"):
        return "GPT-3.5-turbo"
    if gen.startswith("text-davinci"):
        return "GPT-3 (davinci)"
    if gen in ("7B", "13B", "30B", "65B"):
        return "LLaMA"
    if gen.startswith("bloom"):
        return "BLOOM"
    if gen.startswith("gpt_j"):
        return "GPT-J"
    if gen.startswith("gpt_neox"):
        return "GPT-NeoX"
    if gen.startswith("t0"):
        return "T0"
    if gen.startswith("GLM130B"):
        return "GLM-130B"
    return f"unclassified:{gen}"


def measure_rows(detector, rows: list[dict]) -> list[dict]:
    """Run the detector at its native operating point over normalised cache rows.

    Returns one dict per row: label, score, verdict, word count, meta,
    text hash (for disjointness), source/cluster id. Detection errors are
    counted as drops by the caller via the ``error`` field (expected 0).
    """
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
                "text_sha256": canonical_text_sha256(row["text"]),
                "raw_sha256": _sha256_text(row["text"]),
            }
        )
    return out


def slice_metrics(
    slice_id: str,
    measured: list[dict],
    *,
    cluster_key,
    bootstrap: bool = True,
) -> dict:
    """Per-slice metrics at the fixed native operating point.

    FPR/TPR use Wilson 95% intervals (rare-event honest). AUROC/AUPRC/
    TPR@FPR use bootstrap 95% CIs. Slices with < 10 rows in a class get
    no AUROC/AUPRC (same rule as the U1/U7 runs); rates are still
    reported with Wilson intervals and the small n is visible.
    """
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
        "fpr_native": _wilson_entry(k_fp, len(human)) if human else None,
        "tpr_native": _wilson_entry(k_tp, len(ai)) if ai else None,
        "coverage": round(1 - abstentions / len(labelled), 4) if labelled else None,
        "abstention_rate": round(abstentions / len(labelled), 4) if labelled else None,
        "abstentions": abstentions,
        "score_by_label": {
            "human": _score_summary([m["score"] for m in human]),
            "machine": _score_summary([m["score"] for m in ai]),
        },
        "max_human_score": round(max((m["score"] for m in human), default=0.0), 4),
        "operating_point": "builtin-heuristic native verdict (analyze_text via "
        "BuiltinHeuristicDetector.detect); no score threshold",
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
    if bootstrap and len(human) >= 10 and len(ai) >= 10:
        result["auroc"] = _bootstrap_ci(pairs, auroc)
        result["auprc"] = _bootstrap_ci(pairs, auprc)
        result["auprc_baseline_prevalence"] = round(len(ai) / len(labelled), 4)
        result["tpr_at_fpr_0_01"] = _bootstrap_ci(
            pairs, lambda labs, scs: tpr_at_fpr(labs, scs, 0.01)
        )
        result["tpr_at_fpr_0_05"] = _bootstrap_ci(
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
    cluster_fpr = _cluster_bootstrap_fpr(
        [(cluster_key(m), 1 if m["verdict"] == "ai_like" else 0) for m in human]
    )
    if cluster_fpr is not None:
        result["fpr_native_cluster_bootstrap"] = cluster_fpr
    return result


def _write_manifest(manifest: dict) -> Path:
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
    path = MANIFESTS_DIR / f"{manifest['manifest_id']}.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[manifest] wrote {path.name} (sha256 {_sha256_file(path)[:12]}...)")
    return path


def _env_lock() -> dict:
    lock = {}
    for name in ("requirements-pinned.txt", "requirements-hashed.txt"):
        path = REPO_ROOT / name
        lock[name] = _sha256_file(path) if path.exists() else None
    return lock


def _verify_frozen(key: str) -> tuple[Path, list[dict]]:
    info = FROZEN[key]
    root = default_cache_dir()
    cache_path = root.joinpath(*info["cache_rel"])
    manifest_path = root.joinpath(*info["manifest_rel"])
    if not cache_path.exists():
        raise ValueError(f"{key}: frozen validation cache missing: {cache_path}")
    if not manifest_path.exists():
        raise ValueError(f"{key}: frozen validation manifest missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["file_sha256"] != info["sha256"]:
        raise ValueError(
            f"{key}: manifest sha {manifest['file_sha256']} != expected {info['sha256']}"
        )
    if _sha256_file(cache_path) != info["sha256"]:
        raise ValueError(f"{key}: cache file does not hash to {info['sha256']} — refusing")
    if manifest["rows"] != info["rows"]:
        raise ValueError(f"{key}: manifest rows {manifest['rows']} != expected {info['rows']}")
    rows = _load_cache_rows(cache_path)
    if len(rows) != info["rows"]:
        raise ValueError(f"{key}: cache holds {len(rows)} rows, expected {info['rows']}")
    counts = Counter(r["label"] for r in rows)
    if counts.get(0, 0) != info["n_human"] or counts.get(1, 0) != info["n_ai"]:
        raise ValueError(
            f"{key}: cache label counts {dict(counts)} != expected human={info['n_human']} ai={info['n_ai']}"
        )
    print(
        f"[{key}] frozen validation cache verified: {info['rows']} rows, sha256 {info['sha256'][:12]}..."
    )
    return cache_path, rows


def _disjointness_vs_targets(key: str, cache_path: Path, split: str) -> list[dict]:
    fp = fingerprint_dataset(cache_path, key, split=split)
    checks = []
    for target in EXTRA_TARGETS[key]:
        root = default_cache_dir()
        other = root.joinpath(*target["cache_rel"])
        if _sha256_file(other) != target["sha256"]:
            raise ValueError(
                f"{key}: disjointness target {target['label']} does not hash to its frozen sha"
            )
        fp2 = fingerprint_dataset(other, key, split=target["split"])
        check = check_disjointness(cache_path, fp, other, fp2)
        checks.append(
            {
                "against": target["label"],
                "disjoint": check["disjoint"],
                "verified": check["verified"],
                "shared_samples": check["shared_samples"],
                "errors": check["errors"],
            }
        )
        print(
            f"[{key}] disjointness vs {target['label']}: {check['disjoint']} "
            f"(verified={check['verified']}, shared={check['shared_samples']})"
        )
        if not check["disjoint"] or not check["verified"]:
            raise ValueError(f"{key}: NOT disjoint from {target['label']}: {check} — refusing")
    return checks


def _raid_leakage_checks(
    validation_rows: list[dict], final_rows: list[dict]
) -> tuple[list[dict], list[dict], dict]:
    """RAID source-document leakage rules (predeclared).

    Returns (kept_final_rows, exclusions, near_duplicate_report).
    Exclusion 1: final-test human row sharing a validation human
    meta.source_id (same human text twice). Exclusion 2: any final-test
    row with word-8-gram Jaccard > 0.8 against a validation row sharing
    its meta.source_id.
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
                    "text_sha256_prefix": canonical_text_sha256(row["text"])[:16],
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
                    "text_sha256_prefix": canonical_text_sha256(row["text"])[:16],
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


def _get_or_fetch_final(
    *,
    key: str,
    config: str,
    split: str,
    total: int,
    n: int,
    shift: int,
    cache_filename: str,
    checkpoint_filename: str,
    forbidden_offsets: list[set[int]],
    workers: int,
    force: bool,
) -> tuple[list[dict], list[int], bool, Path, dict]:
    """Return (normalised rows, offsets, fetched_fresh, cache_path, fetch_info).

    Reuses a verified existing W8 cache unless --force; otherwise fetches
    the shifted grid (index-disjointness proven before any fetch).
    """
    spec = get_spec(key)
    root = default_cache_dir()
    cache_path = root / key / config / cache_filename
    manifest_path = root / key / config / cache_filename.replace(".jsonl", ".manifest.json")
    offsets = _shifted_offsets(total, n, shift)
    if any(set(offsets) & other for other in forbidden_offsets):
        raise ValueError(f"{key}: shift {shift} grid overlaps a forbidden grid — refusing")
    if cache_path.exists() and manifest_path.exists() and not force:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if _sha256_file(cache_path) == manifest["file_sha256"] and manifest["rows"] == n:
            rows = _load_cache_rows(cache_path)
            print(f"[{key}] reusing verified W8 cache {cache_filename} ({len(rows)} rows)")
            return rows, offsets, False, cache_path, {"reused_cache": True, "shift": shift}
        print(f"[{key}] existing cache {cache_filename} fails verification — re-fetching")
    raw, used_offsets = fetch_shifted_sample(
        key=key,
        config=config,
        split=split,
        total=total,
        n=n,
        shift=shift,
        cache_filename=cache_filename,
        checkpoint_filename=checkpoint_filename,
        workers=workers,
    )
    normalized = []
    mapper_failures = []
    for offset, row in zip(used_offsets, raw, strict=True):
        try:
            normalized.extend(map_row(key, row, config, split))
        except Exception as exc:  # noqa: BLE001 - counted as a drop, never hidden
            mapper_failures.append({"offset": offset, "error": f"{type(exc).__name__}: {exc}"})
    if mapper_failures:
        raise ValueError(
            f"{key}: {len(mapper_failures)} mapper failures on fetch: {mapper_failures[:3]}"
        )
    cache_path, manifest_path = write_sample_cache(
        spec, config, split, normalized, filename=cache_filename
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["file_sha256"] != _sha256_file(cache_path):
        raise ValueError(f"{key}: new cache manifest sha != recomputed sha")
    if len(normalized) != n:
        raise ValueError(f"{key}: mapped {len(normalized)} rows, expected {n}")
    checkpoint = root / key / config / checkpoint_filename
    checkpoint.unlink(missing_ok=True)
    print(
        f"[{key}] cached {len(normalized)} rows -> {cache_path.name} (sha256 {manifest['file_sha256'][:12]}...)"
    )
    # Downstream code works on plain dicts (the cache JSONL format).
    return (
        [asdict(r) for r in normalized],
        used_offsets,
        True,
        cache_path,
        {"reused_cache": False, "shift": shift},
    )


def _dedupe_exact(rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Drop exact-duplicate texts within one sample (keep first)."""
    seen: set[str] = set()
    kept, dropped = [], []
    for row in rows:
        h = canonical_text_sha256(row["text"])
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


def _worst_human_slice(slices: list[dict]) -> dict | None:
    """Worst slice = max Wilson FPR upper among human slices with n_human >= 10."""
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


def _build_slices(key: str, measured: list[dict]) -> tuple[list[dict], list[dict]]:
    """Predeclared slice lists. Returns (primary_slices, secondary_slices)."""
    primary: list[dict] = [slice_metrics("pooled", measured, cluster_key=_cluster_key(key))]
    secondary: list[dict] = []
    if key == "raid":
        by_domain: dict[str, list[dict]] = defaultdict(list)
        by_length: dict[str, list[dict]] = defaultdict(list)
        for m in measured:
            by_domain[str(m["meta"].get("domain"))].append(m)
            by_length[_length_bucket(m["words"])].append(m)
        for domain in sorted(by_domain):
            primary.append(
                slice_metrics(f"domain:{domain}", by_domain[domain], cluster_key=_cluster_key(key))
            )
        for bucket in sorted(by_length):
            secondary.append(
                slice_metrics(f"length:{bucket}", by_length[bucket], cluster_key=_cluster_key(key))
            )
        for field, prefix in (
            ("model", "model"),
            ("attack", "attack"),
            ("decoding", "decoding"),
        ):
            groups: dict[str, list[dict]] = defaultdict(list)
            for m in measured:
                groups[str(m["meta"].get(field))].append(m)
            for value in sorted(groups):
                secondary.append(
                    slice_metrics(f"{prefix}:{value}", groups[value], cluster_key=_cluster_key(key))
                )
    else:  # mage
        by_testbed: dict[str, list[dict]] = defaultdict(list)
        by_task: dict[str, list[dict]] = defaultdict(list)
        by_family: dict[str, list[dict]] = defaultdict(list)
        by_length: dict[str, list[dict]] = defaultdict(list)
        for m in measured:
            src = str(m["meta"].get("src", ""))
            by_testbed[_mage_testbed(src)].append(m)
            task = _mage_task(src)
            if task is not None:
                by_task[task].append(m)
            family = _mage_generator_family(src)
            if family is not None:
                by_family[family].append(m)
            by_length[_length_bucket(m["words"])].append(m)
        for testbed in sorted(by_testbed):
            primary.append(
                slice_metrics(
                    f"testbed:{testbed}", by_testbed[testbed], cluster_key=_cluster_key(key)
                )
            )
        for bucket in sorted(by_length):
            secondary.append(
                slice_metrics(f"length:{bucket}", by_length[bucket], cluster_key=_cluster_key(key))
            )
        for task in sorted(by_task):
            secondary.append(
                slice_metrics(f"task:{task}", by_task[task], cluster_key=_cluster_key(key))
            )
        for family in sorted(by_family):
            secondary.append(
                slice_metrics(
                    f"generator_family:{family}", by_family[family], cluster_key=_cluster_key(key)
                )
            )
    return primary, secondary


def _cluster_key(key: str):
    if key == "raid":
        return lambda m: str(m["meta"].get("source_id") or m["source_id"])
    return lambda m: _mage_testbed(str(m["meta"].get("src", "")))


def qualify_corpus(key: str, *, force: bool, workers: int, command: str) -> dict:
    """Qualify one corpus end to end. Returns the run-artifact results dict."""
    spec = get_spec(key)
    run_id = f"EV-20261116-dataset-{key}"
    print(f"[{key}] === W8 qualification: {spec.name} ({spec.hf_id}) ===")

    # 1. Licence (re-verified live 2026-11-16; see module docstring).
    if spec.licence_status != LICENCE_VERIFIED:
        raise ValueError(
            f"{key}: licence_status is {spec.licence_status!r} — STOP, do not use the data"
        )
    licence_block = {
        "licence": spec.licence,
        "licence_status": spec.licence_status,
        "licence_note": spec.licence_note,
        "reverified": "2026-11-16 (live: HF API cardData + GitHub repo metadata)",
        "permitted_use": "local non-commercial evaluation only; no redistribution; no raw text in the repo",
    }
    print(f"[{key}] licence: {spec.licence} (verified, re-checked 2026-11-16)")

    # 2. Frozen validation partition (verify hashes + counts; re-measure).
    val_cache_path, val_rows = _verify_frozen(key)
    val_rows, val_dupes = _dedupe_exact(val_rows)
    val_counts = Counter(r["label"] for r in val_rows)

    # 3. Plan + freeze the manifest BEFORE fetching final-test (offsets are
    #    a pure function of the plan; no final-test text or score is seen
    #    before the freeze).
    if key == "raid":
        u1_offsets = set(sample_offsets(RAID_TRAIN_TOTAL, RAID_U1_N))
        old_offsets = {
            (o + RAID_OLD_SHIFT) % RAID_TRAIN_TOTAL
            for o in sample_offsets(RAID_TRAIN_TOTAL, RAID_OLD_N)
        }
        shift = _find_shift(RAID_TRAIN_TOTAL, RAID_FINAL_N, [u1_offsets, old_offsets])
        final_offsets = _shifted_offsets(RAID_TRAIN_TOTAL, RAID_FINAL_N, shift)
        forbidden = [u1_offsets, old_offsets]
        final_plan = {
            "config": "raid",
            "split": "train",
            "split_rows_total": RAID_TRAIN_TOTAL,
            "sampling": "strided, phase-shifted",
            "n_target": RAID_FINAL_N,
            "phase_shift": shift,
            "shift_rule": "smallest shift with zero row-index overlap vs U1 3000-grid and +189 6000-grid",
            "offsets_first_5": final_offsets[:5],
            "offsets_last_5": final_offsets[-5:],
            "offsets_sha256": _sha256_text(json.dumps(final_offsets)),
            "cache_filename": "train-4000-w8.jsonl",
            "topup": {
                "rule": f"if n_human < {MIN_N_HUMAN}, fetch a second grid n={RAID_TOPUP_N} "
                "with the next valid shift by the same search, and pool it",
                "n": RAID_TOPUP_N,
            },
        }
    else:
        shift = 0
        final_offsets = sample_offsets(MAGE_TEST_TOTAL, MAGE_FINAL_N)
        forbidden = []
        final_plan = {
            "config": "default",
            "split": "test",
            "split_rows_total": MAGE_TEST_TOTAL,
            "sampling": "strided",
            "n_target": MAGE_FINAL_N,
            "phase_shift": 0,
            "shift_rule": "unshifted strided grid; no prior test-split sample exists",
            "offsets_first_5": final_offsets[:5],
            "offsets_last_5": final_offsets[-5:],
            "offsets_sha256": _sha256_text(json.dumps(final_offsets)),
            "cache_filename": "test-600-w8.jsonl",
            "topup": {
                "rule": f"if n_human < {MIN_N_HUMAN}, fetch a second grid n={MAGE_TOPUP_N} "
                "shifted by half the grid step (50), index-disjoint from the first grid, and pool it",
                "n": MAGE_TOPUP_N,
            },
        }
    manifest_id = f"EV-20261116-{key}-manifest"
    manifest: dict = {
        "schema": "textforensics.w8-manifest/v1",
        "manifest_id": manifest_id,
        "run_id": run_id,
        "corpus": key,
        "hf_id": spec.hf_id,
        "paper": spec.paper,
        "citation": spec.citation,
        "status": "planned",
        "licence": licence_block,
        "detector": {
            "detector_id": BuiltinHeuristicDetector.detector_id,
            "detector_version": BuiltinHeuristicDetector.detector_version,
            "operating_point": "native categorical verdict; no score threshold; no calibration",
        },
        "gates": {
            "min_n_human": MIN_N_HUMAN,
            "fpr_wilson_upper_max": FPR_UPPER_MAX,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
        },
        "partitions": {
            "train": None,
            "dev": None,
            "selection": None,
            "fit": None,
            "note": "train/dev/selection/fit are EMPTY BY DESIGN: no threshold, "
            "calibration or selection decision is made from any data; the "
            "detector's operating point is fixed by the detector itself.",
            "validation": {
                "config": "raid" if key == "raid" else "default",
                "split": "train",
                "cache_file": "/".join(FROZEN[key]["cache_rel"]),
                "cache_sha256": FROZEN[key]["sha256"],
                "n_rows": FROZEN[key]["rows"],
                "n_human": FROZEN[key]["n_human"],
                "n_ai": FROZEN[key]["n_ai"],
                "prior_run": FROZEN[key]["prior_run"],
            },
            "final_test": final_plan,
        },
    }
    manifest_path = _write_manifest(manifest)

    # 4. Fetch final-test (offsets already frozen above).
    fetch_kwargs = dict(
        key=key,
        config=final_plan["config"],
        split=final_plan["split"],
        total=final_plan["split_rows_total"],
        n=final_plan["n_target"],
        shift=final_plan["phase_shift"],
        cache_filename=final_plan["cache_filename"],
        checkpoint_filename=final_plan["cache_filename"].replace(".jsonl", ".raw.jsonl"),
        workers=workers,
        force=force,
    )
    if key == "raid":
        fetch_kwargs["forbidden_offsets"] = forbidden
    else:
        fetch_kwargs["forbidden_offsets"] = []
    final_rows, used_offsets, fetched_fresh, final_cache_path, fetch_info = _get_or_fetch_final(
        **fetch_kwargs
    )
    final_rows, final_dupes = _dedupe_exact(final_rows)
    final_counts = Counter(r["label"] for r in final_rows)
    n_human = final_counts.get(0, 0)
    topup_rows: list[dict] = []
    topup_info: dict | None = None
    if n_human < MIN_N_HUMAN:
        print(f"[{key}] final-test n_human={n_human} < {MIN_N_HUMAN} — predeclared top-up fires")
        if key == "raid":
            used = [set(used_offsets), u1_offsets, old_offsets]
            topup_shift = _find_shift(RAID_TRAIN_TOTAL, RAID_TOPUP_N, used)
            topup_offsets = _shifted_offsets(RAID_TRAIN_TOTAL, RAID_TOPUP_N, topup_shift)
            topup_cache = "train-2000-w8-topup.jsonl"
            topup_total, topup_config, topup_split = RAID_TRAIN_TOTAL, "raid", "train"
        else:
            topup_shift = MAGE_TEST_TOTAL // MAGE_FINAL_N // 2
            topup_offsets = [
                (o + topup_shift) % MAGE_TEST_TOTAL
                for o in sample_offsets(MAGE_TEST_TOTAL, MAGE_TOPUP_N)
            ]
            if set(topup_offsets) & set(used_offsets):
                raise ValueError(f"{key}: top-up grid overlaps the first grid — refusing")
            topup_cache = "test-400-w8-topup.jsonl"
            topup_total, topup_config, topup_split = MAGE_TEST_TOTAL, "default", "test"
        topup_rows, _, _, topup_cache_path, _ = _get_or_fetch_final(
            key=key,
            config=topup_config,
            split=topup_split,
            total=topup_total,
            n=final_plan["topup"]["n"],
            shift=topup_shift,
            cache_filename=topup_cache,
            checkpoint_filename=topup_cache.replace(".jsonl", ".raw.jsonl"),
            forbidden_offsets=[set(used_offsets)],
            workers=workers,
            force=force,
        )
        topup_rows, topup_dupes = _dedupe_exact(topup_rows)
        final_rows = final_rows + topup_rows
        final_dupes = final_dupes + topup_dupes
        final_counts = Counter(r["label"] for r in final_rows)
        n_human = final_counts.get(0, 0)
        topup_info = {
            "n_rows": len(topup_rows),
            "shift": topup_shift,
            "cache_file": topup_cache,
            "cache_sha256": _sha256_file(topup_cache_path),
            "offsets_sha256": _sha256_text(json.dumps(topup_offsets)),
            "n_human_after_topup": n_human,
        }
        print(f"[{key}] top-up fetched: n_human now {n_human}")
    print(
        f"[{key}] final-test: {len(final_rows)} rows "
        f"({final_counts.get(0, 0)} human / {final_counts.get(1, 0)} AI / "
        f"{final_counts.get(None, 0)} unlabelled)"
    )

    # 5. Disjointness by content hash (fail-closed) + leakage rules.
    final_fp = fingerprint_dataset(final_cache_path, key, split=final_plan["split"])
    val_fp = fingerprint_dataset(val_cache_path, key, split="train")
    val_check = check_disjointness(final_cache_path, final_fp, val_cache_path, val_fp)
    disjointness = [
        {
            "against": f"validation ({FROZEN[key]['prior_run']})",
            "disjoint": val_check["disjoint"],
            "verified": val_check["verified"],
            "shared_samples": val_check["shared_samples"],
            "errors": val_check["errors"],
        }
    ]
    print(
        f"[{key}] disjointness vs validation: {val_check['disjoint']} "
        f"(verified={val_check['verified']}, shared={val_check['shared_samples']})"
    )
    if not val_check["disjoint"] or not val_check["verified"]:
        raise ValueError(f"{key}: final-test NOT disjoint from validation: {val_check} — refusing")
    disjointness += _disjointness_vs_targets(key, final_cache_path, final_plan["split"])

    exclusions: list[dict] = []
    near_dup_report: dict | None = None
    if key == "raid":
        kept, exclusions, near_dup_report = _raid_leakage_checks(val_rows, final_rows)
        print(
            f"[{key}] leakage check: {len(exclusions)} exclusions, "
            f"max 8-gram Jaccard {near_dup_report['max_word_8gram_jaccard']} "
            f"over {near_dup_report['pairs_checked_same_source_id']} same-source pairs"
        )
        final_rows = kept
        final_counts = Counter(r["label"] for r in final_rows)
    else:
        # MAGE source_id IS the text hash: content-hash disjointness
        # above already proves no shared source across partitions.
        near_dup_report = {
            "note": "MAGE source_id is the first 16 hex of the text SHA-256, so "
            "content-hash disjointness (0 shared samples) is source disjointness; "
            "no separate near-duplicate pass applies.",
            "n_excluded": 0,
        }

    # 6. Measure at the native operating point (validation + final-test),
    #    with a determinism self-check (final-test scored twice).
    detector = BuiltinHeuristicDetector()
    val_measured = measure_rows(detector, val_rows)
    final_measured = measure_rows(detector, final_rows)
    final_measured_again = measure_rows(detector, final_rows)
    deterministic = all(
        a["score"] == b["score"] and a["verdict"] == b["verdict"]
        for a, b in zip(final_measured, final_measured_again, strict=True)
    )
    print(f"[{key}] determinism self-check (final-test scored twice): identical={deterministic}")
    if not deterministic:
        raise ValueError(f"{key}: detector is NOT deterministic on re-run — refusing to report")
    n_det_errors = sum(1 for m in final_measured if m["error"] is not None)
    if n_det_errors:
        raise ValueError(f"{key}: {n_det_errors} detection errors on final-test — refusing")

    # 7. Per-slice metrics (predeclared slice lists).
    val_primary, val_secondary = _build_slices(key, val_measured)
    final_primary, final_secondary = _build_slices(key, final_measured)
    worst = _worst_human_slice(final_primary)
    print(f"[{key}] worst final-test slice: {worst}")

    # 8. Inclusion / drop accounting (every row accounted for).
    inclusion = {
        "validation_rows_in_cache": FROZEN[key]["rows"],
        "validation_rows_after_exact_dedupe": len(val_rows),
        "validation_label_counts": {
            str(k): v for k, v in sorted(val_counts.items(), key=lambda kv: str(kv[0]))
        },
        "final_test_rows_fetched": final_plan["n_target"] + (len(topup_rows) if topup_rows else 0),
        "final_test_rows_after_exact_dedupe": len(final_rows) + len(exclusions),
        "final_test_rows_after_leakage_exclusions": len(final_rows),
        "final_test_label_counts": {
            str(k): v for k, v in sorted(final_counts.items(), key=lambda kv: str(kv[0]))
        },
        "final_test_exact_duplicates_dropped": len(final_dupes),
        "validation_exact_duplicates_dropped": len(val_dupes),
        "leakage_exclusions": len(exclusions),
    }
    drops = [
        {
            "item": "full-corpus evaluation",
            "reason": f"sample only: validation n={FROZEN[key]['rows']} + final-test "
            f"n={len(final_rows)} normalised rows from "
            f"{final_plan['split_rows_total']} split rows",
        },
        {
            "item": f"Python {', '.join(UNMEASURED_VERSIONS)}",
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
    ]
    if key == "raid":
        drops.append(
            {
                "item": "raid_test/test (50 rows)",
                "reason": "unlabelled in the CSV distribution (label None on every row): "
                "coverage/abstention probe and disjointness target only, never scored as a class",
            }
        )
        drops.append(
            {
                "item": "RAID extra split (2,039,100 rows) and non-train domains",
                "reason": "not evaluated in this wave: the served train split holds 4 domains "
                "(abstracts/books/news/poetry); other domains and non-English (Czech/German) "
                "material live in extra/test and are an explicit coverage gap",
            }
        )
        drops.append(
            {
                "item": f"{len(exclusions)} leakage-excluded final-test rows",
                "reason": "human-source overlap / near-duplicate vs validation (see exclusions)",
            }
        )
    else:
        drops.append(
            {
                "item": "per-generator-combo slices (283 distinct src values, n=1 each)",
                "reason": "too thin to report individually; generators are reported grouped "
                "by family (OPT, Flan-T5, GPT-3.5-turbo, davinci, LLaMA, BLOOM, GPT-J, "
                "GPT-NeoX, T0, GLM-130B) and by task (continuation/specified/topical)",
            }
        )
        drops.append(
            {
                "item": "MAGE paraphrase testbeds (test_ood_set_gpt_para.csv)",
                "reason": "separate OOD-paraphrase files in the HF repo; not sampled in this wave",
            }
        )
    drops += val_dupes + final_dupes

    # 9. Freeze the manifest (planned -> frozen, with hashes + counts).
    final_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    final_manifest["status"] = "frozen"
    final_manifest["partitions"]["final_test"].update(
        {
            "cache_file": "/".join((key, final_plan["config"], final_plan["cache_filename"])),
            "cache_sha256": _sha256_file(final_cache_path),
            "n_rows": len(final_rows) + len(exclusions),
            "n_rows_after_exclusions": len(final_rows),
            "n_human": final_counts.get(0, 0),
            "n_ai": final_counts.get(1, 0),
            "n_unlabelled": final_counts.get(None, 0),
            "fetched_fresh": fetched_fresh,
            "topup": topup_info,
        }
    )
    final_manifest["disjointness"] = disjointness
    final_manifest["near_duplicate_check"] = near_dup_report
    final_manifest["exclusions"] = exclusions
    final_manifest["inclusion"] = inclusion
    final_manifest["environment_lock"] = _env_lock()
    frozen_manifest_path = _write_manifest(final_manifest)

    # 10. Validation reproduction check (same frozen rows, W7 code).
    val_pooled = val_primary[0]
    reproduction = {
        "prior_run": FROZEN[key]["prior_run"],
        "prior_auroc": FROZEN[key]["prior_auroc"],
        "remeasured_auroc": val_pooled["auroc"]["value"] if val_pooled["auroc"] else None,
        "prior_tpr_at_fpr_0_01": FROZEN[key]["prior_tpr_at_1pct"],
        "remeasured_tpr_at_fpr_0_01": val_pooled["tpr_at_fpr_0_01"]["value"]
        if val_pooled.get("tpr_at_fpr_0_01")
        else None,
        "prior_tpr_at_fpr_0_05": FROZEN[key]["prior_tpr_at_5pct"],
        "remeasured_tpr_at_fpr_0_05": val_pooled["tpr_at_fpr_0_05"]["value"]
        if val_pooled.get("tpr_at_fpr_0_05")
        else None,
        "note": "Same frozen rows re-measured on the W7 code (17b8951 lineage); "
        "AUROC/TPR@FPR are threshold-free so small differences come only from "
        "code changes between the prior run and this run, not from tuning.",
    }

    results: dict = {
        "dataset": key,
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "licence_reverification": licence_block,
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_family": BuiltinHeuristicDetector.detector_family,
        "deterministic": BuiltinHeuristicDetector.deterministic,
        "operating_point": "builtin-heuristic native verdict (analyze_text via "
        "BuiltinHeuristicDetector.detect); no score threshold; no calibration",
        "manifest": {
            "path": f"docs/evidence/manifests/{frozen_manifest_path.name}",
            "sha256": _sha256_file(frozen_manifest_path),
        },
        "environment_lock": _env_lock(),
        "seeds": {"bootstrap_seed": BOOTSTRAP_SEED},
        "predeclared_gates": {
            "min_n_human": MIN_N_HUMAN,
            "fpr_wilson_upper_max": FPR_UPPER_MAX,
        },
        "inclusion": inclusion,
        "disjointness": disjointness,
        "near_duplicate_check": near_dup_report,
        "exclusions": exclusions,
        "determinism_self_check": {
            "final_test_scored_twice": True,
            "n_rows": len(final_rows),
            "identical_scores_and_verdicts": deterministic,
        },
        "validation_remeasurement": {
            "prior_run": FROZEN[key]["prior_run"],
            "cache_sha256": FROZEN[key]["sha256"],
            "slices_primary": val_primary,
            "slices_secondary": val_secondary,
            "reproduction_check": reproduction,
        },
        "final_test": {
            "cache_sha256": _sha256_file(final_cache_path),
            "slices_primary": final_primary,
            "slices_secondary": final_secondary,
            "worst_slice": worst,
        },
    }
    record = _base_record(run_id, "command", command)
    record["results"] = results
    record["drops"] = drops
    record["badge"] = "available"
    record["detector_version"] = BuiltinHeuristicDetector.detector_version
    path = _write_record(record, force)
    print(f"[{key}] wrote {path.name} (sha256 {_sha256_file(path)[:12]}...)")
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing run artifacts and re-fetch final-test samples",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="parallel fetch workers (default 4; each fetches distinct offsets)",
    )
    args = parser.parse_args(argv)
    command = f"python scripts/qualify_w8_raid_mage.py{' --force' if args.force else ''}"
    if args.workers != DEFAULT_WORKERS:
        command += f" --workers {args.workers}"
    for key in ("raid", "mage"):
        results = qualify_corpus(key, force=args.force, workers=args.workers, command=command)
        pooled = results["final_test"]["slices_primary"][0]
        print(
            f"[{key}] done: final-test n={pooled['n_rows']} "
            f"human={pooled['n_human']} ai={pooled['n_ai']} "
            f"fpr={pooled['fpr_native']['value']} "
            f"wilson_upper={pooled['fpr_native']['ci_upper']} "
            f"tpr_native={pooled['tpr_native']['value']} "
            f"auroc={pooled['auroc']['value'] if pooled['auroc'] else None} "
            f"worst={results['final_test']['worst_slice']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
