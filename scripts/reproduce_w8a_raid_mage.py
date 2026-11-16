#!/usr/bin/env python3
"""reproduce_w8a_raid_mage.py — W8 worker E (independent reproduction).

Independently reproduces Worker A's RAID + MAGE qualification
(doc/evidence/runs/EV-20261116-dataset-raid.json and
EV-20261116-dataset-mage.json, script scripts/qualify_w8_raid_mage.py)
from scratch, on the W8 code base (audit-w7 @ 17b8951):

- Reads the frozen validation caches and the final-test caches
  DIRECTLY as JSONL, verifying every SHA-256 against the FROZEN table
  and the frozen manifests before use.
- Re-derives the final-test offset grids (repo sample_offsets plus the
  smallest-disjoint-shift search) and compares the offsets SHA-256 and
  first/last 5 offsets with the frozen manifest.
- Re-derives content-hash disjointness (repo fingerprint/check
  functions AND an independent direct content-hash set intersection)
  against validation and every extra target.
- Re-derives the RAID leakage exclusions (same-human-source rule and
  the word-8-gram Jaccard > 0.8 rule) and the near-duplicate report.
- Re-scores validation + final-test rows with a FRESH detector at the
  native operating point, twice for the determinism check.
- Recomputes every slice (primary + secondary) with Worker A's exact
  slice definitions and metric replication: Wilson 95% FPR/TPR (my own
  formula implementation, cross-checked against the repo wilson_ci),
  bootstrap 95% CIs for AUROC/AUPRC/TPR@FPR (the same seeded
  random.Random stream, same percentile convention), cluster-bootstrap
  FPR where k_fp > 0, score summaries, gate flags, worst slice
  (max Wilson upper, first wins on ties).
- AUROC point values are cross-checked with my own pairwise
  Mann-Whitney implementation. AUPRC: Worker A's statistic is the
  PER-ROW average precision (each row contributes at its own rank,
  ties broken by label descending inside sorted()); my independent
  AUPRC groups tied scores before accumulating (the standard stepwise
  form). Both are computed and reported; the comparison against
  Worker A's artifact uses Worker A's form, and the stepwise form is
  reported alongside as a cross-check, NOT as a discrepancy — the two
  estimators differ whenever tied scores straddle the ranking.
- Compares EVERY field of both artifacts recursively (validation
  remeasurement + reproduction check, final-test slices + worst
  slice, inclusion, disjointness, near-duplicate check, exclusions,
  determinism self-check, manifest SHA, seeds/gates, drops). ANY
  discrepancy is a finding.

Usage:
    python scripts/reproduce_w8a_raid_mage.py [--check] [--only raid|mage]
    python scripts/reproduce_w8a_raid_mage.py --output <path>

--check measures and compares only; it writes nothing.
The default output is docs/evidence/runs/EV-20261116-reproduction-raid-mage.json.
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
WORKER_A_ROOT = Path.home() / "workspace" / "TextForensics-rewrite"
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from textforensics.benchmark import check_disjointness, fingerprint_dataset  # noqa: E402
from textforensics.datasets import (  # noqa: E402
    canonical_text_sha256,
    default_cache_dir,
    sample_offsets,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.probe_metrics import wilson_ci as repo_wilson_ci  # noqa: E402
from measure_datasets import auroc as repo_auroc, tpr_at_fpr  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-reproduction-raid-mage"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
BOOTSTRAP_SEED = 20261116
BOOTSTRAP_RESAMPLES = 1000
MIN_N_HUMAN = 100
FPR_UPPER_MAX = 0.05
Z_95 = 1.96
NATIVE_OPERATING_POINT = (
    "builtin-heuristic native verdict (analyze_text via BuiltinHeuristicDetector.detect); "
    "no score threshold; no calibration"
)
# Worker A's SLICE-level operating point omits "; no calibration" (that
# suffix appears only on the artifact-level operating_point). Using the
# long string inside slice_metrics manufactures 116 spurious
# operating_point discrepancies; every number still agrees.
SLICE_OPERATING_POINT = (
    "builtin-heuristic native verdict (analyze_text via BuiltinHeuristicDetector.detect); "
    "no score threshold"
)
CACHE_ROOT = default_cache_dir()

# Frozen prior samples (validation partitions) — copied from Worker A's
# script (commit 756ea41, which corrected the MAGE prior TPR@FPR).
# Every value is verified against the cache files and the artifacts
# before use; a mismatch fails loudly instead of measuring other data.
FROZEN = {
    "raid": {
        "cache_rel": ("raid", "raid", "train-6000.jsonl"),
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
        "sha256": "8969989f35f6affbfc07d1b6846e9acdb481790b964563289342aa075d06eba3",
        "rows": 400,
        "n_human": 117,
        "n_ai": 283,
        "prior_run": "EV-20261106-dataset-mage",
        "prior_auroc": 0.5567,
        "prior_tpr_at_1pct": 0.106,
        "prior_tpr_at_5pct": 0.1661,
    },
}
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
RAID_TRAIN_TOTAL = 2_270_000
RAID_FINAL_N = 4000
RAID_U1_N = 3000
RAID_OLD_N = 6000
RAID_OLD_SHIFT = 189
MAGE_TEST_TOTAL = 60_743
MAGE_FINAL_N = 600


def _load_module(name: str, path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _code_version() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def _round6(value: float | None) -> float | None:
    return None if value is None else round(float(value), 6)


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


def auprc_stepwise(labels: list[int], scores: list[float]) -> float:
    """Stepwise average precision: tied scores are grouped before
    accumulating, so a tie group contributes once with its aggregate
    precision (the standard form; differs from Worker A's per-row form
    whenever ties straddle the ranking)."""
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


def auprc_per_row(labels: list[int], scores: list[float]) -> float:
    """Worker A's AUPRC statistic: per-row average precision, sorted by
    (score, label) descending — ties are broken by label, positives
    first within a tie group. Replicated exactly for the comparison."""
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


def _self_test() -> list[str]:
    problems: list[str] = []
    if abs(auroc_pairwise([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) - 1.0) > 1e-12:
        problems.append("auroc_pairwise perfect != 1.0")
    if abs(repo_auroc([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) - 1.0) > 1e-12:
        problems.append("repo auroc perfect != 1.0")
    if abs(auprc_stepwise([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.1]) - (1.0 + 2.0 / 3.0) / 2.0) > 1e-12:
        problems.append("auprc_stepwise known case != 0.8333")
    if abs(auprc_per_row([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.1]) - (1.0 + 2.0 / 3.0) / 2.0) > 1e-12:
        problems.append("auprc_per_row known case != 0.8333")
    lo, hi = wilson(0, 200)
    if abs(hi - 0.018846) > 1e-6:
        problems.append(f"wilson(0,200) upper {hi} != 0.018846")
    lo2, hi2 = repo_wilson_ci(0, 200, z=1.96)
    if abs(hi2 - hi) > 1e-12 or abs(lo2 - lo) > 1e-12:
        problems.append("repo wilson_ci disagrees with the formula implementation")
    return problems


# --- Worker A metric replication (same stream, same conventions) ---


def _bootstrap_ci(pairs: list[tuple[int, float]], fn, *, seed: int = BOOTSTRAP_SEED,
                  resamples: int = BOOTSTRAP_RESAMPLES) -> dict | None:
    """Percentile bootstrap 95% CI, replicating Worker A's stream
    exactly: a fresh random.Random(seed) per call, rng.randrange(n)
    draws, percentile [int(0.025*m)-1] / [int(0.975*m)]."""
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
    lo, hi = wilson(k, n)
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


def _cluster_bootstrap_fpr(human_clusters: list[tuple[str, int]], *,
                           seed: int = BOOTSTRAP_SEED,
                           resamples: int = BOOTSTRAP_RESAMPLES) -> dict | None:
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
    return {" ".join(words[i:i + n]) for i in range(max(0, len(words) - n + 1))}


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


def slice_metrics(slice_id: str, measured: list[dict], *, cluster_key, bootstrap: bool = True) -> dict:
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
        "operating_point": SLICE_OPERATING_POINT,
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
        result["auroc"] = _bootstrap_ci(pairs, repo_auroc)
        result["auprc"] = _bootstrap_ci(pairs, auprc_per_row)
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


def _build_slices(key: str, measured: list[dict]) -> tuple[list[dict], list[dict]]:
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


def _worst_human_slice(slices: list[dict]) -> dict | None:
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


def _load_cache_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _dedupe_exact(rows: list[dict]) -> tuple[list[dict], list[dict]]:
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


def _find_shift(total: int, n: int, forbidden: list[set[int]]) -> int:
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


def _raid_leakage_checks(
    validation_rows: list[dict], final_rows: list[dict]
) -> tuple[list[dict], list[dict], dict]:
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


def _content_hashes(rows: list[dict]) -> set[str]:
    return {canonical_text_sha256(r["text"]) for r in rows}


def validate_run_artifact(artifact: dict) -> list[str]:
    check_claims = _load_module(
        "check_claims_for_validation", REPO_ROOT / "scripts" / "check_claims.py"
    )
    schema = check_claims._load_schema(REPO_ROOT, "run-artifact.schema.json")
    return check_claims._schema_errors(schema, artifact)


def _auroc_cross_checks(pairs: list[tuple[int, float]]) -> dict:
    """Independent AUROC/AUPRC point values for one slice's pairs."""
    labels = [lab for lab, _ in pairs]
    scores = [s for _, s in pairs]
    if sum(labels) == 0 or sum(labels) == len(labels):
        return {"auroc_pairwise": None, "auroc_rank_repo": None,
                "auprc_stepwise": None, "auprc_per_row": None}
    return {
        "auroc_pairwise": _round6(auroc_pairwise(labels, scores)),
        "auroc_rank_repo": _round6(repo_auroc(labels, scores)),
        "auprc_stepwise": _round6(auprc_stepwise(labels, scores)),
        "auprc_per_row": _round6(auprc_per_row(labels, scores)),
    }


def reproduce_corpus(key: str, detector, comparison: list[dict], discrepancies: list[dict],
                     checks: list[dict], cross_checks: dict) -> dict:
    prefix = f"{key}."
    a_results_path = WORKER_A_ROOT / "docs" / "evidence" / "runs" / f"EV-20261116-dataset-{key}.json"
    a_manifest_path = WORKER_A_ROOT / "docs" / "evidence" / "manifests" / f"EV-20261116-{key}-manifest.json"
    if not a_results_path.exists():
        raise ValueError(f"{key}: Worker A artifact missing: {a_results_path}")
    if not a_manifest_path.exists():
        raise ValueError(f"{key}: Worker A manifest missing: {a_manifest_path}")
    a_artifact = json.loads(a_results_path.read_text(encoding="utf-8"))
    a_results = a_artifact["results"]
    a_manifest = json.loads(a_manifest_path.read_text(encoding="utf-8"))
    a_sha = _sha256_file(a_results_path)

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": prefix + name, "passed": bool(ok), "detail": str(detail)})
        print(f"[{'PASS' if ok else 'FAIL'}] {prefix}{name} {detail}", flush=True)

    def compare(path: str, mine, theirs) -> None:
        same = mine == theirs
        comparison.append({"field": prefix + path, "reproduction": mine, "worker_a": theirs,
                           "agree": same})
        if not same:
            discrepancies.append({"field": prefix + path, "reproduction": mine, "worker_a": theirs})

    def deep_compare(path: str, mine, theirs) -> None:
        """Recursive field-by-field comparison; lists compare by index."""
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
    info = FROZEN[key]
    val_cache_path = CACHE_ROOT.joinpath(*info["cache_rel"])
    check("validation cache sha256 matches FROZEN",
          _sha256_file(val_cache_path) == info["sha256"],
          f"{_sha256_file(val_cache_path)[:12]} vs {info['sha256'][:12]}")
    val_rows_raw = _load_cache_jsonl(val_cache_path)
    check("validation cache row count", len(val_rows_raw) == info["rows"],
          f"{len(val_rows_raw)} vs {info['rows']}")
    val_counts_raw = Counter(r["label"] for r in val_rows_raw)
    check("validation cache label counts",
          val_counts_raw.get(0, 0) == info["n_human"] and val_counts_raw.get(1, 0) == info["n_ai"],
          dict(val_counts_raw))
    val_rows, val_dupes = _dedupe_exact(val_rows_raw)
    val_counts = Counter(r["label"] for r in val_rows)

    # --- 2. Frozen manifest: status, offsets, final-test cache ---
    check("manifest status is frozen", a_manifest["status"] == "frozen", a_manifest["status"])
    ft = a_manifest["partitions"]["final_test"]
    if key == "raid":
        u1_offsets = set(sample_offsets(RAID_TRAIN_TOTAL, RAID_U1_N))
        old_offsets = {
            (o + RAID_OLD_SHIFT) % RAID_TRAIN_TOTAL
            for o in sample_offsets(RAID_TRAIN_TOTAL, RAID_OLD_N)
        }
        shift = _find_shift(RAID_TRAIN_TOTAL, RAID_FINAL_N, [u1_offsets, old_offsets])
        final_offsets = _shifted_offsets(RAID_TRAIN_TOTAL, RAID_FINAL_N, shift)
        total, n_target = RAID_TRAIN_TOTAL, RAID_FINAL_N
    else:
        shift = 0
        final_offsets = sample_offsets(MAGE_TEST_TOTAL, MAGE_FINAL_N)
        total, n_target = MAGE_TEST_TOTAL, MAGE_FINAL_N
    check("final-test phase shift re-derives", shift == ft["phase_shift"],
          f"recomputed {shift} vs manifest {ft['phase_shift']}")
    check("final-test offsets sha256 re-derives",
          _sha256_text(json.dumps(final_offsets)) == ft["offsets_sha256"],
          f"{_sha256_text(json.dumps(final_offsets))[:12]} vs {ft['offsets_sha256'][:12]}")
    check("final-test offsets first/last 5",
          final_offsets[:5] == ft["offsets_first_5"] and final_offsets[-5:] == ft["offsets_last_5"],
          f"{final_offsets[:5]} / {final_offsets[-5:]}")
    final_cache_path = CACHE_ROOT / key / ft["config"] / ft["cache_filename"]
    check("final-test cache sha256 matches manifest",
          _sha256_file(final_cache_path) == ft["cache_sha256"],
          f"{_sha256_file(final_cache_path)[:12]} vs {ft['cache_sha256'][:12]}")
    check("final-test cache sha256 matches artifact",
          _sha256_file(final_cache_path) == a_results["final_test"]["cache_sha256"],
          _sha256_file(final_cache_path)[:12])
    check("manifest top-up is null (n_human >= 100, no top-up fired)",
          ft.get("topup") is None, str(ft.get("topup")))
    final_rows_raw = _load_cache_jsonl(final_cache_path)
    check("final-test fetched rows == n_target", len(final_rows_raw) == n_target,
          f"{len(final_rows_raw)} vs {n_target}")
    final_rows, final_dupes = _dedupe_exact(final_rows_raw)
    final_counts_pre = Counter(r["label"] for r in final_rows)

    # --- 3. Disjointness: repo functions + independent content-hash sets ---
    final_fp = fingerprint_dataset(final_cache_path, key, split=ft["split"])
    val_fp = fingerprint_dataset(val_cache_path, key, split="train")
    val_check = check_disjointness(final_cache_path, final_fp, val_cache_path, val_fp)
    check("final-test disjoint from validation (repo check)",
          val_check["disjoint"] and val_check["verified"],
          f"disjoint={val_check['disjoint']} verified={val_check['verified']} "
          f"shared={val_check['shared_samples']}")
    shared_mine = _content_hashes(final_rows) & _content_hashes(val_rows)
    check("final-test disjoint from validation (independent content-hash sets)",
          len(shared_mine) == 0, f"{len(shared_mine)} shared hashes")
    disjointness = [
        {
            "against": f"validation ({info['prior_run']})",
            "disjoint": val_check["disjoint"],
            "verified": val_check["verified"],
            "shared_samples": val_check["shared_samples"],
            "errors": val_check["errors"],
        }
    ]
    for target in EXTRA_TARGETS[key]:
        other = CACHE_ROOT.joinpath(*target["cache_rel"])
        check(f"disjointness target sha {target['label']}",
              _sha256_file(other) == target["sha256"], _sha256_file(other)[:12])
        fp2 = fingerprint_dataset(other, key, split=target["split"])
        t_check = check_disjointness(final_cache_path, final_fp, other, fp2)
        check(f"disjoint vs {target['label']}",
              t_check["disjoint"] and t_check["verified"],
              f"shared={t_check['shared_samples']}")
        other_rows = _load_cache_jsonl(other)
        shared_t = _content_hashes(final_rows) & _content_hashes(other_rows)
        check(f"disjoint vs {target['label']} (independent content-hash sets)",
              len(shared_t) == 0, f"{len(shared_t)} shared hashes")
        disjointness.append(
            {
                "against": target["label"],
                "disjoint": t_check["disjoint"],
                "verified": t_check["verified"],
                "shared_samples": t_check["shared_samples"],
                "errors": t_check["errors"],
            }
        )
    deep_compare("disjointness", disjointness, a_results["disjointness"])
    deep_compare("manifest.disjointness", disjointness, a_manifest.get("disjointness"))

    # --- 4. Leakage exclusions (RAID) / near-duplicate report ---
    if key == "raid":
        kept, exclusions, near_dup_report = _raid_leakage_checks(val_rows, final_rows)
        final_rows = kept
        final_counts = Counter(r["label"] for r in final_rows)
    else:
        exclusions = []
        final_counts = Counter(r["label"] for r in final_rows)
        near_dup_report = {
            "note": "MAGE source_id is the first 16 hex of the text SHA-256, so "
            "content-hash disjointness (0 shared samples) is source disjointness; "
            "no separate near-duplicate pass applies.",
            "n_excluded": 0,
        }
    deep_compare("exclusions", exclusions, a_results["exclusions"])
    deep_compare("near_duplicate_check", near_dup_report, a_results["near_duplicate_check"])
    deep_compare("manifest.near_duplicate_check", near_dup_report,
                 a_manifest.get("near_duplicate_check"))
    deep_compare("manifest.exclusions", exclusions, a_manifest.get("exclusions"))

    # --- 5. Fresh scoring (validation + final-test), determinism double-score ---
    print(f"[{key}] scoring validation ({len(val_rows)} rows) + final-test ({len(final_rows)} rows) ...",
          flush=True)
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
    deep_compare("determinism_self_check",
                 {"final_test_scored_twice": True, "n_rows": len(final_rows),
                  "identical_scores_and_verdicts": deterministic},
                 a_results["determinism_self_check"])

    # --- 6. Slices (primary + secondary) + worst slice ---
    val_primary, val_secondary = _build_slices(key, val_measured)
    final_primary, final_secondary = _build_slices(key, final_measured)
    worst = _worst_human_slice(final_primary)
    # Independent AUROC/AUPRC cross-checks on the pooled final-test slice
    # (and on the pooled validation slice): pairwise AUROC vs repo rank
    # AUROC, stepwise AUPRC vs Worker A's per-row AUPRC.
    for tag, measured in (("final_test.pooled", final_measured), ("validation.pooled", val_measured)):
        labelled = [m for m in measured if m["label"] is not None and m["error"] is None]
        pairs = [(m["label"], m["score"]) for m in labelled]
        cc = _auroc_cross_checks(pairs)
        cross_checks[f"{key}.{tag}"] = cc
        check(f"{tag} AUROC pairwise == repo rank form",
              cc["auroc_pairwise"] == cc["auroc_rank_repo"],
              f"{cc['auroc_pairwise']} vs {cc['auroc_rank_repo']}")
    deep_compare("validation_remeasurement.slices_primary", val_primary,
                 a_results["validation_remeasurement"]["slices_primary"])
    deep_compare("validation_remeasurement.slices_secondary", val_secondary,
                 a_results["validation_remeasurement"]["slices_secondary"])
    deep_compare("final_test.slices_primary", final_primary,
                 a_results["final_test"]["slices_primary"])
    deep_compare("final_test.slices_secondary", final_secondary,
                 a_results["final_test"]["slices_secondary"])
    deep_compare("final_test.worst_slice", worst, a_results["final_test"]["worst_slice"])

    # --- 7. Inclusion, reproduction check, manifest, seeds/gates, drops ---
    inclusion = {
        "validation_rows_in_cache": info["rows"],
        "validation_rows_after_exact_dedupe": len(val_rows),
        "validation_label_counts": {
            str(k): v for k, v in sorted(val_counts.items(), key=lambda kv: str(kv[0]))
        },
        "final_test_rows_fetched": n_target,
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
        "prior_run": info["prior_run"],
        "prior_auroc": info["prior_auroc"],
        "remeasured_auroc": val_pooled["auroc"]["value"] if val_pooled["auroc"] else None,
        "prior_tpr_at_fpr_0_01": info["prior_tpr_at_1pct"],
        "remeasured_tpr_at_fpr_0_01": val_pooled["tpr_at_fpr_0_01"]["value"]
        if val_pooled.get("tpr_at_fpr_0_01")
        else None,
        "prior_tpr_at_fpr_0_05": info["prior_tpr_at_5pct"],
        "remeasured_tpr_at_fpr_0_05": val_pooled["tpr_at_fpr_0_05"]["value"]
        if val_pooled.get("tpr_at_fpr_0_05")
        else None,
        "note": "Same frozen rows re-measured on the W7 code (17b8951 lineage); "
        "AUROC/TPR@FPR are threshold-free so small differences come only from "
        "code changes between the prior run and this run, not from tuning.",
    }
    deep_compare("validation_remeasurement.reproduction_check", reproduction,
                 a_results["validation_remeasurement"]["reproduction_check"])
    compare("validation_remeasurement.prior_run", info["prior_run"],
            a_results["validation_remeasurement"]["prior_run"])
    compare("validation_remeasurement.cache_sha256", info["sha256"],
            a_results["validation_remeasurement"]["cache_sha256"])
    compare("manifest.sha256", _sha256_file(a_manifest_path),
            a_results["manifest"]["sha256"])
    compare("manifest.path", f"docs/evidence/manifests/{a_manifest_path.name}",
            a_results["manifest"]["path"])
    deep_compare("seeds", {"bootstrap_seed": BOOTSTRAP_SEED}, a_results["seeds"])
    deep_compare("predeclared_gates",
                 {"min_n_human": MIN_N_HUMAN, "fpr_wilson_upper_max": FPR_UPPER_MAX},
                 a_results["predeclared_gates"])
    # Drops live on the artifact RECORD (not in results): reconstruct
    # Worker A's exact drops list (four fixed items, corpus-specific
    # items, then the val + final exact-duplicate drops) and compare.
    split_total = RAID_TRAIN_TOTAL if key == "raid" else MAGE_TEST_TOTAL
    drops = [
        {
            "item": "full-corpus evaluation",
            "reason": f"sample only: validation n={info['rows']} + final-test "
            f"n={len(final_rows)} normalised rows from {split_total} split rows",
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
    deep_compare("drops", drops, a_artifact.get("drops"))
    return {
        "corpus": key,
        "artifact_sha256": a_sha,
        "artifact_code_version": a_artifact.get("code_version"),
        "manifest_sha256": _sha256_file(a_manifest_path),
        "validation": {
            "cache_sha256": info["sha256"],
            "rows_in_cache": len(val_rows_raw),
            "rows_after_dedupe": len(val_rows),
            "label_counts": {str(k): v for k, v in sorted(val_counts.items(), key=lambda kv: str(kv[0]))},
            "exact_duplicates_dropped": len(val_dupes),
            "pooled": val_primary[0],
        },
        "final_test": {
            "cache_sha256": _sha256_file(final_cache_path),
            "rows_fetched": n_target,
            "rows_after_dedupe": len(final_rows) + len(exclusions),
            "rows_after_exclusions": len(final_rows),
            "label_counts": {str(k): v for k, v in sorted(final_counts.items(), key=lambda kv: str(kv[0]))},
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
        "drops": a_artifact.get("drops"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="measure and compare only; write nothing")
    parser.add_argument("--only", choices=["raid", "mage"], default=None)
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    problems = _self_test()
    if problems:
        print("METRIC SELF-TEST FAILURE:", file=sys.stderr)
        for item in problems:
            print(f"  - {item}", file=sys.stderr)
        return 2

    keys = [args.only] if args.only else ["raid", "mage"]
    detector = BuiltinHeuristicDetector()
    comparison: list[dict] = []
    discrepancies: list[dict] = []
    checks: list[dict] = []
    cross_checks: dict = {}
    corpora: dict[str, dict] = {}
    for key in keys:
        print(f"=== reproducing {key} ===", flush=True)
        corpora[key] = reproduce_corpus(key, detector, comparison, discrepancies, checks, cross_checks)

    n_agree = sum(1 for c in comparison if c["agree"])
    n_checks_pass = sum(1 for c in checks if c["passed"])
    print(f"comparison: {n_agree}/{len(comparison)} fields agree; {len(discrepancies)} discrepancies",
          flush=True)
    for d in discrepancies:
        print(f"  DISCREPANCY {d['field']}: reproduction={d['reproduction']} worker_a={d['worker_a']}",
              flush=True)
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
            capture_output=True, text=True, check=True, timeout=60,
        )
        env_lock["extras"] = freeze.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        env_lock["extras"] = f"pip freeze unavailable: {exc}"

    artifact = {
        "schema": RUN_ARTIFACT_SCHEMA,
        "evidence_record_id": ARTIFACT_ID,
        "kind": "command",
        "command": "python scripts/reproduce_w8a_raid_mage.py",
        "environment": env_lock,
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "detector": detector.detector_id,
            "detector_family": detector.detector_family,
            "detector_version": detector.detector_version,
            "operating_point": NATIVE_OPERATING_POINT,
            "method": (
                "Independent reproduction of Worker A's RAID + MAGE qualification: "
                "frozen validation caches and final-test caches read directly as "
                "JSONL with SHA-256 verification; offset grids re-derived "
                "(smallest disjoint shift); content-hash disjointness checked "
                "twice (repo fingerprint/check functions and an independent "
                "direct content-hash set intersection); RAID leakage exclusions "
                "re-derived (same-human-source rule and word-8-gram Jaccard > "
                "0.8); detector re-run fresh at its native operating point, "
                "twice for determinism; every slice recomputed with Worker A's "
                "exact slice definitions, Wilson FPR/TPR from my own formula "
                "implementation, bootstrap CIs from the same seeded stream, "
                "cluster-bootstrap FPR where k_fp > 0. AUROC point values are "
                "cross-checked with a pairwise Mann-Whitney implementation; "
                "AUPRC is compared in Worker A's per-row form and "
                "cross-checked in the stepwise (tie-grouped) form, reported "
                "alongside, not as a discrepancy."
            ),
            "corpora": corpora,
            "identity_checks": checks,
            "auroc_auprc_cross_checks": cross_checks,
            "comparison": comparison,
            "discrepancies": discrepancies,
            "verdict": verdict,
        },
        "drops": [
            {"item": "Worker A fit/dev/selection partitions",
             "reason": "empty by design — nothing is fitted, calibrated or selected"},
            {"item": "Unlabelled rows",
             "reason": "no binary label; excluded from binary FPR/TPR/AUROC/AUPRC, as in Worker A's artifacts"},
        ],
        "badge": "available",
        "detector_version": detector.detector_version,
        "notes": (
            "W8 worker E reproduction of Worker A's RAID + MAGE qualification. "
            "Every compared field either agrees exactly or is listed in "
            "'discrepancies'. "
            f"Reproduction verdict: {verdict}. "
            + " ".join(
                f"{key.upper()} final-test pooled as re-measured here: human FPR "
                f"{c['final_test']['pooled']['fpr_native']['k']}/{c['final_test']['pooled']['fpr_native']['n']} "
                f"(Wilson 95% upper {c['final_test']['pooled']['fpr_native']['ci_upper']}), "
                f"native TPR {c['final_test']['pooled']['tpr_native']['k']}/{c['final_test']['pooled']['tpr_native']['n']}, "
                f"AUROC {c['final_test']['pooled']['auroc']['value'] if c['final_test']['pooled']['auroc'] else None} "
                f"(bootstrap 95% CI "
                f"{c['final_test']['pooled']['auroc']['ci_lower'] if c['final_test']['pooled']['auroc'] else None}-"
                f"{c['final_test']['pooled']['auroc']['ci_upper'] if c['final_test']['pooled']['auroc'] else None})."
                for key, c in corpora.items()
            )
            + " Below-chance or near-chance ranking results are reported as "
            "measured, not tuned around. The native operating point is unchanged."
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
