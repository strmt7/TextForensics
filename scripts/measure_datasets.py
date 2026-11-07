#!/usr/bin/env python3
"""measure_datasets.py — Fetch wave-1 + wave-2 dataset samples and measure the built-in detector.

For each dataset in the wave-1 plan (plus GhostWriter in wave 2): fetch a documented strided sample
(``n`` evenly spaced rows across the split — every wave-1 split is
ordered by testbed/model, so first-*n* sampling would be one-sided;
RAID first-200 was all-human), map it to normalised rows, write the
JSONL cache + manifest under the local datasets cache dir, fingerprint
the cache and check disjointness against a second split with the
fail-closed ``check_disjointness``, run ``BuiltinHeuristicDetector``
over the labelled rows, and write one U7 run artifact (kind
``command``) per dataset to ``docs/evidence/runs/``, then rebuild the
registry.

No dataset text is written to the repo: caches live outside it (XDG
cache dir, ``TEXTFORENSICS_DATASETS_DIR`` override) and artifacts carry
counts, hashes and metrics only. Sample sizes are grown slices, not
full-corpus evaluations; the drops manifest of each artifact says so.
RAID n=3000 strided — its human rows are only ~3.3% of train, so 600
rows yielded just 20 humans and 3000 rows yield ~100, the minimum
human sample for a supported slice; MAGE n=400 (~118 humans, up from
200); OpAI-Bench n=500 (~115 binary-labelled endpoint rows, up from
100); Beemo unchanged at n=100 records (200 humans already). The
wave-1 preliminary sizes (RAID 600, MAGE 200, OpAI-Bench 100) are
superseded by these larger samples.

Usage:
    python scripts/measure_datasets.py [--only raid,mage] [--force]
    python scripts/measure_datasets.py --list   # print the plan, no network
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from seed_evidence import _base_record, _write_record, rebuild_registry  # noqa: E402

from textforensics.benchmark import check_disjointness, fingerprint_dataset  # noqa: E402
from textforensics.datasets import (  # noqa: E402
    DatasetsServerClient,
    fetch_sample,
    fetch_strided_sample,
    get_spec,
    map_row,
    write_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

# Sample sizes (U1 growth, 2026-11-06): RAID 3000 strided so the ~3.3%
# human fraction yields ~100 humans (the minimum human sample for a
# supported slice); MAGE 400 (~118 humans); OpAI-Bench 500 (~115
# binary-labelled v0/v8 endpoint rows); Beemo unchanged at 100 records
# (200 humans already). Wave-1 sizes (600/200/100) were preliminary.
# Verified row counts (datasets-server /size, 2026-11-06). These are the
# denominators for strided sampling; if the server reports a different
# total the script refuses rather than sampling a stale plan.
# GhostWriter counts verified 2026-11-07 (train 332,224; validation
# 47,548; total 474,904).
SAMPLE_PLAN = {
    "raid": {
        "config": "raid",
        "split": "train",
        "n": 3000,
        "method": "strided",
        "total": 2_270_000,
        "disjoint": {
            "config": "raid_test",
            "split": "test",
            "n": 50,
            "method": "first",
            "total": 672_000,
        },
    },
    "mage": {
        "config": "default",
        "split": "train",
        "n": 400,
        "method": "strided",
        "total": 319_071,
        "disjoint": {
            "config": "default",
            "split": "validation",
            "n": 50,
            "method": "strided",
            "total": 56_792,
        },
    },
    "beemo": {
        "config": "default",
        "split": "train",
        "n": 100,
        "method": "strided",
        "total": 2_187,
        "disjoint": None,  # single-split dataset; nothing to check against
    },
    "opai_bench": {
        "config": "default",
        "split": "train",
        "n": 500,
        "method": "strided",
        "total": 196_029,
        "disjoint": {
            "config": "default",
            "split": "dev",
            "n": 50,
            "method": "strided",
            "total": 42_363,
        },
    },
    # Wave 2 (2026-11-07): GhostWriter n=500 strided across train
    # (332,224 rows); disjointness vs validation (47,548 rows, n=50
    # strided). Verified row counts (datasets-server /size, 2026-11-07).
    "ghostwriter": {
        "config": "default",
        "split": "train",
        "n": 500,
        "method": "strided",
        "total": 332_224,
        "disjoint": {
            "config": "default",
            "split": "validation",
            "n": 50,
            "method": "strided",
            "total": 47_548,
        },
    },
}

# MixSet is deliberately absent: licence unresolved, loader gate closed.
UNMEASURED_VERSIONS = ["3.11", "3.13", "3.14", "3.15"]


def auroc(labels: list[int], scores: list[float]) -> float:
    """AUROC via Mann-Whitney U with tie credit (0.5). No third-party deps.

    ``labels`` are 1 (machine) / 0 (human); higher scores mean more
    machine-like. Raises ValueError unless both classes are present.
    """
    pos = [s for lab, s in zip(labels, scores, strict=True) if lab == 1]
    neg = [s for lab, s in zip(labels, scores, strict=True) if lab == 0]
    if not pos or not neg:
        raise ValueError("auroc needs both classes present")
    wins = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def tpr_at_fpr(labels: list[int], scores: list[float], target_fpr: float) -> float:
    """Max TPR among ROC operating points with FPR <= ``target_fpr``.

    ROC points are the distinct-score thresholds (score >= threshold
    predicts machine). If no non-trivial threshold keeps FPR within the
    target, the result is 0.0 — the detector cannot operate there.
    """
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
        fpr = fp / n_neg
        tpr = tp / n_pos
        if fpr <= target_fpr and tpr > best:
            best = tpr
    return best


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


def _fetch(plan: dict, spec, client: DatasetsServerClient) -> list[dict]:
    if plan["method"] == "first":
        return fetch_sample(spec, plan["config"], plan["split"], plan["n"], client=client)
    return fetch_strided_sample(
        spec, plan["config"], plan["split"], plan["n"], plan["total"], client=client
    )


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


def measure_dataset(key: str, force: bool) -> dict:
    spec = get_spec(key)
    plan = SAMPLE_PLAN[key]
    client = DatasetsServerClient()
    _check_server_total(spec, plan["config"], plan["split"], plan["total"], client)
    print(
        f"[{key}] fetching {plan['n']} rows ({plan['method']}) from {plan['config']}/{plan['split']} ..."
    )
    raw = _fetch(plan, spec, client)
    normalized = []
    for row in raw:
        normalized.extend(map_row(key, row, plan["config"], plan["split"]))
    cache_path, manifest_path = write_sample_cache(spec, plan["config"], plan["split"], normalized)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    print(f"[{key}] mapped to {len(normalized)} normalised rows -> {cache_path}")
    counts = Counter(r.label for r in normalized)

    results: dict = {
        "dataset": key,
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "preliminary": True,
        "config": plan["config"],
        "split": plan["split"],
        "sampling": plan["method"],
        "split_rows_total": plan["total"],
        "rows_fetched": len(raw),
        "rows_normalised": len(normalized),
        "label_counts": {str(k): counts[k] for k in (0, 1, None) if k in counts},
        "cache_file_sha256": manifest["file_sha256"],
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
    }

    # Disjointness against a second split (fail-closed; a shared text is
    # a real finding, reported as-is, never hidden).
    disjoint_plan = plan["disjoint"]
    if disjoint_plan is None:
        results["disjointness"] = {"checked": False, "reason": "single-split dataset"}
    else:
        _check_server_total(
            spec,
            disjoint_plan["config"],
            disjoint_plan["split"],
            disjoint_plan["total"],
            client,
        )
        raw2 = _fetch(disjoint_plan, spec, client)
        normalized2 = []
        for row in raw2:
            normalized2.extend(map_row(key, row, disjoint_plan["config"], disjoint_plan["split"]))
        cache2, _ = write_sample_cache(
            spec, disjoint_plan["config"], disjoint_plan["split"], normalized2
        )
        fp1 = fingerprint_dataset(cache_path, key, split=plan["split"])
        fp2 = fingerprint_dataset(cache2, key, split=disjoint_plan["split"])
        check = check_disjointness(cache_path, fp1, cache2, fp2)
        results["disjointness"] = {
            "checked": True,
            "against": f"{disjoint_plan['config']}/{disjoint_plan['split']} (n={len(normalized2)})",
            "disjoint": check["disjoint"],
            "verified": check["verified"],
            "shared_samples": check["shared_samples"],
            "errors": check["errors"],
        }
        print(
            f"[{key}] disjointness vs {disjoint_plan['config']}/{disjoint_plan['split']}: {check['disjoint']} (verified={check['verified']}, shared={check['shared_samples']})"
        )

    # Detector behaviour on the labelled rows only; unlabelled rows
    # (RAID test, OpAI-Bench partials) are counted, never scored as a class.
    detector = BuiltinHeuristicDetector()
    labelled = [r for r in normalized if r.label is not None]
    pairs: list[tuple[int, float]] = []
    abstentions = 0
    per_kind: dict[str, list[float]] = {}
    for row in labelled:
        prediction = detector.detect(row.text)
        if prediction.verdict == "abstain":
            abstentions += 1
        pairs.append((int(row.label), float(prediction.score)))
        kind = str(row.meta.get("kind", row.regime))
        per_kind.setdefault(kind, []).append(float(prediction.score))
    labels = [lab for lab, _ in pairs]
    scores = [s for _, s in pairs]
    results["detector_evaluated_rows"] = len(pairs)
    results["detector_abstentions"] = abstentions
    results["score_by_label"] = {
        "human": _score_summary([s for lab, s in pairs if lab == 0]),
        "machine": _score_summary([s for lab, s in pairs if lab == 1]),
    }
    if len(set(labels)) == 2 and min(Counter(labels).values()) >= 10:
        results["auroc"] = round(auroc(labels, scores), 4)
        results["tpr_at_1pct_fpr"] = round(tpr_at_fpr(labels, scores, 0.01), 4)
        results["tpr_at_5pct_fpr"] = round(tpr_at_fpr(labels, scores, 0.05), 4)
    else:
        results["auroc"] = None
        results["auroc_not_computed"] = (
            f"both classes need >= 10 rows; label counts are {dict(Counter(labels))}"
        )
    results["mean_score_by_kind"] = {
        kind: round(statistics.fmean(vals), 4) for kind, vals in sorted(per_kind.items())
    }
    results["rows_by_kind"] = {kind: len(vals) for kind, vals in sorted(per_kind.items())}
    if key == "opai_bench":
        results["ai_sentence_ratio_values"] = sorted(
            {str(r.meta.get("ai_sentence_ratio")) for r in normalized}
        )
    if key == "ghostwriter":
        results["rows_by_domain"] = {
            domain: sum(1 for r in normalized if r.meta.get("domain") == domain)
            for domain in sorted({str(r.meta.get("domain")) for r in normalized})
        }
        results["label_counts_by_domain"] = {
            domain: {
                str(k): sum(
                    1 for r in normalized if r.meta.get("domain") == domain and r.label == k
                )
                for k in (0, 1, None)
                if any(r.meta.get("domain") == domain and r.label == k for r in normalized)
            }
            for domain in sorted({str(r.meta.get("domain")) for r in normalized})
        }

    drops = [
        {
            "item": "full-corpus evaluation",
            "reason": f"preliminary sample only (n={len(normalized)} normalised rows from {plan['total']} split rows)",
        },
        {
            "item": f"Python {', '.join(UNMEASURED_VERSIONS)}",
            "reason": "measured on the local interpreter only; CI covers the matrix",
        },
        {
            "item": "train/test threshold selection",
            "reason": "no threshold was fitted on this sample; AUROC/TPR@FPR are threshold-free",
        },
    ]
    if key == "beemo":
        drops.append(
            {
                "item": "split disjointness check",
                "reason": "Beemo ships a single train split; there is no second split to check against",
            }
        )
    if key == "ghostwriter":
        drops.append(
            {
                "item": f"{counts.get(None, 0)} fusion (mixed-origin) rows",
                "reason": "label 2 rows carry no binary label; they are the U4 spine, not U1 evidence",
            }
        )

    # The run-artifact schema only allows [a-z0-9-] in the record id,
    # so opai_bench becomes opai-bench here (results["dataset"] keeps
    # the loader key).
    record_id = f"EV-{date.today().strftime('%Y%m%d')}-dataset-{key.replace('_', '-')}"
    record = _base_record(
        record_id,
        "command",
        f"python scripts/measure_datasets.py --only {key}",
    )
    record["results"] = results
    record["drops"] = drops
    # Badge enum is fixed (available/functional/reproduced); the
    # preliminary nature lives in results["preliminary"] + the drops.
    record["badge"] = "available"
    _write_record(record, force)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default="", help="comma-separated dataset keys (default: all)")
    parser.add_argument("--force", action="store_true", help="replace existing artifacts")
    parser.add_argument("--list", action="store_true", help="print the plan and exit (no network)")
    args = parser.parse_args()

    keys = [k for k in SAMPLE_PLAN if not args.only or k in args.only.split(",")]
    unknown = set(args.only.split(",")) - set(SAMPLE_PLAN) if args.only else set()
    if unknown:
        print(f"unknown dataset keys: {sorted(unknown)} (known: {sorted(SAMPLE_PLAN)})")
        return 2
    if args.list:
        for key in keys:
            plan = SAMPLE_PLAN[key]
            print(
                f"{key}: {plan['config']}/{plan['split']} n={plan['n']} "
                f"({plan['method']}, split total {plan['total']})"
            )
        return 0
    for key in keys:
        measure_dataset(key, args.force)
    rebuild_registry()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
