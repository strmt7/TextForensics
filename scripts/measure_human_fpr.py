#!/usr/bin/env python3
"""measure_human_fpr.py — Re-run the builtin detector on the cached human rows.

For each of the 7 slices in ``docs/validation/registry.json``, re-run
the deterministic builtin detector at its native operating point
(``analyze_text`` verdict ``ai_like``; no score threshold, no fitted
threshold) over the cached labelled rows and report the human false
positive rate (FPR) with a Wilson 95% confidence interval, plus the
paired native true positive rate (TPR) with its Wilson interval.

Why Wilson, not the registry's bootstrap CI: every registry
``fpr_native`` CI is the degenerate ``[0.0, 0.0]`` — a percentile
bootstrap over an all-zero sample can never resample a positive, so
it reports certainty of a zero FPR from as few as 56 humans. The
Wilson score interval is honest at the boundary (k=0): it gives the
upper bound the sample actually supports. The registry values are
NOT overwritten here — this script only re-measures and writes a
standalone evidence artifact plus a registry-patch *recommendation*
for the parent. The report card / CLAIMS.yaml lead changes only by a
parent decision.

Slice kinds: six slices are document-level (``BuiltinHeuristicDetector.
detect`` on the cached text). The seventh (OpAI-Bench 20261107) is
segment-level (sentences, not documents): it is scored exactly as
the U4 segment record was — ``analyze_text(sentence,
include_robustness=False)`` + ``mixed_origin.segment_verdict`` —
and is NEVER pooled with the document slices or read as a
document-level claim.

Cache safety: every cache file's SHA-256 is verified against the
registry record's ``file_sha256`` before it is measured, and the
re-run row counts must match the registry's ``n_human``/``n_ai``.
A mismatch raises instead of silently measuring a different sample.
(Worker 1 is growing the RAID sample in parallel; if the live RAID
cache has moved on, re-run with ``--cache-dir`` pointing at a
byte-identical snapshot of the registry caches.)

Usage:
    python scripts/measure_human_fpr.py [--only beemo,raid]
    python scripts/measure_human_fpr.py --check   # measure only, write nothing
    python scripts/measure_human_fpr.py --cache-dir /tmp/human-fpr-cache-20261108
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from textforensics.datasets import cache_path, get_spec, read_sample_cache  # noqa: E402
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.engine import analyze_text  # noqa: E402
from textforensics.evidence import (  # noqa: E402
    DEFAULT_FPR_CEILING,
    MIN_AI_SAMPLES,
    MIN_HUMAN_SAMPLES,
)
from textforensics.mixed_origin import segment_verdict  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402

RUN_DATE = "2026-11-08"
Z_95 = 1.96
WILSON_METHOD = "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci"
NATIVE_OPERATING_POINT = "builtin-heuristic native verdict (analyze_text); no score threshold"
SEGMENT_OPERATING_POINT = (
    "segment verdict (analyze_text include_robustness=False + "
    "mixed_origin.segment_verdict, 0.68/0.32); segments under 20 words abstain"
)
ARTIFACT_ID = "EV-20261108-human-fpr"
PATCH_ARTIFACT_ID = "EV-20261108-human-fpr-registry-patch"

# record_id -> cache location. Row counts / hashes are read from the
# registry at run time, never hardcoded here.
SLICES = [
    {
        "record_id": "evr-20261106-beemo-builtin-heuristic",
        "key": "beemo",
        "config": "default",
        "split": "train",
        "segment": False,
    },
    {
        "record_id": "evr-20261106-mage-builtin-heuristic",
        "key": "mage",
        "config": "default",
        "split": "train",
        "segment": False,
    },
    {
        "record_id": "evr-20261106-opai-bench-builtin-heuristic",
        "key": "opai_bench",
        "config": "default",
        "split": "train",
        "segment": False,
    },
    {
        "record_id": "evr-20261106-raid-builtin-heuristic",
        "key": "raid",
        "config": "raid",
        "split": "train",
        "segment": False,
    },
    {
        "record_id": "evr-20261107-detectrl-x-builtin-heuristic",
        "key": "detectrl_x",
        "config": "binary",
        "split": "train",
        "segment": False,
    },
    {
        "record_id": "evr-20261107-ghostwriter-builtin-heuristic",
        "key": "ghostwriter",
        "config": "default",
        "split": "train",
        "segment": False,
    },
    {
        "record_id": "evr-20261107-opai-bench-builtin-heuristic",
        "key": "opai_bench",
        "config": "default",
        "split": "train",
        "segment": True,
        "filename": "train-segments.jsonl",
    },
]


def rate_with_ci(k: int, n: int, *, z: float = Z_95) -> dict:
    """Point rate k/n with a Wilson 95% CI.

    Pure function. ``wilson_ci`` raises ValueError for n <= 0 or
    k outside [0, n]; the rate itself is exact (k/n, unrounded).
    """
    lower, upper = wilson_ci(k, n, z=z)
    return {
        "k": k,
        "n": n,
        "rate": k / n,
        "ci_lower": lower,
        "ci_upper": upper,
        "method": WILSON_METHOD,
    }


def assess_slice(
    *,
    record_id: str,
    n_human: int,
    n_ai: int,
    fpr_ci_upper: float | None,
    fpr_ci_present: bool = True,
    segment_level: bool = False,
    fpr_ceiling: float = DEFAULT_FPR_CEILING,
) -> dict:
    """Assess one slice against the FPR-evidence bar only.

    Pure function. The bar is the one ``validation._fpr_blockers``
    plus ``_support_blockers`` apply to the human-FPR dimension:
    at least ``MIN_HUMAN_SAMPLES`` humans (and ``MIN_AI_SAMPLES`` AI
    rows, so the paired TPR is meaningful), an ``fpr_native`` CI
    present, and the best (here: only) Wilson ``ci_upper`` at or
    below the ceiling. This is NOT a full ``supported`` assessment:
    effective record status (all seeds are ``partial``, unreviewed),
    contamination, freshness and the other dimensions are out of
    scope here and still block ``supported`` on their own. A
    segment-level slice can never support a document-level FPR claim.
    """
    blockers: list[str] = []
    if segment_level:
        blockers.append(
            "segment-level slice (sentences, not documents): cannot support "
            "a document-level human-FPR claim; assessed separately"
        )
    if n_human < MIN_HUMAN_SAMPLES:
        blockers.append(
            f"n_human={n_human} is below the {MIN_HUMAN_SAMPLES}-row minimum for a supported slice"
        )
    if n_ai < MIN_AI_SAMPLES:
        blockers.append(
            f"n_ai={n_ai} is below the {MIN_AI_SAMPLES}-row minimum (paired native TPR is thin)"
        )
    if not fpr_ci_present or fpr_ci_upper is None:
        blockers.append("no fpr_native metric carries a confidence interval")
    elif fpr_ci_upper > fpr_ceiling:
        blockers.append(
            f"Wilson fpr_native ci_upper is {fpr_ci_upper:.6f}, which exceeds "
            f"the ceiling {fpr_ceiling}"
        )
    return {
        "record_id": record_id,
        "can_support_fpr_claim": not blockers,
        "blockers": blockers,
    }


def pooled_rate(counts: list[tuple[int, int]], *, z: float = Z_95) -> dict:
    """Pooled rate over (k, n) pairs. Pure function."""
    total_k = sum(k for k, _ in counts)
    total_n = sum(n for _, n in counts)
    return rate_with_ci(total_k, total_n, z=z)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _round6(value: float) -> float:
    return round(float(value), 6)


def _rate_out(rate: dict) -> dict:
    return {
        "k": rate["k"],
        "n": rate["n"],
        "value": _round6(rate["rate"]),
        "ci_lower": _round6(rate["ci_lower"]),
        "ci_upper": _round6(rate["ci_upper"]),
        "method": rate["method"],
    }


def _registry_record(registry: dict, record_id: str) -> dict:
    for record in registry["records"]:
        if record["record_id"] == record_id:
            return record
    raise ValueError(f"record {record_id} not in docs/validation/registry.json")


def measure_slice(slice_def: dict, registry: dict, *, cache_dir: Path | None = None) -> dict:
    """Re-run the detector over one registry slice's cached rows.

    Verifies the cache SHA-256 against the registry record and the
    re-run row counts against the registry's n_human/n_ai, then
    counts native ``ai_like`` verdicts per class. Returns the
    per-slice evidence dict (rates rounded to 6 decimals).
    """
    record = _registry_record(registry, slice_def["record_id"])
    spec = get_spec(slice_def["key"])
    cache_file = cache_path(spec.key, slice_def["config"], slice_def["split"], cache_dir=cache_dir)
    if slice_def.get("filename"):
        cache_file = cache_file.with_name(slice_def["filename"])
    if not cache_file.exists():
        raise ValueError(f"{slice_def['record_id']}: cache file missing: {cache_file}")
    cache_sha = _sha256_file(cache_file)
    registry_sha = record["data"]["file_sha256"]
    if cache_sha != registry_sha:
        raise ValueError(
            f"{slice_def['record_id']}: cache SHA-256 {cache_sha} != registry "
            f"file_sha256 {registry_sha} for {cache_file} — refusing to "
            "measure a different sample than the registry record describes"
        )
    metric = record["metrics"][0]
    registry_fpr = metric["fpr_native"]
    registry_tpr = metric["tpr_native"]

    if slice_def["segment"]:
        rows = read_sample_cache(
            spec,
            slice_def["config"],
            slice_def["split"],
            cache_dir=cache_dir,
            filename=slice_def["filename"],
        )
        n_human = n_ai = k_fp = k_tp = abstentions = 0
        max_human_score: float | None = None
        for row in rows:
            sentences = row.meta.get("sentences")
            labels = row.meta.get("sentence_labels")
            if (
                not isinstance(sentences, list)
                or not isinstance(labels, list)
                or len(sentences) != len(labels)
            ):
                raise ValueError(
                    f"{slice_def['record_id']}: cached row {row.source_id!r} "
                    "lacks valid segment meta — re-run scripts/measure_segments.py"
                )
            for sentence, label in zip(sentences, labels, strict=True):
                result = analyze_text(sentence, include_robustness=False)
                score = float(result.score)
                verdict = segment_verdict(score, len(sentence.split()))
                if int(label) == 0:
                    n_human += 1
                    max_human_score = (
                        score if max_human_score is None else max(max_human_score, score)
                    )
                    if verdict == "ai_like":
                        k_fp += 1
                else:
                    n_ai += 1
                    if verdict == "ai_like":
                        k_tp += 1
                if verdict == "abstain":
                    abstentions += 1
        operating_point = SEGMENT_OPERATING_POINT
    else:
        rows = read_sample_cache(spec, slice_def["config"], slice_def["split"], cache_dir=cache_dir)
        labelled = [row for row in rows if row.label is not None]
        detector = BuiltinHeuristicDetector()
        n_human = n_ai = k_fp = k_tp = abstentions = 0
        max_human_score: float | None = None
        for row in labelled:
            prediction = detector.detect(row.text)
            score = float(prediction.score)
            if int(row.label) == 0:
                n_human += 1
                max_human_score = score if max_human_score is None else max(max_human_score, score)
                if prediction.verdict == "ai_like":
                    k_fp += 1
            elif int(row.label) == 1:
                n_ai += 1
                if prediction.verdict == "ai_like":
                    k_tp += 1
            else:
                raise ValueError(
                    f"{slice_def['record_id']}: unexpected label "
                    f"{row.label!r} on row {row.source_id!r}"
                )
            if prediction.verdict == "abstain":
                abstentions += 1
        operating_point = NATIVE_OPERATING_POINT

    if n_human != metric["n_human"] or n_ai != metric["n_ai"]:
        raise ValueError(
            f"{slice_def['record_id']}: re-run counts n_human={n_human}, "
            f"n_ai={n_ai} != registry n_human={metric['n_human']}, "
            f"n_ai={metric['n_ai']} — refusing to report a different sample"
        )
    # Reproduction: the registry stores fpr/tpr rounded to 4 decimals,
    # so the re-run k must be the integer the rounded value implies.
    expected_k_fp = round(registry_fpr["value"] * n_human)
    expected_k_tp = round(registry_tpr["value"] * n_ai)
    reproduces_fpr = k_fp == expected_k_fp
    reproduces_tpr = k_tp == expected_k_tp
    if not (reproduces_fpr and reproduces_tpr):
        print(
            f"LOUD: {slice_def['record_id']}: RE-RUN DOES NOT REPRODUCE THE "
            f"REGISTRY — fpr k={k_fp} (registry implies {expected_k_fp}), "
            f"tpr k={k_tp} (registry implies {expected_k_tp})",
            file=sys.stderr,
        )

    fpr = rate_with_ci(k_fp, n_human)
    tpr = rate_with_ci(k_tp, n_ai)
    assessment = assess_slice(
        record_id=slice_def["record_id"],
        n_human=n_human,
        n_ai=n_ai,
        fpr_ci_upper=fpr["ci_upper"],
        segment_level=bool(slice_def["segment"]),
    )
    return {
        "record_id": slice_def["record_id"],
        "dataset": record["data"]["dataset_name"],
        "slice_kind": "segment" if slice_def["segment"] else "document",
        "cache_file_sha256": cache_sha,
        "registry_file_sha256": registry_sha,
        "cache_sha256_matches_registry": cache_sha == registry_sha,
        "n_human": n_human,
        "n_ai": n_ai,
        "abstentions": abstentions,
        "max_human_score": (None if max_human_score is None else _round6(max_human_score)),
        "operating_point": operating_point,
        "fpr_native_wilson": _rate_out(fpr),
        "tpr_native_wilson": _rate_out(tpr),
        "registry_fpr_native": {
            "value": registry_fpr["value"],
            "n": registry_fpr["n"],
            "ci_lower": registry_fpr["ci_lower"],
            "ci_upper": registry_fpr["ci_upper"],
            "method": registry_fpr["method"],
        },
        "registry_tpr_native": {
            "value": registry_tpr["value"],
            "n": registry_tpr["n"],
            "ci_lower": registry_tpr["ci_lower"],
            "ci_upper": registry_tpr["ci_upper"],
            "method": registry_tpr["method"],
        },
        "reproduces_registry_fpr": reproduces_fpr,
        "reproduces_registry_tpr": reproduces_tpr,
        "assessment": assessment,
    }


def build_patch_assessment(slices: list[dict]) -> dict:
    """Registry-patch recommendation (NOT an applied edit).

    For each record: replace the degenerate bootstrap ``fpr_native``
    CI ``[0.0, 0.0]`` with the Wilson CI from this re-run (value
    unchanged — the re-run reproduced every registry value), and
    record whether the FPR bar alone would then be met. No status
    change is recommended for any record: every seed record stays
    ``partial`` (unreviewed, preliminary strided sample) whatever
    its FPR bar says.
    """
    entries = []
    for item in slices:
        fpr = item["fpr_native_wilson"]
        entries.append(
            {
                "record_id": item["record_id"],
                "dataset": item["dataset"],
                "slice_kind": item["slice_kind"],
                "proposed_change": (
                    "replace metrics[0].fpr_native ci_lower/ci_upper/method "
                    "with the Wilson 95% CI from EV-20261108-human-fpr "
                    f"(value stays {fpr['value']}); do NOT change status, "
                    "value, or any other field"
                ),
                "wilson_fpr_native": fpr,
                "fpr_bar_met": item["assessment"]["can_support_fpr_claim"],
                "fpr_bar_blockers": item["assessment"]["blockers"],
                "recommendation": (
                    "apply the Wilson CI replacement; keep status partial"
                    if item["assessment"]["can_support_fpr_claim"]
                    or item["slice_kind"] == "segment"
                    else "apply the Wilson CI replacement; keep status partial "
                    "— the FPR bar is NOT met, so this record must not be "
                    "cited as human-FPR evidence"
                ),
            }
        )
    return {
        "schema": "textforensics.human-fpr-registry-patch/v1",
        "evidence_record_id": PATCH_ARTIFACT_ID,
        "run_date": RUN_DATE,
        "source_artifact": f"docs/evidence/{ARTIFACT_ID}.json",
        "note": (
            "Recommendation for the parent only. No registry file was "
            "edited by scripts/measure_human_fpr.py. Applying the CI "
            "replacement requires re-signing each touched record and "
            "recomputing the registry id."
        ),
        "records": entries,
    }


def _code_version() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default="", help="comma-separated dataset keys (default: all)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="measure only; write no artifact files",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="dataset cache dir (default: XDG cache / TEXTFORENSICS_DATASETS_DIR)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="artifact path (default: docs/evidence/EV-20261108-human-fpr.json)",
    )
    parser.add_argument(
        "--patch-output",
        default=None,
        help="registry-patch path (default: "
        "docs/evidence/EV-20261108-human-fpr-registry-patch.json)",
    )
    args = parser.parse_args(argv)

    only = {key for key in args.only.split(",") if key} if args.only else None
    selected = [s for s in SLICES if only is None or s["key"] in only]
    if only and len(selected) != len(only):
        unknown = only - {s["key"] for s in SLICES}
        print(f"unknown dataset keys: {sorted(unknown)}")
        return 2
    cache_dir = Path(args.cache_dir) if args.cache_dir else None

    registry = json.loads(
        (REPO_ROOT / "docs" / "validation" / "registry.json").read_text(encoding="utf-8")
    )
    slices = [measure_slice(slice_def, registry, cache_dir=cache_dir) for slice_def in selected]

    doc_counts = [
        (s["fpr_native_wilson"]["k"], s["n_human"]) for s in slices if s["slice_kind"] == "document"
    ]
    all_counts = [(s["fpr_native_wilson"]["k"], s["n_human"]) for s in slices]
    pooled_documents = _rate_out(pooled_rate(doc_counts)) if doc_counts else None
    pooled_all = _rate_out(pooled_rate(all_counts)) if all_counts else None
    worst_slice_upper = max(s["fpr_native_wilson"]["ci_upper"] for s in slices) if slices else None
    worst_document_upper = (
        max(s["fpr_native_wilson"]["ci_upper"] for s in slices if s["slice_kind"] == "document")
        if doc_counts
        else None
    )

    artifact = {
        "schema": "textforensics.human-fpr-evidence/v1",
        "evidence_record_id": ARTIFACT_ID,
        "run_date": RUN_DATE,
        "code_version": _code_version(),
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_family": BuiltinHeuristicDetector.detector_family,
        "command": "python scripts/measure_human_fpr.py",
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "method": (
            "Re-ran the deterministic builtin detector at its native "
            "operating point over the cached labelled rows of each "
            "registry slice (cache SHA-256 verified against the registry "
            "record first; row counts verified against the registry). "
            "Human FPR = P(verdict=ai_like | human); native TPR = "
            "P(verdict=ai_like | AI) at the same operating point. "
            "Intervals are Wilson 95% CIs (z=1.96) from the re-run (k, n) "
            "counts. The registry's bootstrap fpr_native CIs are all the "
            "degenerate [0.0, 0.0] (a percentile bootstrap over an "
            "all-zero sample cannot resample a positive); Wilson is the "
            "honest interval here and replaces nothing in the registry — "
            "see the companion registry-patch recommendation."
        ),
        "pooling_assessment": (
            "Pooling is NOT legitimate as the gate statistic. The slices "
            "differ in regime (raw vs human-edited), language (en vs mul "
            "8-language vs en+de), domain, generator vintage and editing; "
            "pooling hides that heterogeneity, and the segment slice is a "
            "different unit (sentences, not documents) that must never be "
            "pooled with document slices at all. The pooled numbers are "
            "reported for completeness only. The release gate must use "
            "the per-slice worst Wilson ci_upper among the document "
            "slices that meet the sample minimum — a single pooled "
            "number would let a large slice (DetectRL-X, n=400) mask a "
            "thin slice (OpAI-Bench 20261106, n=56, Wilson upper 0.0642)."
        ),
        "slices": slices,
        "pooled_documents_only": pooled_documents,
        "pooled_all_slices_including_segments": pooled_all,
        "worst_slice_wilson_ci_upper": worst_slice_upper,
        "worst_document_slice_wilson_ci_upper": worst_document_upper,
        "still_unknown": [
            "Worst-slice human FPR as a *supported* claim: no slice is "
            "supported (all records are unreviewed partial seeds), and "
            "two document slices fail the FPR bar outright (OpAI-Bench "
            "20261106: n=56, Wilson upper above the 0.05 ceiling; RAID: "
            "n=92, below the 100-human minimum). The report-card lead "
            "('worst-slice human FPR = unknown') changes only by a parent "
            "decision; this artifact does not change it.",
            "Human FPR on slices the registry does not cover at all: "
            "non-English document text outside DetectRL-X/GhostWriter, "
            "ESL human text, texts below 80 words, generators newer than "
            "each record's declared vintage, and human populations "
            "outside the declared ones.",
            "Whether the zero observed false positives persist on larger "
            "human samples: every Wilson upper bound here is a bound on "
            "zero events, not a measured positive rate. A larger human "
            "sample (RAID growth is worker 1's parallel work) could "
            "produce the first false positive and move the bound.",
            "Per-language / per-domain / per-generator FPR: this re-run "
            "reports one pooled slice per dataset, as the registry does; "
            "finer slices are wave-2 work.",
        ],
    }

    for item in slices:
        fpr = item["fpr_native_wilson"]
        tpr = item["tpr_native_wilson"]
        print(
            f"{item['dataset']:<14} {item['slice_kind']:<8} n_hum={item['n_human']:>5} "
            f"k_fp={fpr['k']:>3} FPR={fpr['value']:.4f} "
            f"Wilson95=[{fpr['ci_lower']:.4f}, {fpr['ci_upper']:.4f}] "
            f"TPR={tpr['value']:.4f} Wilson95=[{tpr['ci_lower']:.4f}, {tpr['ci_upper']:.4f}] "
            f"reproduces_registry={item['reproduces_registry_fpr'] and item['reproduces_registry_tpr']} "
            f"fpr_bar={'PASS' if item['assessment']['can_support_fpr_claim'] else 'FAIL'}"
        )
    if pooled_documents is not None:
        print(
            f"POOLED documents-only: n={pooled_documents['n']} k={pooled_documents['k']} "
            f"FPR={pooled_documents['value']:.4f} "
            f"Wilson95=[{pooled_documents['ci_lower']:.4f}, {pooled_documents['ci_upper']:.4f}]"
        )
    if pooled_all is not None:
        print(
            f"POOLED all slices (incl. segments — NOT gate-legitimate): "
            f"n={pooled_all['n']} k={pooled_all['k']} FPR={pooled_all['value']:.4f} "
            f"Wilson95=[{pooled_all['ci_lower']:.4f}, {pooled_all['ci_upper']:.4f}]"
        )

    if args.check:
        print("check mode: no artifact files written")
        return 0
    output = (
        Path(args.output)
        if args.output
        else REPO_ROOT / "docs" / "evidence" / f"{ARTIFACT_ID}.json"
    )
    patch_output = (
        Path(args.patch_output)
        if args.patch_output
        else REPO_ROOT / "docs" / "evidence" / f"{PATCH_ARTIFACT_ID}.json"
    )
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    patch = build_patch_assessment(slices)
    patch_output.write_text(json.dumps(patch, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)})")
    print(f"wrote {patch_output} (sha256 {_sha256_file(patch_output)})")
    if not all(s["reproduces_registry_fpr"] and s["reproduces_registry_tpr"] for s in slices):
        print("LOUD: at least one slice did NOT reproduce its registry values", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
