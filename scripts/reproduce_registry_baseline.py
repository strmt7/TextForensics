#!/usr/bin/env python3
"""reproduce_registry_baseline.py — W8 worker E (independent reproduction).

Independently reproduces the NINE frozen pre-W8 registry records
(docs/validation/registry.json, as tabulated in Worker D's
predeclaration §1) from scratch, on the W8 code base (audit-w7 @
17b8951, no inference changes):

- Locates each record's cache file by SHA-256 (scanning the dataset
  cache; the file is identified by its hash, never by its name).
- Reads the cache files DIRECTLY as JSONL (no dataset-loader helpers,
  no import of scripts/measure_human_fpr.py).
- Re-runs the deterministic builtin-heuristic detector at its native
  operating point over every labelled row (document slices) and over
  every labelled sentence (the OpAI-Bench segment slice, via
  analyze_text(include_robustness=False) + segment_verdict).
- Recomputes, with implementations written here from the definitions:
  per-slice human FPR and native TPR with Wilson 95% CIs (repo
  wilson_ci cross-checked against the formula implementation),
  AUROC (pairwise Mann-Whitney counting, cross-checked against the
  rank form) and AUPRC (stepwise average precision over distinct
  score thresholds), all on the native score.
- Compares every recomputed number with the registry record: FPR/TPR
  by exact k (the registry stores values rounded to 4 decimals, so
  the re-run k must be the integer the rounded value implies),
  AUROC by exact 4-decimal agreement, and reports the exact signed
  difference where they differ. ANY discrepancy is a finding.

This is the baseline leg of the W8-E reproduction: it checks that the
frozen numbers Worker D predecalred still reproduce on the W8 code
before any W8 final-holdout claim is built on them.

Usage:
    python scripts/reproduce_registry_baseline.py [--check]
    python scripts/reproduce_registry_baseline.py --output <path>

--check measures and compares only; it writes nothing.
The default output is docs/evidence/runs/EV-20261116-reproduction-registry.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.engine import analyze_text  # noqa: E402
from textforensics.mixed_origin import segment_verdict  # noqa: E402
from textforensics.probe_metrics import wilson_ci as repo_wilson_ci  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-reproduction-registry"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
CACHE_ROOT = Path.home() / ".cache" / "textforensics" / "datasets"
Z_95 = 1.96
WILSON_METHOD = "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci"
NATIVE_OPERATING_POINT = "builtin-heuristic native verdict (analyze_text); no score threshold"
SEGMENT_OPERATING_POINT = (
    "segment verdict (analyze_text include_robustness=False + "
    "mixed_origin.segment_verdict, 0.68/0.32); segments under 20 words abstain"
)

# record_id -> cache location (relative to CACHE_ROOT). The file is
# still verified by SHA-256 against the registry record before use;
# a wrong mapping fails loudly instead of measuring another sample.
RECORD_CACHE = {
    "evr-20261106-beemo-builtin-heuristic": "beemo/default/train.jsonl",
    "evr-20261106-mage-builtin-heuristic": "mage/default/train.jsonl",
    "evr-20261106-opai-bench-builtin-heuristic": "opai_bench/default/train.jsonl",
    "evr-20261106-raid-builtin-heuristic": "raid/raid/train.jsonl",
    "evr-20261107-detectrl-x-builtin-heuristic": "detectrl_x/binary/train.jsonl",
    "evr-20261107-ghostwriter-builtin-heuristic": "ghostwriter/default/train.jsonl",
    "evr-20261107-opai-bench-builtin-heuristic": "opai_bench/default/train-segments.jsonl",
    "evr-20261108-raid-builtin-heuristic": "raid/raid/train-6000.jsonl",
    "evr-20261110-opai-bench-builtin-heuristic": "opai_bench/default/train-2000.jsonl",
}
SEGMENT_RECORD = "evr-20261107-opai-bench-builtin-heuristic"

# Frozen pre-W8 Wilson 95% FPR uppers from Worker D's predeclaration
# (docs/evidence/w8-predeclared-claims.md §1). The registry record's
# OWN stored FPR CI is a bootstrap CI for one record (RAID 20261106,
# ci_upper 0.0 — degenerate on an all-zero sample) and Wilson for the
# rest; the Wilson comparison here is against these predeclaration
# values in every case, and the registry method is recorded per record.
PREDECLARED_WILSON_FPR_UPPER = {
    "evr-20261106-beemo-builtin-heuristic": 0.018846,
    "evr-20261106-mage-builtin-heuristic": 0.031790,
    "evr-20261106-opai-bench-builtin-heuristic": 0.064196,
    "evr-20261106-raid-builtin-heuristic": 0.040083,
    "evr-20261107-detectrl-x-builtin-heuristic": 0.009513,
    "evr-20261107-ghostwriter-builtin-heuristic": 0.027276,
    "evr-20261107-opai-bench-builtin-heuristic": 0.000802,
    "evr-20261108-raid-builtin-heuristic": 0.021972,
    "evr-20261110-opai-bench-builtin-heuristic": 0.017317,
}


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


def auroc_rank(labels: list[int], scores: list[float]) -> float:
    """Rank-form AUROC (average ranks for ties). Must equal pairwise."""
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    rank_sum = 0.0
    i = 0
    n = len(order)
    while i < n:
        j = i
        while j < n and scores[order[j]] == scores[order[i]]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            if labels[order[k]] == 1:
                rank_sum += avg_rank
        i = j
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def auprc_distinct_thresholds(labels: list[int], scores: list[float]) -> float:
    """Stepwise average precision over distinct score thresholds
    (descending). Groups tied scores before computing precision, so a
    tie group contributes once with its aggregate precision."""
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


def rate_with_ci(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {
        "k": k,
        "n": n,
        "value": _round6(k / n),
        "ci_lower": _round6(lo),
        "ci_upper": _round6(hi),
        "method": WILSON_METHOD,
    }


def _self_test() -> list[str]:
    problems: list[str] = []
    if abs(auroc_pairwise([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) - 1.0) > 1e-12:
        problems.append("auroc_pairwise perfect != 1.0")
    if abs(auroc_rank([1, 1, 0, 0], [0.9, 0.8, 0.2, 0.1]) - 1.0) > 1e-12:
        problems.append("auroc_rank perfect != 1.0")
    if abs(auroc_pairwise([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.1]) - 0.75) > 1e-12:
        problems.append("auroc_pairwise known case != 0.75")
    if abs(auprc_distinct_thresholds([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.1]) - (1.0 + 2.0 / 3.0) / 2.0) > 1e-12:
        problems.append("auprc known case != 0.8333")
    lo, hi = wilson(0, 200)
    if abs(hi - 0.018846) > 1e-6:
        problems.append(f"wilson(0,200) upper {hi} != 0.018846")
    lo2, hi2 = repo_wilson_ci(0, 200, z=1.96)
    if abs(hi2 - hi) > 1e-12 or abs(lo2 - lo) > 1e-12:
        problems.append("repo wilson_ci disagrees with the formula implementation")
    return problems


def load_cache_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def measure_record(record: dict, registry: dict, detector: BuiltinHeuristicDetector) -> dict:
    record_id = record["record_id"]
    cache_rel = RECORD_CACHE[record_id]
    cache_file = CACHE_ROOT / cache_rel
    if not cache_file.exists():
        raise ValueError(f"{record_id}: cache file missing: {cache_file}")
    cache_sha = _sha256_file(cache_file)
    registry_sha = record["data"]["file_sha256"]
    if cache_sha != registry_sha:
        raise ValueError(
            f"{record_id}: cache SHA-256 {cache_sha} != registry file_sha256 {registry_sha}"
        )
    rows = load_cache_jsonl(cache_file)
    metric = record["metrics"][0]
    segment = record_id == SEGMENT_RECORD
    n_human = n_ai = k_fp = k_tp = abstentions = 0
    scores: list[float] = []
    labels: list[int] = []
    max_human_score: float | None = None
    for row in rows:
        if segment:
            sentences = row["meta"].get("sentences")
            sent_labels = row["meta"].get("sentence_labels")
            if not isinstance(sentences, list) or not isinstance(sent_labels, list):
                raise ValueError(f"{record_id}: row {row.get('source_id')} lacks segment meta")
            for sentence, label in zip(sentences, sent_labels, strict=True):
                result = analyze_text(sentence, include_robustness=False)
                score = float(result.score)
                verdict = segment_verdict(score, len(sentence.split()))
                scores.append(score)
                labels.append(int(label))
                if int(label) == 0:
                    n_human += 1
                    max_human_score = score if max_human_score is None else max(max_human_score, score)
                    if verdict == "ai_like":
                        k_fp += 1
                else:
                    n_ai += 1
                    if verdict == "ai_like":
                        k_tp += 1
                if verdict == "abstain":
                    abstentions += 1
        else:
            if row.get("label") is None:
                continue
            pred = detector.detect(row["text"])
            score = float(pred.score)
            scores.append(score)
            labels.append(int(row["label"]))
            if int(row["label"]) == 0:
                n_human += 1
                max_human_score = score if max_human_score is None else max(max_human_score, score)
                if pred.verdict == "ai_like":
                    k_fp += 1
            elif int(row["label"]) == 1:
                n_ai += 1
                if pred.verdict == "ai_like":
                    k_tp += 1
            else:
                raise ValueError(f"{record_id}: unexpected label {row['label']!r}")
            if pred.verdict == "abstain":
                abstentions += 1
    if n_human != metric["n_human"] or n_ai != metric["n_ai"]:
        raise ValueError(
            f"{record_id}: re-run counts n_human={n_human}, n_ai={n_ai} != registry "
            f"n_human={metric['n_human']}, n_ai={metric['n_ai']}"
        )
    fpr = rate_with_ci(k_fp, n_human)
    tpr = rate_with_ci(k_tp, n_ai)
    auroc_p = auroc_pairwise(labels, scores)
    auroc_r = auroc_rank(labels, scores)
    if abs(auroc_p - auroc_r) > 1e-9:
        raise ValueError(
            f"{record_id}: AUROC implementations disagree: pairwise={auroc_p} rank={auroc_r}"
        )
    auprc = auprc_distinct_thresholds(labels, scores)
    reg_fpr = metric["fpr_native"]
    reg_tpr = metric["tpr_native"]
    reg_auroc = metric.get("auroc", {})
    predeclared_upper = PREDECLARED_WILSON_FPR_UPPER[record_id]
    return {
        "record_id": record_id,
        "dataset": record["data"]["dataset_name"],
        "slice_kind": "segment" if segment else "document",
        "cache_file": str(cache_file),
        "cache_file_sha256": cache_sha,
        "registry_file_sha256": registry_sha,
        "cache_sha256_matches_registry": cache_sha == registry_sha,
        "cache_rows_total": len(rows),
        "n_human": n_human,
        "n_ai": n_ai,
        "abstentions": abstentions,
        "abstention_rate": _round6(abstentions / (n_human + n_ai)),
        "max_human_score": _round6(max_human_score),
        "operating_point": SEGMENT_OPERATING_POINT if segment else NATIVE_OPERATING_POINT,
        "fpr_native_wilson": fpr,
        "tpr_native_wilson": tpr,
        "auroc_recomputed": _round6(auroc_p),
        "auprc_recomputed": _round6(auprc),
        "registry_fpr_native": {
            "value": reg_fpr["value"],
            "n": reg_fpr["n"],
            "ci_lower": reg_fpr["ci_lower"],
            "ci_upper": reg_fpr["ci_upper"],
            "method": reg_fpr["method"],
        },
        "registry_tpr_native": {
            "value": reg_tpr["value"],
            "n": reg_tpr["n"],
            "ci_lower": reg_tpr["ci_lower"],
            "ci_upper": reg_tpr["ci_upper"],
            "method": reg_tpr["method"],
        },
        "registry_auroc": {
            "value": reg_auroc.get("value"),
            "n": reg_auroc.get("n"),
            "ci_lower": reg_auroc.get("ci_lower"),
            "ci_upper": reg_auroc.get("ci_upper"),
            "method": reg_auroc.get("method"),
        },
        "reproduces_registry_fpr": k_fp == round(reg_fpr["value"] * n_human),
        "reproduces_registry_tpr": k_tp == round(reg_tpr["value"] * n_ai),
        # The registry's stored FPR/TPR CIs are bootstrap CIs in some
        # records (RAID 20261106 FPR ci_upper is 0.0 — degenerate on an
        # all-zero sample — and every TPR CI is bootstrap). They are
        # recorded verbatim above and NOT compared to the recomputed
        # Wilson CIs. The Wilson comparison is against Worker D's
        # predeclaration (§1) values, to 6 decimals.
        "registry_fpr_ci_method": reg_fpr["method"],
        "registry_tpr_ci_method": reg_tpr["method"],
        "predeclared_wilson_fpr_upper": predeclared_upper,
        "wilson_fpr_upper_matches_predeclaration": (
            round(fpr["ci_upper"], 6) == round(predeclared_upper, 6)
        ),
        "wilson_fpr_upper_difference_recomputed_minus_predeclared": (
            _round6(fpr["ci_upper"] - predeclared_upper)
        ),
        "auroc_difference_recomputed_minus_registry": (
            _round6(auroc_p - reg_auroc["value"]) if reg_auroc.get("value") is not None else None
        ),
        "auroc_agrees_to_4dp": (
            round(auroc_p, 4) == reg_auroc["value"] if reg_auroc.get("value") is not None else None
        ),
    }


def validate_run_artifact(artifact: dict) -> list[str]:
    check_claims = _load_module(
        "check_claims_for_validation", REPO_ROOT / "scripts" / "check_claims.py"
    )
    schema = check_claims._load_schema(REPO_ROOT, "run-artifact.schema.json")
    return check_claims._schema_errors(schema, artifact)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="measure and compare only; write nothing")
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    problems = _self_test()
    if problems:
        print("METRIC SELF-TEST FAILURE:", file=sys.stderr)
        for item in problems:
            print(f"  - {item}", file=sys.stderr)
        return 2

    registry = json.loads((REPO_ROOT / "docs" / "validation" / "registry.json").read_text(encoding="utf-8"))
    detector = BuiltinHeuristicDetector()
    slices: list[dict] = []
    for record in registry["records"]:
        print(f"measuring {record['record_id']} ...", flush=True)
        slices.append(measure_record(record, registry, detector))
    n_fpr_ok = sum(1 for s in slices if s["reproduces_registry_fpr"])
    n_tpr_ok = sum(1 for s in slices if s["reproduces_registry_tpr"])
    n_auroc_ok = sum(1 for s in slices if s["auroc_agrees_to_4dp"])
    n_wilson_ok = sum(1 for s in slices if s["wilson_fpr_upper_matches_predeclaration"])
    worst_doc_upper = max(
        s["fpr_native_wilson"]["ci_upper"] for s in slices if s["slice_kind"] == "document"
    )
    worst_upper = max(s["fpr_native_wilson"]["ci_upper"] for s in slices)
    print(f"slices: {len(slices)}; FPR reproduces {n_fpr_ok}/{len(slices)}; "
          f"TPR reproduces {n_tpr_ok}/{len(slices)}; AUROC agrees to 4dp {n_auroc_ok}/{len(slices)}; "
          f"Wilson FPR upper matches predeclaration {n_wilson_ok}/{len(slices)}")
    print(f"worst document-slice Wilson upper: {worst_doc_upper:.6f}; worst overall: {worst_upper:.6f}")

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
        "command": "python scripts/reproduce_registry_baseline.py",
        "environment": env_lock,
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "detector": detector.detector_id,
            "detector_family": detector.detector_family,
            "detector_version": detector.detector_version,
            "operating_point": NATIVE_OPERATING_POINT,
            "method": (
                "Independent reproduction of the nine frozen pre-W8 registry "
                "records on the W8 code base: cache files located by SHA-256 "
                "and read directly as JSONL; detector re-run at its native "
                "operating point over every labelled row (document slices) "
                "and every labelled sentence (OpAI-Bench segment slice); "
                "FPR/TPR with Wilson 95% CIs, AUROC (pairwise Mann-Whitney, "
                "cross-checked against the rank form) and AUPRC (stepwise "
                "average precision over distinct score thresholds), all "
                "recomputed from scratch with implementations written here. "
                "FPR/TPR agreement is by exact k implied by the registry's "
                "4-decimal values; AUROC agreement is to 4 decimals. The "
                "recomputed Wilson FPR upper is compared against Worker D's "
                "predeclaration §1 values, NOT against the registry's "
                "stored CI: the registry's stored FPR CI for the RAID "
                "20261106 record is a bootstrap CI (ci_upper 0.0, "
                "degenerate on an all-zero sample) and every stored TPR CI "
                "is bootstrap, so those stored CIs cannot be compared to a "
                "Wilson CI. The stored CIs are recorded verbatim per "
                "record alongside their method."
            ),
            "slices": slices,
            "counts": {
                "slices": len(slices),
                "fpr_reproduces": n_fpr_ok,
                "tpr_reproduces": n_tpr_ok,
                "auroc_agrees_to_4dp": n_auroc_ok,
                "wilson_fpr_upper_matches_predeclaration": n_wilson_ok,
            },
            "worst_document_slice_wilson_ci_upper": _round6(worst_doc_upper),
            "worst_slice_wilson_ci_upper": _round6(worst_upper),
        },
        "drops": [
            {
                "item": "Unlabelled rows (OpAI-Bench mixed-origin rows, label None)",
                "reason": "no binary label; excluded from binary FPR/TPR/AUROC/AUPRC, as in the registry records",
            },
            {
                "item": "Python versions other than the run's own",
                "reason": "measured on the local interpreter only; CI covers the matrix",
            },
        ],
        "badge": "available",
        "detector_version": detector.detector_version,
        "notes": (
            "W8 worker E baseline leg. This reproduction checks the frozen "
            "pre-W8 numbers against the W8 code before any W8 final-holdout "
            "claim is built on them. It does not upgrade any record and "
            "does not change the report-card lead: the worst document-slice "
            "Wilson upper is recomputed here for the predeclaration's §1 "
            "baseline only."
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
        return 0
    output = (
        Path(args.output)
        if args.output
        else REPO_ROOT / "docs" / "evidence" / "runs" / f"{ARTIFACT_ID}.json"
    )
    output.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {output} (sha256 {_sha256_file(output)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
