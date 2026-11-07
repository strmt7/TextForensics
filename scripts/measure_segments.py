#!/usr/bin/env python3
"""measure_segments.py — Segment-level OpAI-Bench validation run (U4, §12(g)).

Re-fetches the SAME 500-row strided OpAI-Bench train sample as the U1
document record (same offsets: n=500 of 196,029) plus the dev-50
replication slice, with the extended mapper (segment ground truth in
meta), scores every dataset sentence with the report builder's segment
scorer, and writes:

* segment caches ``train-segments.jsonl`` / ``dev-segments.jsonl``
  (+ manifests) next to the document caches — the document caches
  are untouched, so the U1 document record's cited cache hash is
  preserved;
* one U7 run artifact ``EV-YYYYMMDD-dataset-opai-bench-segments.json``
  with segment-level metrics (AUROC, TPR@FPR, native FPR/TPR,
  precision/recall/F1 at the declared operating point, all with
  bootstrap 95% CIs) sliced by version, operation, segment length and
  domain, plus the operation-hypothesis accuracy, the verdict
  distribution on mixed documents, and the segmentation-fidelity check;
* the U1 segment record (via ``seed_validation.build_segment_record``),
  appended to ``docs/validation/registry.json``.

Segment verdicts use the report builder's operating point
(``mixed_origin.segment_verdict``: score >= 0.68 ai_like, <= 0.32
human_like, else abstain; segments under 20 words abstain) — NOT the
document detector's reliability-gated verdict, which abstains on all
short text by construction. The U7 artifact and the record state this.

No dataset text is written to the repo: caches live outside it
(XDG cache dir, ``TEXTFORENSICS_DATASETS_DIR`` override) and artifacts
carry counts, hashes and metrics only.

Usage:
    python scripts/measure_segments.py [--force] [--run-date YYYYMMDD]
    python scripts/measure_segments.py --skip-record   # artifact only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
from collections import Counter
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from measure_datasets import _check_server_total  # noqa: E402
from seed_evidence import _base_record, _write_record, rebuild_registry  # noqa: E402
from seed_validation import (  # noqa: E402
    DEV_SEGMENTS_FILENAME,
    TRAIN_SEGMENTS_FILENAME,
    bootstrap_ci,
    build_segment_record,
    measure_triples,
)

from textforensics.adversarial import AdversarialDetector  # noqa: E402
from textforensics.benchmark import check_disjointness, fingerprint_dataset  # noqa: E402
from textforensics.datasets import (  # noqa: E402
    DatasetsServerClient,
    fetch_strided_sample,
    get_spec,
    map_row,
    read_sample_cache,
    require_licence,
    write_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.engine import analyze_text  # noqa: E402
from textforensics.mixed_origin import (  # noqa: E402
    build_mixed_origin_report,
    segment_verdict,
    split_sentences_with_offsets,
)

# Same sample as the U1 document record (same offsets -> same rows).
TRAIN_PLAN = {
    "config": "default",
    "split": "train",
    "n": 500,
    "method": "strided",
    "total": 196_029,
}
DEV_PLAN = {
    "config": "default",
    "split": "dev",
    "n": 50,
    "method": "strided",
    "total": 42_363,
}

# OpAI-Bench edit operations -> the report taxonomy (brief §8.6).
OPERATION_MAP = {
    "polish": "polish",
    "paraphrase": "rewrite",
    "style": "rewrite",
    "compress": "condense",
    "expand": "expand",
}


def _metric_dict(estimate) -> dict:
    return {
        "value": round(float(estimate.value), 4),
        "n": int(estimate.n),
        "ci_lower": round(float(estimate.ci_lower), 4) if estimate.ci_lower is not None else None,
        "ci_upper": round(float(estimate.ci_upper), 4) if estimate.ci_upper is not None else None,
        "method": estimate.method,
    }


def _prf1(labels: list[int], verdicts: list[str]) -> dict:
    """Precision/recall/F1 at the declared segment operating point.

    Predicted AI = verdict ``ai_like``; predicted human =
    ``human_like``; ``abstain`` is no prediction and counts as a miss
    for recall (an AI segment the method cannot verdict is a false
    negative). Precision is None when nothing is predicted AI.
    """
    tp = sum(1 for lab, v in zip(labels, verdicts, strict=True) if lab == 1 and v == "ai_like")
    fp = sum(1 for lab, v in zip(labels, verdicts, strict=True) if lab == 0 and v == "ai_like")
    fn = sum(1 for lab, v in zip(labels, verdicts, strict=True) if lab == 1 and v != "ai_like")
    n_ai = sum(labels)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / n_ai if n_ai else None
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "n_ai": n_ai,
        "n_human": len(labels) - n_ai,
    }


def _f1_stat(sample: list[tuple[int, str]]) -> float:
    """F1 over a bootstrap resample; ValueError when undefined (skipped)."""
    result = _prf1([lab for lab, _ in sample], [v for _, v in sample])
    if result["f1"] is None:
        raise ValueError("F1 undefined on this resample (no AI predictions)")
    return result["f1"]


def _undefined_metric(n: int, note: str) -> dict:
    """Placeholder for a metric that is undefined on this slice."""
    return {
        "value": None,
        "n": n,
        "ci_lower": None,
        "ci_upper": None,
        "method": None,
        "note": note,
    }


def _native_rate_metric(verdicts: list[str], n: int, note: str) -> dict:
    """Native ai_like rate on one class, with a bootstrap CI.

    Used for single-class slices, where the present class's native
    rate is still defined (0.0 when nothing fires ai_like).
    """
    if n == 0:
        return _undefined_metric(0, note)
    value = sum(1 for v in verdicts if v == "ai_like") / n
    ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "ai_like") / len(sample),
        verdicts,
    )
    return {
        "value": round(value, 4),
        "n": n,
        "ci_lower": round(min(ci[0], value), 4),
        "ci_upper": round(max(ci[1], value), 4),
        "method": "bootstrap percentile, 1000 resamples, seed 20261106",
    }


def _slice_metrics(segments: list[dict]) -> dict:
    """Full metric set for one segment slice (pooled or sliced).

    Single-class slices (v0 is all-human, v8 is all-AI by
    construction of the edit ladder) carry null AUROC/TPR@FPR with a
    note; the native rate of the present class, coverage and the
    operating-point P/R/F1 are still reported.
    """
    labels = [s["label"] for s in segments]
    verdicts = [s["verdict"] for s in segments]
    n_human = labels.count(0)
    n_ai = labels.count(1)
    prf1 = _prf1(labels, verdicts)
    if prf1["f1"] is None:
        # No segment reached the 0.68 operating point, so precision
        # and F1 are undefined — a finding, not an error. (On the
        # OpAI-Bench train sample no segment scores >= 0.68 at all:
        # the builtin heuristic never fires ai_like on sentences.)
        # Recall is still defined (0.0: no AI segment was predicted).
        prf1["f1_ci_lower"] = None
        prf1["f1_ci_upper"] = None
        prf1["f1_ci_note"] = (
            "undefined: no segment reached the 0.68 operating point, "
            "so no AI prediction exists to score precision/F1 against"
        )
    else:
        try:
            f1_ci = bootstrap_ci(
                _f1_stat, [(lab, v) for lab, v in zip(labels, verdicts, strict=True)]
            )
        except ValueError:
            prf1["f1_ci_lower"] = None
            prf1["f1_ci_upper"] = None
            prf1["f1_ci_note"] = "bootstrap produced too few usable resamples"
        else:
            prf1["f1_ci_lower"] = round(min(f1_ci[0], prf1["f1"]), 4)
            prf1["f1_ci_upper"] = round(max(f1_ci[1], prf1["f1"]), 4)
    if n_human and n_ai:
        triples = [(s["label"], s["score"], s["verdict"]) for s in segments]
        measured = measure_triples(triples)
        return {
            "n_segments": len(segments),
            "n_human_segments": measured["n_human"],
            "n_ai_segments": measured["n_ai"],
            "auroc": _metric_dict(measured["auroc"]),
            "tpr_at_1pct_fpr": _metric_dict(measured["tpr_at_fpr_0_01"]),
            "tpr_at_5pct_fpr": _metric_dict(measured["tpr_at_fpr_0_05"]),
            "fpr_native": _metric_dict(measured["fpr_native"]),
            "tpr_native": _metric_dict(measured["tpr_native"]),
            "abstention_rate": measured["abstention_rate"],
            "abstention_ci": list(measured["abstention_ci"]),
            "coverage": measured["coverage"],
            "prf1_at_operating_point": prf1,
        }
    present = "human" if n_human else "ai"
    single_note = (
        f"single-class slice (only {present} segments): AUROC and "
        "TPR@FPR are undefined — they need both classes. v0 is "
        "all-human and v8 is all-AI by construction of the edit ladder."
    )
    human_verdicts = [v for lab, v in zip(labels, verdicts, strict=True) if lab == 0]
    ai_verdicts = [v for lab, v in zip(labels, verdicts, strict=True) if lab == 1]
    abstention_rate = verdicts.count("abstain") / len(verdicts)
    abstention_ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "abstain") / len(sample),
        verdicts,
    )
    return {
        "n_segments": len(segments),
        "n_human_segments": n_human,
        "n_ai_segments": n_ai,
        "auroc": _undefined_metric(len(segments), single_note),
        "tpr_at_1pct_fpr": _undefined_metric(len(segments), single_note),
        "tpr_at_5pct_fpr": _undefined_metric(len(segments), single_note),
        "fpr_native": _native_rate_metric(
            human_verdicts, n_human, "no human segments in this slice"
        ),
        "tpr_native": _native_rate_metric(ai_verdicts, n_ai, "no AI segments in this slice"),
        "abstention_rate": round(abstention_rate, 4),
        "abstention_ci": [round(abstention_ci[0], 4), round(abstention_ci[1], 4)],
        "coverage": round(1.0 - abstention_rate, 4),
        "prf1_at_operating_point": prf1,
        "note": single_note,
    }


def _length_band(n_words: int) -> str:
    if n_words < 20:
        return "<20 (never verdicted)"
    if n_words < 50:
        return "20-49"
    return "50+"


def _score_segments(rows: list) -> list[dict]:
    """Score every dataset sentence in ``rows`` (cache re-read)."""
    segments: list[dict] = []
    for row in rows:
        sentences = row.meta["sentences"]
        labels = row.meta["sentence_labels"]
        for sentence, label in zip(sentences, labels, strict=True):
            result = analyze_text(sentence, include_robustness=False)
            score = float(result.score)
            n_words = len(sentence.split())
            segments.append(
                {
                    "label": int(label),
                    "score": score,
                    "verdict": segment_verdict(score, n_words),
                    "n_words": n_words,
                    "version": str(row.meta.get("version")),
                    "operation": str(row.meta.get("edit_operation")),
                    "domain": str(row.meta.get("domain")),
                    "doc_id": str(row.source_id),
                }
            )
    return segments


def _segmentation_fidelity(rows: list) -> dict:
    """How well the report builder's splitter recovers dataset sentences.

    For each document, the builder's ``split_sentences_with_offsets``
    sentences are compared with the dataset's own ``sentences`` list
    (exact string match). A mismatch is a real limitation of the
    report on that document, reported here, never hidden.
    """
    docs_exact = 0
    sentences_matched = 0
    sentences_total = 0
    for row in rows:
        expected = [s for s in row.meta["sentences"]]
        got = [s for s, _, _ in split_sentences_with_offsets(row.text)]
        sentences_total += len(expected)
        matched = len(set(expected) & set(got))
        sentences_matched += matched
        if got == expected:
            docs_exact += 1
    return {
        "docs_exact_match": docs_exact,
        "docs_total": len(rows),
        "docs_exact_match_rate": round(docs_exact / len(rows), 4) if rows else None,
        "sentences_matched": sentences_matched,
        "sentences_total": sentences_total,
        "sentence_match_rate": round(sentences_matched / sentences_total, 4)
        if sentences_total
        else None,
    }


def _operation_accuracy(rows: list, *, covered_regimes: set) -> dict:
    """Predicted vs ground-truth edit operation, per document.

    The report builder is run on every document (with adversarial
    findings + document analysis, as the CLI does). The predicted
    operation is compared with the dataset's ``edit_operation``,
    mapped into the report taxonomy. v0 rows (no edit) are excluded:
    their true operation is "none", which the taxonomy has no value
    for. Accuracy is reported honestly — the hypothesis is a
    low-confidence inference and a low number is the expected result.
    """
    detector = AdversarialDetector()
    correct = 0
    total = 0
    confusion: dict[str, Counter] = {}
    verdicts_covered: Counter = Counter()
    for row in rows:
        true_op = str(row.meta.get("edit_operation"))
        if true_op in ("none", "None", ""):
            continue
        expected = OPERATION_MAP.get(true_op)
        if expected is None:
            continue
        findings = detector.analyze(row.text).findings
        document_analysis = analyze_text(row.text)
        report = build_mixed_origin_report(
            row.text,
            language="en",
            domain=str(row.meta.get("domain")),
            covered_regimes=covered_regimes,
            adversarial_findings=findings,
            document_analysis=document_analysis,
        )
        predicted = report["operation_hypothesis"]["operation"]
        confusion.setdefault(true_op, Counter())[predicted] += 1
        total += 1
        if predicted == expected:
            correct += 1
        verdicts_covered[report["verdict"]] += 1
    # Without coverage every document is withheld: condition (iv) fires
    # unconditionally (see _decide_verdict), so the no-coverage
    # distribution is trivially all-withheld and needs no second pass.
    return {
        "docs_evaluated": total,
        "correct": correct,
        "accuracy": round(correct / total, 4) if total else None,
        "confusion_true_operation_to_predicted": {
            true_op: dict(counter) for true_op, counter in sorted(confusion.items())
        },
        "verdict_distribution_no_coverage": {"withheld": total},
        "verdict_distribution_with_coverage": dict(verdicts_covered),
    }


def measure_segments(*, force: bool, run_date: str, skip_record: bool) -> dict:
    spec = get_spec("opai_bench")
    require_licence(spec)
    client = DatasetsServerClient()
    _check_server_total(spec, "default", "train", TRAIN_PLAN["total"], client)
    _check_server_total(spec, "default", "dev", DEV_PLAN["total"], client)

    print("[opai_bench_segments] fetching train n=500 (strided) ...")
    raw_train = fetch_strided_sample(
        spec, "default", "train", TRAIN_PLAN["n"], TRAIN_PLAN["total"], client=client
    )
    print("[opai_bench_segments] fetching dev n=50 (strided) ...")
    raw_dev = fetch_strided_sample(
        spec, "default", "dev", DEV_PLAN["n"], DEV_PLAN["total"], client=client
    )
    normalized_train: list = []
    for row in raw_train:
        normalized_train.extend(map_row("opai_bench", row, "default", "train"))
    normalized_dev: list = []
    for row in raw_dev:
        normalized_dev.extend(map_row("opai_bench", row, "default", "dev"))
    cache_train, manifest_train = write_sample_cache(
        spec, "default", "train", normalized_train, filename=TRAIN_SEGMENTS_FILENAME
    )
    cache_dev, manifest_dev = write_sample_cache(
        spec, "default", "dev", normalized_dev, filename=DEV_SEGMENTS_FILENAME
    )
    manifest_train_data = json.loads(manifest_train.read_text(encoding="utf-8"))
    print(f"[opai_bench_segments] train cache -> {cache_train} ({len(normalized_train)} rows)")
    print(f"[opai_bench_segments] dev cache -> {cache_dev} ({len(normalized_dev)} rows)")

    # Ratio/label agreement: the dataset's ai_sentence_ratio and its
    # sentence_labels were computed on slightly different segmentations
    # (diagnostic 2026-11-07: 6/500 train rows disagree, max |diff|
    # 0.032, all intermediate versions). The labels are the segment
    # ground truth and the ratio is the document summary; the run
    # measures the agreement and reports it, never asserts it.
    ratio_diffs = []
    for row in normalized_train:
        labels = row.meta["sentence_labels"]
        ratio = float(row.meta["ai_sentence_ratio"])
        diff = abs(sum(labels) / len(labels) - ratio)
        if diff > 1e-9:
            ratio_diffs.append((str(row.source_id), round(diff, 4)))
    print(
        f"[opai_bench_segments] ratio/label agreement: "
        f"{len(normalized_train) - len(ratio_diffs)}/{len(normalized_train)} rows agree"
    )

    # Disjointness, document-level (fail-closed) + segment-level (hash sets).
    fp_train = fingerprint_dataset(cache_train, "opai_bench", split="train")
    fp_dev = fingerprint_dataset(cache_dev, "opai_bench", split="dev")
    check = check_disjointness(cache_train, fp_train, cache_dev, fp_dev)
    train_rows = read_sample_cache(spec, "default", "train", filename=TRAIN_SEGMENTS_FILENAME)
    dev_rows = read_sample_cache(spec, "default", "dev", filename=DEV_SEGMENTS_FILENAME)
    train_seg_hashes = {
        hashlib.sha256(s.encode("utf-8")).hexdigest()
        for row in train_rows
        for s in row.meta["sentences"]
    }
    dev_seg_hashes = {
        hashlib.sha256(s.encode("utf-8")).hexdigest()
        for row in dev_rows
        for s in row.meta["sentences"]
    }
    shared_segments = train_seg_hashes & dev_seg_hashes
    # Word counts of the shared segments only (never the text):
    # a shared segment is only meaningful if it is substantive.
    shared_word_counts = sorted(
        len(s.split())
        for row in train_rows
        for s in row.meta["sentences"]
        if hashlib.sha256(s.encode("utf-8")).hexdigest() in shared_segments
    )
    print(
        f"[opai_bench_segments] disjointness train vs dev: {check['disjoint']} "
        f"(verified={check['verified']}, shared={check['shared_samples']}); "
        f"segment hashes shared: {len(shared_segments)}"
    )

    # Score segments from the cache re-read (never from the fetch).
    train_segments = _score_segments(train_rows)
    dev_segments = _score_segments(dev_rows)
    print(
        f"[opai_bench_segments] scored {len(train_segments)} train segments "
        f"({sum(1 for s in train_segments if s['label'] == 0)} human / "
        f"{sum(1 for s in train_segments if s['label'] == 1)} AI) + "
        f"{len(dev_segments)} dev segments"
    )

    results: dict = {
        "dataset": "opai_bench_segments",
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "preliminary": True,
        "config": "default",
        "split": "train",
        "sampling": "strided",
        "split_rows_total": TRAIN_PLAN["total"],
        "rows_fetched": len(raw_train),
        "rows_normalised": len(normalized_train),
        "cache_file_sha256": manifest_train_data["file_sha256"],
        "cache_file": TRAIN_SEGMENTS_FILENAME,
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "segment_scorer": (
            "analyze_text(include_robustness=False) at the declared operating "
            "point (score >=0.68 ai_like, <=0.32 human_like, else abstain; "
            "segments under 20 words abstain) — mixed_origin.segment_verdict"
        ),
        "ratio_label_agreement": {
            "rows_agreeing": len(normalized_train) - len(ratio_diffs),
            "rows_total": len(normalized_train),
            "rows_disagreeing": len(ratio_diffs),
            "max_abs_diff": max((d for _, d in ratio_diffs), default=0.0),
            "disagreeing_record_ids": [rid for rid, _ in ratio_diffs],
        },
        "disjointness": {
            "checked": True,
            "against": "default/dev (n=50)",
            "disjoint": check["disjoint"],
            "verified": check["verified"],
            "shared_samples": check["shared_samples"],
            "errors": check["errors"],
            "segment_hashes_shared": len(shared_segments),
            "shared_segment_word_counts": shared_word_counts,
        },
        "segments_train": _slice_metrics(train_segments),
        "segments_dev_replication": _slice_metrics(dev_segments),
        "segments_by_version": {
            version: _slice_metrics([s for s in train_segments if s["version"] == version])
            for version in sorted({s["version"] for s in train_segments})
        },
        "segments_by_operation": {
            op: _slice_metrics([s for s in train_segments if s["operation"] == op])
            for op in sorted({s["operation"] for s in train_segments})
        },
        "segments_by_length": {
            band: _slice_metrics([s for s in train_segments if _length_band(s["n_words"]) == band])
            for band in ("<20 (never verdicted)", "20-49", "50+")
        },
        "segments_by_domain": {
            domain: _slice_metrics([s for s in train_segments if s["domain"] == domain])
            for domain in sorted({s["domain"] for s in train_segments})
        },
        "segmentation_fidelity_train": _segmentation_fidelity(train_rows),
        "operation_hypothesis_train": _operation_accuracy(
            train_rows,
            covered_regimes={
                ("en", d) for d in sorted({str(r.meta.get("domain")) for r in train_rows})
            },
        ),
    }
    results["mean_score_by_label"] = {
        "human": {
            "n": sum(1 for s in train_segments if s["label"] == 0),
            "mean": round(
                statistics.fmean([s["score"] for s in train_segments if s["label"] == 0]),
                4,
            ),
        },
        "machine": {
            "n": sum(1 for s in train_segments if s["label"] == 1),
            "mean": round(
                statistics.fmean([s["score"] for s in train_segments if s["label"] == 1]),
                4,
            ),
        },
    }

    drops = [
        {
            "item": "full-corpus evaluation",
            "reason": "preliminary sample only (n=500 strided train rows of 196,029)",
        },
        {
            "item": "ai→human direction",
            "reason": "no data source covers it: every OpAI-Bench row is human→ai, so those cells are unknown",
        },
        {
            "item": "population slicing",
            "reason": "no population-labelled source exists; the human-slice segment FPR is pooled by domain only, never by population",
        },
        {
            "item": "dedicated adversarial-paraphrase attack slice",
            "reason": "no paraphrase generator exists in core; the paraphrase/style operations are the boundary-blurring edits in effect",
        },
        {
            "item": "per-sentence probabilities",
            "reason": "segment scores are evidence scores, never sentence authorship probabilities; no threshold was fitted",
        },
        {
            "item": "dev-50 replication pooling",
            "reason": "the dev slice is reported separately as a replication, not pooled into the train metrics",
        },
        {
            "item": "ratio/label agreement",
            "reason": (
                "6/500 train rows have mean(sentence_labels) != ai_sentence_ratio "
                "(max |diff| 0.032, all intermediate versions): the ratio and the "
                "labels were computed on slightly different segmentations; the "
                "labels are the segment ground truth and the ratio is the "
                "document summary, each used for its own purpose"
            ),
        },
        {
            "item": "segment precision/F1 at the declared operating point",
            "reason": (
                "no train segment scores >= 0.68, so no AI prediction "
                "exists: precision and F1 are undefined (recorded as null), "
                "recall is 0.0; the builtin heuristic never fires ai_like "
                "on sentences at the document operating point — see "
                "results.segments_train.precision_recall_f1"
            ),
        },
        {
            "item": "document-cache rewrite",
            "reason": "the segment caches are separate files (train-segments.jsonl); the U1 document record's cited cache hash is preserved",
        },
    ]
    record_id = f"EV-{run_date}-dataset-opai-bench-segments"
    record = _base_record(record_id, "command", "python scripts/measure_segments.py")
    record["results"] = results
    record["drops"] = drops
    record["badge"] = "available"
    _write_record(record, force)
    rebuild_registry()

    if not skip_record:
        build_segment_record(run_date=run_date)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="replace the existing artifact")
    parser.add_argument(
        "--run-date",
        default=date.today().strftime("%Y%m%d"),
        help="YYYYMMDD stamp for the artifact filename (default: today)",
    )
    parser.add_argument(
        "--skip-record",
        action="store_true",
        help="write the run artifact only; do not build/append the U1 segment record",
    )
    args = parser.parse_args()
    results = measure_segments(
        force=args.force, run_date=args.run_date, skip_record=args.skip_record
    )
    pooled = results["segments_train"]
    print(
        f"[opai_bench_segments] pooled train: n={pooled['n_segments']} segments, "
        f"AUROC {pooled['auroc']['value']} "
        f"[{pooled['auroc']['ci_lower']}, {pooled['auroc']['ci_upper']}], "
        f"F1 {pooled['prf1_at_operating_point']['f1']} "
        f"(P {pooled['prf1_at_operating_point']['precision']}, "
        f"R {pooled['prf1_at_operating_point']['recall']}), "
        f"native FPR {pooled['fpr_native']['value']}, "
        f"coverage {pooled['coverage']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
