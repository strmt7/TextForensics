from __future__ import annotations

import json
from pathlib import Path

from .engine import analyze_text


def benchmark_jsonl(path: str | Path, threshold: float = 0.5) -> dict:
    tp = fp = tn = fn = 0
    total = 0
    failures = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        label = str(row["label"]).strip().lower()
        if label not in {"human", "ai"}:
            failures += 1
            continue
        score = analyze_text(str(row["text"]), include_robustness=False).score
        pred = "ai" if score >= threshold else "human"
        total += 1
        if label == "ai" and pred == "ai":
            tp += 1
        elif label == "ai" and pred == "human":
            fn += 1
        elif label == "human" and pred == "ai":
            fp += 1
        else:
            tn += 1

    accuracy = (tp + tn) / total if total else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "threshold": threshold,
        "evaluated": total,
        "skipped": failures,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "warning": "Built-in v0.1 analyzers are heuristic baselines, not a validated production detector.",
    }


def _load_scores(path: str | Path) -> list[tuple[str, float]]:
    rows: list[tuple[str, float]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        label = str(row["label"]).strip().lower()
        if label not in {"human", "ai"}:
            continue
        score = analyze_text(str(row["text"]), include_robustness=False).score
        rows.append((label, score))
    return rows


def calibrate_threshold_jsonl(path: str | Path, target_fpr: float = 0.01) -> dict:
    if not 0 <= target_fpr <= 1:
        raise ValueError("target_fpr must be between 0 and 1")
    rows = _load_scores(path)
    humans = [score for label, score in rows if label == "human"]
    ais = [score for label, score in rows if label == "ai"]
    if not humans or not ais:
        raise ValueError("Calibration requires at least one human and one AI sample.")

    candidates = sorted({0.0, 1.0, *(score for _, score in rows)})
    best = None
    for threshold in candidates:
        fp = sum(score >= threshold for score in humans)
        tp = sum(score >= threshold for score in ais)
        fpr = fp / len(humans)
        tpr = tp / len(ais)
        if fpr <= target_fpr:
            candidate = (tpr, -fpr, threshold)
            if best is None or candidate > best[0]:
                best = (candidate, threshold, fpr, tpr)

    if best is None:
        threshold, fpr, tpr = 1.0, 0.0, 0.0
    else:
        _, threshold, fpr, tpr = best
    return {
        "target_false_positive_rate": target_fpr,
        "recommended_threshold": round(float(threshold), 4),
        "observed_false_positive_rate": round(float(fpr), 4),
        "observed_true_positive_rate": round(float(tpr), 4),
        "human_samples": len(humans),
        "ai_samples": len(ais),
        "warning": "Threshold is valid only for data sufficiently similar to the calibration set.",
    }
