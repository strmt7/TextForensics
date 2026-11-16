#!/usr/bin/env python3
"""build_w8e_ood_short_refusal_run_artifact.py — W8 worker E, 2026-11-16.

Measures the deterministic builtin-heuristic detector at its native
operating point on three probe sets that the six registry corpora do
NOT cover, and verifies the refusal/abstention contract end to end:

1. OUT-OF-DOMAIN: 66 original human-authored texts (11 slices x 6)
   in languages/domains absent from RAID, MAGE, Beemo, DetectRL-X,
   GhostWriter and OpAI-Bench (see scripts/w8e_ood_corpus.py for the
   coverage rationale). All are human-side, so any ``ai_like`` verdict
   is a false positive. Per-slice FPR with Wilson 95% CI.
2. SYNTHETIC TEMPLATE PROBE (labelled, NOT a TPR claim): 30
   programmatically generated formulaic English texts (seeded RNG).
   They are NOT LLM output; they test whether the detector fires on
   formulaic prose. Reported as a stress probe only.
3. SHORT TEXT: cached rows from the six document caches, truncated
   to 5/10/20/40/60/80/120/200 words (deterministic first-N-words
   truncation) plus full length. Per-budget, per-slice FPR/TPR,
   abstention rate, AUROC and AUPRC on the native score.
4. REFUSAL / ABSTENTION: empty/whitespace/non-string/oversize/binary
   inputs at the engine, detector, execute_detector, config-validation,
   HTTP API (TestClient) and CLI layers; plus end-to-end checks that
   an abstention is recorded as ``abstain`` (detector), as
   ``insufficient_evidence`` (engine) and in the forensic bundle's
   completeness accounting — never as a verdict.

No threshold is tuned, no baseline is grown, no failing case is
dropped. A negative result stays a negative result.

Usage:
    python scripts/build_w8e_ood_short_refusal_run_artifact.py [--check]
    python scripts/build_w8e_ood_short_refusal_run_artifact.py --output <path>
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import platform
import random
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from textforensics.config import Settings, validate_text_input  # noqa: E402
from textforensics.datasets import cache_path, get_spec, read_sample_cache  # noqa: E402
from textforensics.detectors import (  # noqa: E402
    BuiltinHeuristicDetector,
    execute_detector,
)
from textforensics.engine import analyze_text  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402
from w8e_ood_corpus import OOD_SLICES  # noqa: E402

RUN_DATE = "2026-11-16"
ARTIFACT_ID = "EV-20261116-ood-short-refusal"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"
Z_95 = 1.96
WILSON_METHOD = "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci"
NATIVE_OPERATING_POINT = "builtin-heuristic native verdict (analyze_text); no score threshold"
SHORT_BUDGETS = [5, 10, 20, 40, 60, 80, 120, 200]
SHORT_CAP_PER_CLASS = 200
TEMPLATE_SEED = 20261116

DROPS = [
    {
        "item": "OOD AI-side (TPR) measurement",
        "reason": (
            "no local LLM generator is available in this environment "
            "(no ollama, no API keys) and PAN 2025 is an explicit gap; "
            "genuine out-of-domain AI text could not be obtained, so no "
            "OOD TPR is claimed. The synthetic-template probe is a "
            "formulaic-prose stress test only, not a TPR measurement."
        ),
    },
    {
        "item": "German/French/Spanish as out-of-domain languages",
        "reason": (
            "DetectRL-X covers de/fr/es (and GhostWriter covers de); "
            "those languages are in-domain for at least one registry "
            "slice, so Italian and Japanese were used instead."
        ),
    },
    {
        "item": "Python versions other than the run's own",
        "reason": "measured on the local interpreter only; CI covers the matrix",
    },
    {
        "item": "Threshold tuning on any probe set",
        "reason": (
            "the native operating point is used throughout; a negative "
            "result is reported as a negative result, never tuned around"
        ),
    },
]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _code_version() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _round6(value: float | None) -> float | None:
    return None if value is None else round(float(value), 6)


def rate_with_ci(k: int, n: int) -> dict:
    lower, upper = wilson_ci(k, n, z=Z_95)
    return {
        "k": k,
        "n": n,
        "value": _round6(k / n) if n else None,
        "ci_lower": _round6(lower),
        "ci_upper": _round6(upper),
        "method": WILSON_METHOD,
    }


# ---------------------------------------------------------------------------
# AUROC / AUPRC from scratch (no sklearn in the environment).
# AUROC: Mann-Whitney U with 0.5 credit for ties.
# AUPRC: average precision with the step (sklearn average_precision_score)
# convention: precision at each true-positive threshold, weighted by the
# recall gain. Both are pure functions of (score, label) pairs.
# ---------------------------------------------------------------------------


def auroc(scores: list[float], labels: list[int]) -> float:
    pos = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    neg = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not pos or not neg:
        raise ValueError("auroc needs both classes present")
    wins = 0.0
    for p in pos:
        for q in neg:
            if p > q:
                wins += 1.0
            elif p == q:
                wins += 0.5
    return wins / (len(pos) * len(neg))


def auprc(scores: list[float], labels: list[int]) -> float:
    order = sorted(range(len(scores)), key=lambda i: (-scores[i], i))
    n_pos = sum(labels)
    if n_pos == 0:
        raise ValueError("auprc needs at least one positive")
    tp = fp = 0
    prev_recall = 0.0
    ap = 0.0
    for i in order:
        if labels[i] == 1:
            tp += 1
            recall = tp / n_pos
            precision = tp / (tp + fp)
            ap += (recall - prev_recall) * precision
            prev_recall = recall
        else:
            fp += 1
    return ap


def _self_test_metrics() -> list[str]:
    """Sanity checks of the from-scratch AUROC/AUPRC on known cases."""
    problems: list[str] = []
    # Perfect separation.
    if abs(auroc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]) - 1.0) > 1e-12:
        problems.append("auroc perfect separation != 1.0")
    if abs(auprc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]) - 1.0) > 1e-12:
        problems.append("auprc perfect separation != 1.0")
    # Perfectly reversed.
    if abs(auroc([0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0]) - 0.0) > 1e-12:
        problems.append("auroc reversed separation != 0.0")
    # All ties -> 0.5.
    if abs(auroc([0.5, 0.5, 0.5, 0.5], [1, 1, 0, 0]) - 0.5) > 1e-12:
        problems.append("auroc all-ties != 0.5")
    # Known AP: positives ranked 1st and 3rd of 4 -> AP = (1/1 + 2/3)/2.
    expect = (1.0 + 2.0 / 3.0) / 2.0
    if abs(auprc([0.9, 0.8, 0.7, 0.1], [1, 0, 1, 0]) - expect) > 1e-12:
        problems.append(f"auprc known case != {expect}")
    # Wilson sanity: k=0, n=200 upper must be 0.018846 (registry value).
    _, upper = wilson_ci(0, 200, z=1.96)
    if abs(upper - 0.018846) > 1e-6:
        problems.append(f"wilson_ci(0,200) upper {upper} != 0.018846")
    return problems


# ---------------------------------------------------------------------------
# Synthetic template probe (seeded, deterministic, NOT LLM output).
# ---------------------------------------------------------------------------

_TEMPLATE_OPENERS = [
    "In today's fast-paced world, it is important to consider the many factors that shape our daily lives and influence the choices we make.",
    "There are several key reasons why this topic deserves careful attention from anyone who wants to understand the bigger picture.",
    "When we look at the evidence as a whole, a clear pattern begins to emerge that cannot be ignored by serious observers.",
    "It is widely recognised that progress in this area depends on cooperation, planning and a willingness to adapt to new circumstances.",
    "One of the most significant developments in recent years has been the growing awareness of how interconnected our systems really are.",
]
_TEMPLATE_MIDDLES = [
    "First, the available data suggests that early action tends to produce better outcomes than waiting for the situation to resolve itself.",
    "Second, experts increasingly agree that a balanced approach, combining caution with ambition, offers the most reliable path forward.",
    "Third, the experience of other communities shows that small, consistent steps often matter more than dramatic gestures.",
    "Moreover, it is essential to remember that every decision carries trade-offs, and that no single solution will work in every context.",
    "In addition, recent studies indicate that transparency and open communication help to build the trust on which lasting results depend.",
    "Finally, it is worth noting that the challenges we face today are not entirely new, and that earlier generations found ways to meet them.",
]
_TEMPLATE_CLOSERS = [
    "In conclusion, the way forward is clear: act thoughtfully, measure the results, and remain open to changing course when the facts demand it.",
    "Ultimately, the question is not whether change will come, but whether we will be ready for it when it arrives.",
    "Taken together, these points make a strong case for a measured, evidence-based approach that puts long-term stability ahead of short-term gain.",
    "The lesson is simple, and it is one worth repeating: careful preparation today prevents far greater difficulty tomorrow.",
]


def build_template_texts(n: int = 30, *, seed: int = TEMPLATE_SEED) -> list[str]:
    rng = random.Random(seed)
    texts: list[str] = []
    for _ in range(n):
        parts = [rng.choice(_TEMPLATE_OPENERS)]
        middles = rng.sample(_TEMPLATE_MIDDLES, k=rng.randint(3, 5))
        parts.extend(middles)
        parts.append(rng.choice(_TEMPLATE_CLOSERS))
        # Pad to ~130-170 words with a second opener/middle round if short.
        while len(" ".join(parts).split()) < 130:
            parts.insert(len(parts) - 1, rng.choice(_TEMPLATE_MIDDLES))
        texts.append(" ".join(parts))
    return texts


# ---------------------------------------------------------------------------
# Out-of-domain measurement.
# ---------------------------------------------------------------------------


def measure_ood(detector: BuiltinHeuristicDetector) -> dict:
    slices: list[dict] = []
    all_items: list[dict] = []
    for slice_id, texts in OOD_SLICES.items():
        items: list[dict] = []
        for idx, text in enumerate(texts):
            pred = detector.detect(text)
            # Cross-check via the engine directly: same deterministic
            # score, plus the engine-reported word_count (the detector
            # prediction carries no word_count field of its own).
            engine_result = analyze_text(text)
            if engine_result.score != pred.score:
                raise ValueError(
                    f"{slice_id}-{idx + 1}: detector score {pred.score} != "
                    f"engine score {engine_result.score}"
                )
            items.append(
                {
                    "item_id": f"{slice_id}-{idx + 1}",
                    "text_sha256": _sha256_text(text),
                    "whitespace_words": len(text.split()),
                    "detector_word_count": engine_result.word_count,
                    "engine_verdict": engine_result.verdict,
                    "score": pred.score,
                    "verdict": pred.verdict,
                    "reliability": pred.reliability,
                    "warnings": list(pred.warnings),
                }
            )
        k_fp = sum(1 for it in items if it["verdict"] == "ai_like")
        k_abstain = sum(1 for it in items if it["verdict"] == "abstain")
        k_human = sum(1 for it in items if it["verdict"] == "human_like")
        scores = [it["score"] for it in items]
        slices.append(
            {
                "slice_id": slice_id,
                "n": len(items),
                "label": "human (original, authored for this probe)",
                "k_ai_like": k_fp,
                "k_human_like": k_human,
                "k_abstain": k_abstain,
                "fpr_native_wilson": rate_with_ci(k_fp, len(items)),
                "abstention_rate": _round6(k_abstain / len(items)),
                "mean_score": _round6(sum(scores) / len(scores)),
                "min_score": _round6(min(scores)),
                "max_score": _round6(max(scores)),
                "items": items,
            }
        )
        all_items.extend(items)
    pooled_k = sum(s["k_ai_like"] for s in slices)
    pooled_n = sum(s["n"] for s in slices)
    pooled_abstain = sum(s["k_abstain"] for s in slices)
    return {
        "slices": slices,
        "pooled": {
            "k_ai_like": pooled_k,
            "n": pooled_n,
            "fpr_native_wilson": rate_with_ci(pooled_k, pooled_n),
            "k_abstain": pooled_abstain,
            "abstention_rate": _round6(pooled_abstain / pooled_n),
        },
    }


def measure_template_probe(detector: BuiltinHeuristicDetector) -> dict:
    texts = build_template_texts()
    items: list[dict] = []
    for idx, text in enumerate(texts):
        pred = detector.detect(text)
        engine_result = analyze_text(text)
        if engine_result.score != pred.score:
            raise ValueError(
                f"template-{idx + 1}: detector score {pred.score} != "
                f"engine score {engine_result.score}"
            )
        items.append(
            {
                "item_id": f"template-{idx + 1}",
                "text_sha256": _sha256_text(text),
                "whitespace_words": len(text.split()),
                "detector_word_count": engine_result.word_count,
                "engine_verdict": engine_result.verdict,
                "score": pred.score,
                "verdict": pred.verdict,
                "reliability": pred.reliability,
            }
        )
    n = len(items)
    return {
        "n": n,
        "seed": TEMPLATE_SEED,
        "label": (
            "SYNTHETIC formulaic template text (seeded RNG stitching of "
            "fixed sentences). NOT LLM output. Stress probe only; no TPR "
            "claim is made or implied."
        ),
        "k_ai_like": sum(1 for it in items if it["verdict"] == "ai_like"),
        "k_human_like": sum(1 for it in items if it["verdict"] == "human_like"),
        "k_abstain": sum(1 for it in items if it["verdict"] == "abstain"),
        "rate_ai_like": rate_with_ci(
            sum(1 for it in items if it["verdict"] == "ai_like"), n
        ),
        "abstention_rate": _round6(
            sum(1 for it in items if it["verdict"] == "abstain") / n
        ),
        "mean_score": _round6(sum(it["score"] for it in items) / n),
        "min_score": _round6(min(it["score"] for it in items)),
        "max_score": _round6(max(it["score"] for it in items)),
        "items": items,
    }


# ---------------------------------------------------------------------------
# Short-text measurement.
# ---------------------------------------------------------------------------

SHORT_SLICES = [
    {"key": "raid", "config": "raid", "split": "train"},
    {"key": "mage", "config": "default", "split": "train"},
    {"key": "beemo", "config": "default", "split": "train"},
    {"key": "detectrl_x", "config": "binary", "split": "train"},
    {"key": "ghostwriter", "config": "default", "split": "train"},
    {"key": "opai_bench", "config": "default", "split": "train"},
]


def _truncate_words(text: str, budget: int) -> str:
    return " ".join(text.split()[:budget])


def measure_short_text(detector: BuiltinHeuristicDetector) -> dict:
    slices: list[dict] = []
    for slice_def in SHORT_SLICES:
        spec = get_spec(slice_def["key"])
        cache_file = cache_path(spec.key, slice_def["config"], slice_def["split"])
        rows = read_sample_cache(spec, slice_def["config"], slice_def["split"])
        labelled = [r for r in rows if r.label in (0, 1)]
        # Deterministic sample: sort by source_id, first N per class.
        humans = sorted(
            (r for r in labelled if int(r.label) == 0), key=lambda r: str(r.source_id)
        )[:SHORT_CAP_PER_CLASS]
        ais = sorted(
            (r for r in labelled if int(r.label) == 1), key=lambda r: str(r.source_id)
        )[:SHORT_CAP_PER_CLASS]
        sample = humans + ais
        budgets: list[dict] = []
        for budget in SHORT_BUDGETS + ["full"]:
            scores: list[float] = []
            labels: list[int] = []
            k_fp = k_tp = k_abstain = 0
            n_human = n_ai = 0
            for row in sample:
                text = row.text if budget == "full" else _truncate_words(row.text, budget)  # type: ignore[arg-type]
                pred = detector.detect(text)
                scores.append(float(pred.score))
                labels.append(int(row.label))
                if int(row.label) == 0:
                    n_human += 1
                    if pred.verdict == "ai_like":
                        k_fp += 1
                else:
                    n_ai += 1
                    if pred.verdict == "ai_like":
                        k_tp += 1
                if pred.verdict == "abstain":
                    k_abstain += 1
            budgets.append(
                {
                    "budget_words": budget,
                    "n_human": n_human,
                    "n_ai": n_ai,
                    "fpr_native_wilson": rate_with_ci(k_fp, n_human),
                    "tpr_native_wilson": rate_with_ci(k_tp, n_ai),
                    "abstentions": k_abstain,
                    "abstention_rate": _round6(k_abstain / (n_human + n_ai)),
                    "auroc": _round6(auroc(scores, labels)),
                    "auprc": _round6(auprc(scores, labels)),
                    "mean_score_human": _round6(
                        sum(s for s, y in zip(scores, labels, strict=True) if y == 0)
                        / n_human
                    ),
                    "mean_score_ai": _round6(
                        sum(s for s, y in zip(scores, labels, strict=True) if y == 1) / n_ai
                    ),
                }
            )
        slices.append(
            {
                "dataset": slice_def["key"],
                "config": slice_def["config"],
                "split": slice_def["split"],
                "cache_file": str(cache_file),
                "cache_file_sha256": _sha256_file(cache_file),
                "cache_rows_total": len(rows),
                "cache_rows_labelled": len(labelled),
                "sample_n_human": len(humans),
                "sample_n_ai": len(ais),
                "sample_rule": (
                    "deterministic: rows sorted by source_id, first "
                    f"{SHORT_CAP_PER_CLASS} per class"
                ),
                "truncation": "first-N whitespace words; 'full' is the untruncated row text",
                "budgets": budgets,
            }
        )
    return {"slices": slices}


# ---------------------------------------------------------------------------
# Refusal / abstention contract.
# ---------------------------------------------------------------------------


#: Keys that are nondeterministic per run (wall-clock timing, random
#: request ids, generation timestamps). They are scrubbed from every
#: recorded value so the artifact is reproducible: two runs of this
#: script must produce byte-identical ``results``.
NONDETERMINISTIC_KEYS = {"runtime_ms", "request_id", "generated_at_utc"}


def _scrub(value):
    if isinstance(value, dict):
        return {
            key: _scrub(item)
            for key, item in value.items()
            if key not in NONDETERMINISTIC_KEYS
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


def _call_outcome(fn, *args, **kwargs) -> dict:
    """Run fn(*args); record raised vs returned, never propagating."""
    try:
        result = fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - the exception IS the datum
        return {
            "outcome": "raised",
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
        }
    if isinstance(result, tuple) and len(result) == 2:
        pred, failure = result
        return {
            "outcome": "returned",
            "prediction": None if pred is None else _scrub(pred.to_dict()),
            "failure": None if failure is None else _scrub(failure.to_dict()),
        }
    if hasattr(result, "to_dict"):
        return {"outcome": "returned", "value": _scrub(result.to_dict())}
    return {"outcome": "returned", "value": repr(result)[:500]}


def measure_refusals() -> dict:
    detector = BuiltinHeuristicDetector()
    cases: list[dict] = []

    def add(layer: str, case_id: str, fn, *args, **kwargs):
        cases.append({"layer": layer, "case": case_id, **_call_outcome(fn, *args, **kwargs)})

    # Engine layer: analyze_text raises on empty / non-string.
    add("engine:analyze_text", "empty_string", analyze_text, "")
    add("engine:analyze_text", "whitespace_only", analyze_text, "   \n\t  ")
    add("engine:analyze_text", "none", analyze_text, None)
    add("engine:analyze_text", "int", analyze_text, 123)
    add("engine:analyze_text", "bytes", analyze_text, b"hello world")
    add("engine:analyze_text", "list", analyze_text, ["hello world"])
    # Detector layer: detect() propagates the same refusal (no verdict).
    add("detector:detect", "empty_string", detector.detect, "")
    add("detector:detect", "whitespace_only", detector.detect, "   ")
    add("detector:detect", "none", detector.detect, None)
    add("detector:detect", "int", detector.detect, 123)
    # Short-but-valid input abstains (verdict, not an error).
    add(
        "detector:detect",
        "two_words",
        detector.detect,
        "Hello world, this is a test.",
    )
    add(
        "detector:detect",
        "eighty_words_exact",
        detector.detect,
        " ".join(["word"] * 80),
    )
    # execute_detector converts a detector raise into a failure record.
    add("execute_detector", "empty_string", execute_detector, detector, "")
    add(
        "execute_detector",
        "short_text",
        execute_detector,
        detector,
        "Hello world, this is a test.",
    )
    # Config validation layer.
    add(
        "config:validate_text_input",
        "empty_string",
        validate_text_input,
        "",
        max_input_bytes=Settings().max_input_bytes,
    )
    add(
        "config:validate_text_input",
        "none",
        validate_text_input,
        None,
        max_input_bytes=Settings().max_input_bytes,
    )
    add(
        "config:validate_text_input",
        "oversize",
        validate_text_input,
        "x" * (Settings().max_input_bytes + 1),
        max_input_bytes=Settings().max_input_bytes,
    )
    add(
        "config:validate_text_input",
        "at_limit",
        validate_text_input,
        "x" * Settings().max_input_bytes,
        max_input_bytes=Settings().max_input_bytes,
    )

    # HTTP API layer via TestClient (in-process; no network).
    api_cases: list[dict] = []
    try:
        from fastapi.testclient import TestClient

        from textforensics.api import create_app

        client = TestClient(create_app(), raise_server_exceptions=False)
        for case_id, payload in [
            ("empty_string", {"text": ""}),
            ("whitespace_only", {"text": "   "}),
            ("missing_text_field", {}),
            ("short_text", {"text": "Hello world, this is a test."}),
        ]:
            resp = client.post("/v1/analyze", json=payload)
            try:
                body = _scrub(resp.json())
            except Exception:  # noqa: BLE001
                body = resp.text[:500]
            api_cases.append(
                {
                    "layer": "api:/v1/analyze",
                    "case": case_id,
                    "http_status": resp.status_code,
                    "body": body,
                }
            )
        resp = client.post("/v1/report", json={"text": ""})
        api_cases.append(
            {
                "layer": "api:/v1/report",
                "case": "empty_string",
                "http_status": resp.status_code,
                "body": _scrub(resp.json())
                if resp.headers.get("content-type", "").startswith("application/json")
                else resp.text[:500],
            }
        )
    except Exception as exc:  # noqa: BLE001 - record, do not fail the run
        api_cases.append(
            {"layer": "api", "case": "testclient_unavailable", "error": f"{type(exc).__name__}: {exc}"}
        )

    # CLI layer via subprocess (canonical venv python).
    cli_cases: list[dict] = []
    cli_python = str(Path.home() / "workspace" / "TextForensics-rewrite" / ".venv" / "bin" / "python3")
    with tempfile.TemporaryDirectory() as tmp:
        binary_path = Path(tmp) / "binary.bin"
        binary_path.write_bytes(b"\xff\xfe\x00\x01 not utf-8 \x80\x81")
        for case_id, argv in [
            ("empty_text", ["-m", "textforensics.cli", "scan", "--text", "", "--json"]),
            ("short_text", ["-m", "textforensics.cli", "scan", "--text", "Hello world, this is a test.", "--json"]),
            ("binary_file", ["-m", "textforensics.cli", "scan", "--file", str(binary_path), "--json"]),
        ]:
            proc = subprocess.run(
                [cli_python, *argv],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=120,
            )
            stdout = proc.stdout.strip()
            try:
                parsed = json.loads(stdout) if stdout else None
            except json.JSONDecodeError:
                parsed = None
            cli_cases.append(
                {
                    "layer": "cli:scan",
                    "case": case_id,
                    "exit_code": proc.returncode,
                    "stderr": proc.stderr.strip()[:500],
                    "stdout_is_json": parsed is not None,
                    "stdout_verdict": (parsed or {}).get("verdict") if isinstance(parsed, dict) else None,
                    "stdout_head": stdout[:300],
                }
            )

    # Abstention recording end to end: forensic bundle on short text.
    bundle_case: dict = {}
    try:
        from textforensics.report import build_forensic_bundle

        short_text = "Hello world, this is a test of the abstention path."
        bundle = build_forensic_bundle(short_text)
        bundle_dict = bundle.to_dict()
        detector_rows = bundle_dict.get("detector_results", [])
        bundle_case = {
            "layer": "bundle:build_forensic_bundle",
            "case": "short_text",
            "outcome": "returned",
            "detector_results": _scrub(detector_rows),
            "detector_failures": _scrub(bundle_dict.get("detector_failures", [])),
            "consensus_verdict": (bundle_dict.get("consensus") or {}).get("verdict"),
            "completeness": _scrub(bundle_dict.get("completeness")),
            "trust_map_state": _scrub(bundle_dict.get("trust_map") or {}),
        }
    except Exception as exc:  # noqa: BLE001 - record, do not fail the run
        bundle_case = {
            "layer": "bundle:build_forensic_bundle",
            "case": "short_text",
            "outcome": "raised",
            "exception_type": type(exc).__name__,
            "exception_message": str(exc)[:500],
        }

    return {"cases": cases, "api_cases": api_cases, "cli_cases": cli_cases, "bundle_case": bundle_case}


# ---------------------------------------------------------------------------
# Determinism re-run (OOD only; short-text determinism follows from the
# same pure detector, spot-checked on one budget per slice in the report).
# ---------------------------------------------------------------------------


def check_ood_determinism(first: dict) -> dict:
    detector = BuiltinHeuristicDetector()
    mismatches: list[str] = []
    checked = 0
    for slice_data in first["slices"]:
        slice_id = slice_data["slice_id"]
        for item in slice_data["items"]:
            idx = int(item["item_id"].rsplit("-", 1)[1]) - 1
            text = OOD_SLICES[slice_id][idx]
            pred = detector.detect(text)
            checked += 1
            if pred.score != item["score"] or pred.verdict != item["verdict"]:
                mismatches.append(
                    f"{item['item_id']}: first (score={item['score']}, "
                    f"verdict={item['verdict']}) != rerun (score={pred.score}, "
                    f"verdict={pred.verdict})"
                )
    return {"items_checked": checked, "mismatches": mismatches}


def validate_run_artifact(artifact: dict) -> list[str]:
    check_claims = _load_module(
        "check_claims_for_validation", REPO_ROOT / "scripts" / "check_claims.py"
    )
    schema = check_claims._load_schema(REPO_ROOT, "run-artifact.schema.json")
    return check_claims._schema_errors(schema, artifact)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="measure and validate only; write nothing")
    parser.add_argument("--output", default=None, help="artifact path")
    args = parser.parse_args(argv)

    problems = _self_test_metrics()
    if problems:
        print("METRIC SELF-TEST FAILURE:", file=sys.stderr)
        for item in problems:
            print(f"  - {item}", file=sys.stderr)
        return 2

    detector = BuiltinHeuristicDetector()
    print("measuring out-of-domain slices ...", flush=True)
    ood = measure_ood(detector)
    print("measuring synthetic template probe ...", flush=True)
    template = measure_template_probe(detector)
    print("checking OOD determinism (full re-run) ...", flush=True)
    determinism = check_ood_determinism(ood)
    print("measuring short text ...", flush=True)
    short = measure_short_text(detector)
    print("measuring refusal / abstention contract ...", flush=True)
    refusals = measure_refusals()

    env_lock: dict = {"platform": platform.system(), "python": platform.python_version()}
    try:
        freeze = subprocess.run(
            [
                str(Path.home() / "workspace" / "TextForensics-rewrite" / ".venv" / "bin" / "pip"),
                "freeze",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        env_lock["extras"] = freeze.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        env_lock["extras"] = f"pip freeze unavailable: {exc}"

    artifact = {
        "schema": RUN_ARTIFACT_SCHEMA,
        "evidence_record_id": ARTIFACT_ID,
        "kind": "command",
        "command": "python scripts/build_w8e_ood_short_refusal_run_artifact.py",
        "environment": env_lock,
        "code_version": _code_version(),
        "run_date": RUN_DATE,
        "results": {
            "detector": detector.detector_id,
            "detector_family": detector.detector_family,
            "detector_version": detector.detector_version,
            "operating_point": NATIVE_OPERATING_POINT,
            "method": (
                "Deterministic builtin-heuristic detector at its native "
                "operating point over (a) 66 original human-authored "
                "out-of-domain texts in 11 slices, (b) 30 seeded "
                "synthetic formulaic-template texts (stress probe only, "
                "not LLM output, no TPR claim), (c) cached rows of the "
                "six document caches truncated to 5/10/20/40/60/80/120/200 "
                "words plus full length (deterministic source_id-sorted "
                "sample, max 200 per class per slice), and (d) a refusal "
                "matrix across engine/detector/execute_detector/config/API/"
                "CLI/bundle layers. Rates are Wilson 95% CIs (z=1.96). "
                "AUROC is Mann-Whitney U with 0.5 for ties; AUPRC is "
                "step average precision. Both are computed from scratch "
                "in this script (no sklearn) and self-tested on known cases."
            ),
            "ood_corpus_sha256": _sha256_file(REPO_ROOT / "scripts" / "w8e_ood_corpus.py"),
            "ood": ood,
            "synthetic_template_probe": template,
            "ood_determinism": determinism,
            "short_text": short,
            "refusals": refusals,
        },
        "drops": DROPS,
        "badge": "available",
        "detector_version": detector.detector_version,
        "notes": (
            "W8 worker E qualification probe. Out-of-domain and short-text "
            "results are measurements, not claims: per-slice n is small "
            "(n=6 per OOD slice), so Wilson uppers are wide and the "
            "pooled OOD number must not be read as a supported FPR claim. "
            "The lyrics slice is near-domain (RAID covers poetry) and is "
            "flagged as such. Japanese texts have no whitespace, so the "
            "detector's word counter sees 16-20 words per text (runs split "
            "by punctuation) instead of the ~140 whitespace words; the "
            "6/6 abstention on that slice is a length-gate effect on a "
            "spaceless script, not a language judgement. The same "
            "whitespace-word artefact affects the short-text truncation: "
            "49 of the 400 sampled DetectRL-X rows are Chinese with fewer "
            "than 20 whitespace words at full length, so truncating them "
            "to a 5/10/20-word budget keeps the full (long) text and they "
            "receive normal verdicts — that is why DetectRL-X abstention "
            "is 0.963/0.948/0.905 at the 5/10/20-word budgets instead of "
            "1.000. A whitespace-word budget is not a length control for "
            "spaceless scripts; the DetectRL-X small-budget numbers must "
            "be read with that caveat. No threshold was tuned; no failing "
            "case was dropped."
        ),
    }

    errors = validate_run_artifact(artifact)
    print(f"ood slices: {len(ood['slices'])}, pooled FPR k={ood['pooled']['k_ai_like']}/{ood['pooled']['n']}")
    print(f"template probe: k_ai_like={template['k_ai_like']}/{template['n']}")
    print(f"ood determinism: {determinism['items_checked']} checked, {len(determinism['mismatches'])} mismatches")
    print(f"short-text slices: {len(short['slices'])}")
    print(f"refusal cases: {len(refusals['cases'])} + {len(refusals['api_cases'])} api + {len(refusals['cli_cases'])} cli")
    print(f"run-artifact/v1 validation errors: {len(errors)}")
    for error in errors:
        print(f"  - {error}")
    if errors:
        return 2
    if determinism["mismatches"]:
        print("DETERMINISM FAILURE", file=sys.stderr)
        for item in determinism["mismatches"]:
            print(f"  - {item}", file=sys.stderr)
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
