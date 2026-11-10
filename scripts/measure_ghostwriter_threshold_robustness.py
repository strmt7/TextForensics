#!/usr/bin/env python3
"""measure_ghostwriter_threshold_robustness.py — How close is the GhostWriter
human slice to a false positive, and what drives the near-threshold scores?

Threshold-robustness evidence, NOT a threshold change. The ``ai_like``
verdict threshold 0.68 is a detector operating point (AGENTS.md rule 17:
never lower a threshold to make a demo look better). This script measures
only:

* the distribution of the 137 human scores on the GhostWriter document
  slice (record ``evr-20261107-ghostwriter-builtin-heuristic``),
* how many human rows sit within 0.01 / 0.02 / 0.05 below 0.68,
* what the human FPR *would be* at perturbed thresholds 0.66 and 0.70
  (sensitivity analysis only — the verdict at a perturbed threshold is
  ``score >= T and diagnostic_reliability >= 0.28``, the same reliability
  gate the native verdict applies),
* which stylometric features drive the top scores (per-analyzer scores
  and the underlying features, read from the repo's own detector code —
  nothing is guessed),
* whether the near-threshold texts share characteristics (domain,
  language, length).

Method: the repo's own ``BuiltinHeuristicDetector.detect`` (i.e.
``analyze_text``) is re-run over the cached labelled rows, exactly as
``scripts/measure_human_fpr.py`` does. The cache SHA-256 is verified
against the registry record before measuring, and the re-run row counts
and abstention count must reproduce the registry / FPR artifact, or the
script raises instead of reporting a different sample. No raw text is
written anywhere: rows are identified by ``source_id`` and a truncated
SHA-256 of the text.

The headline result (2026-11-10 re-run) is fragile downward by exactly
one row: at 0.66 the 0.6740 row flips to a false positive (FPR 1/137),
at 0.68 and 0.70 the FPR stays 0/137. The threshold is UNCHANGED by this
work — the finding is reported, not acted on.

Usage:
    python scripts/measure_ghostwriter_threshold_robustness.py [--check]
    python scripts/measure_ghostwriter_threshold_robustness.py --output summary.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from textforensics.datasets import cache_path, get_spec, read_sample_cache  # noqa: E402
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.engine import analyze_text  # noqa: E402
from textforensics.features import extract_features  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402

RUN_DATE = "2026-11-10"
RECORD_ID = "evr-20261107-ghostwriter-builtin-heuristic"
DATASET_KEY = "ghostwriter"
CONFIG = "default"
SPLIT = "train"
EXPECTED_CACHE_SHA256 = "12d2ab690b8952d34cb8814231b332f96dbc565de6f2daf4af50d3a60df184c8"
NATIVE_THRESHOLD = 0.68
PERTURBED_THRESHOLDS = (0.66, 0.70)
RELIABILITY_FLOOR = 0.28
NEAR_THRESHOLD_FLOOR = 0.63
WILSON_METHOD = "Wilson score interval, 95% (z=1.96), textforensics.probe_metrics.wilson_ci"
# Features that feed the three builtin analyzers (see
# src/textforensics/analyzers.py): structural_uniformity reads the first
# three, formulaic_language the next three, lexical_profile the last three.
DRIVER_FEATURES = (
    "sentence_length_cv",
    "paragraph_length_cv",
    "repeated_sentence_start_ratio",
    "transition_density",
    "cliche_density",
    "repeated_trigram_ratio",
    "type_token_ratio",
    "hapax_ratio",
    "punctuation_variety",
)
ANALYZER_NAMES = (
    "structural_uniformity",
    "formulaic_language",
    "lexical_profile",
)


def quantile(sorted_values: list[float], p: float) -> float:
    """Linear-interpolation quantile of an already-sorted list. Pure."""
    if not sorted_values:
        raise ValueError("quantile of an empty list is undefined")
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"quantile p must be in [0, 1], got {p}")
    pos = (len(sorted_values) - 1) * p
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_values[lo]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def count_within_below(scores: list[float], threshold: float, delta: float) -> int:
    """Rows with ``threshold - delta <= score < threshold``. Pure."""
    if delta < 0:
        raise ValueError(f"delta must be >= 0, got {delta}")
    return sum(1 for s in scores if threshold - delta <= s < threshold)


def fpr_at_threshold(
    scores: list[float],
    reliabilities: list[float],
    threshold: float,
    *,
    z: float = 1.96,
) -> dict:
    """Verdict-equivalent human FPR at a perturbed score threshold.

    A row counts as a false positive at threshold ``T`` when its score
    is ``>= T`` *and* its diagnostic reliability clears the same 0.28
    floor the native verdict applies (``engine._verdict``). The native
    threshold is not special-cased: at T = 0.68 this reproduces the
    native verdict count. Pure function; the interval is Wilson 95%.
    """
    if len(scores) != len(reliabilities):
        raise ValueError("scores and reliabilities must have the same length")
    n = len(scores)
    k = sum(
        1
        for s, r in zip(scores, reliabilities, strict=True)
        if s >= threshold and r >= RELIABILITY_FLOOR
    )
    lower, upper = wilson_ci(k, n, z=z)
    return {
        "threshold": threshold,
        "k": k,
        "n": n,
        "rate": k / n if n else 0.0,
        "ci_lower": lower,
        "ci_upper": upper,
        "method": WILSON_METHOD,
    }


def analyzer_mean_scores(rows: list[dict]) -> dict[str, float]:
    """Mean per-analyzer score over the given (already scored) rows. Pure."""
    if not rows:
        raise ValueError("analyzer_mean_scores of an empty row list is undefined")
    return {
        name: statistics.mean(row["analyzers"][name] for row in rows) for name in ANALYZER_NAMES
    }


def feature_means(rows: list[dict]) -> dict[str, float]:
    """Mean of each driver feature over the given rows. Pure."""
    if not rows:
        raise ValueError("feature_means of an empty row list is undefined")
    return {
        name: statistics.mean(row["features"][name] for row in rows) for name in DRIVER_FEATURES
    }


def _round6(value: float) -> float:
    return round(float(value), 6)


def _registry_record(registry: dict, record_id: str) -> dict:
    for record in registry["records"]:
        if record["record_id"] == record_id:
            return record
    raise ValueError(f"record {record_id} not in docs/validation/registry.json")


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _code_version() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def measure_ghostwriter(*, cache_dir: Path | None = None) -> dict:
    """Re-run the detector over the GhostWriter labelled rows.

    Verifies the cache SHA-256 against the registry record and the
    re-run row counts / abstentions against the registry, then scores
    every human row (plus AI-side context) and returns the full
    deterministic summary. Raises on any mismatch instead of reporting
    a different sample.
    """
    registry = json.loads(
        (REPO_ROOT / "docs" / "validation" / "registry.json").read_text(encoding="utf-8")
    )
    record = _registry_record(registry, RECORD_ID)
    metric = record["metrics"][0]
    registry_sha = record["data"]["file_sha256"]
    if registry_sha != EXPECTED_CACHE_SHA256:
        raise ValueError(
            f"{RECORD_ID}: registry file_sha256 {registry_sha} != the "
            f"expected GhostWriter cache SHA-256 — refusing to measure "
            "against a moved registry"
        )
    spec = get_spec(DATASET_KEY)
    cache_file = cache_path(spec.key, CONFIG, SPLIT, cache_dir=cache_dir)
    if not cache_file.exists():
        raise ValueError(f"{RECORD_ID}: cache file missing: {cache_file}")
    cache_sha = _sha256_file(cache_file)
    if cache_sha != registry_sha:
        raise ValueError(
            f"{RECORD_ID}: cache SHA-256 {cache_sha} != registry "
            f"file_sha256 {registry_sha} for {cache_file} — refusing to "
            "measure a different sample than the registry record describes"
        )
    rows = read_sample_cache(spec, CONFIG, SPLIT, cache_dir=cache_dir)
    labelled = [row for row in rows if row.label is not None]
    detector = BuiltinHeuristicDetector()

    human_rows: list[dict] = []
    ai_scores: list[float] = []
    ai_single_paragraph = 0
    n_human = n_ai = abstentions = 0
    for row in labelled:
        prediction = detector.detect(row.text)
        score = float(prediction.score)
        reliability = float(prediction.reliability)
        if prediction.verdict == "abstain":
            abstentions += 1
        if int(row.label) == 0:
            n_human += 1
            features = extract_features(row.text)
            human_rows.append(
                {
                    "source_id": row.source_id,
                    "text_sha256": hashlib.sha256(row.text.encode()).hexdigest()[:16],
                    "score": round(score, 4),
                    "reliability": round(reliability, 4),
                    "verdict": prediction.verdict,
                    "words": int(features["word_count"]),
                    "domain": row.meta.get("domain"),
                    "lang": row.meta.get("lang"),
                    "analyzers": {item["analyzer"]: item["score"] for item in prediction.evidence},
                    "features": {name: round(float(features[name]), 4) for name in DRIVER_FEATURES},
                }
            )
        elif int(row.label) == 1:
            n_ai += 1
            ai_scores.append(score)
            if float(extract_features(row.text)["paragraph_length_cv"]) == 0.0:
                ai_single_paragraph += 1
        else:  # pragma: no cover - the registry sample has labels 0/1 only
            raise ValueError(f"{RECORD_ID}: unexpected label {row.label!r}")

    if n_human != metric["n_human"] or n_ai != metric["n_ai"]:
        raise ValueError(
            f"{RECORD_ID}: re-run counts n_human={n_human}, n_ai={n_ai} "
            f"!= registry n_human={metric['n_human']}, "
            f"n_ai={metric['n_ai']} — refusing to report a different sample"
        )
    if abstentions != 162:
        raise ValueError(
            f"{RECORD_ID}: re-run abstentions={abstentions} != 162 "
            "(docs/evidence/EV-20261108-human-fpr.json) — refusing to "
            "report a different sample"
        )

    # Full analyzer detail (unrounded scores, reliabilities, weights) for
    # the top rows, via the same analyze_text the detector calls. The
    # detector is deterministic, so these scores match the detect() run.
    human_rows.sort(key=lambda r: (-r["score"], r["source_id"]))
    by_source = {row.source_id: row.text for row in labelled}
    top_rows: list[dict] = []
    for row in human_rows[:10]:
        result = analyze_text(by_source[row["source_id"]])
        if round(float(result.score), 4) != row["score"]:
            raise ValueError(
                f"{RECORD_ID}: analyze_text score {result.score} != "
                f"detect() score {row['score']} on row {row['source_id']} "
                "— the detector is not deterministic on this input"
            )
        top_rows.append(
            {
                **row,
                "analyzer_reliabilities": {
                    a.name: round(float(a.reliability), 4) for a in result.analyzers
                },
            }
        )

    scores = sorted(row["score"] for row in human_rows)
    reliabilities = [row["reliability"] for row in human_rows]
    near = [row for row in human_rows if row["score"] >= NEAR_THRESHOLD_FLOOR]
    sensitivity = [
        fpr_at_threshold(scores, reliabilities, t)
        for t in (PERTURBED_THRESHOLDS[0], NATIVE_THRESHOLD, PERTURBED_THRESHOLDS[1])
    ]
    return {
        "schema": "textforensics.ghostwriter-threshold-robustness/summary-v1",
        "record_id": RECORD_ID,
        "run_date": RUN_DATE,
        "code_version": _code_version(),
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_family": BuiltinHeuristicDetector.detector_family,
        "cache_file_sha256": cache_sha,
        "registry_file_sha256": registry_sha,
        "cache_sha256_matches_registry": cache_sha == registry_sha,
        "native_threshold": NATIVE_THRESHOLD,
        "reliability_floor": RELIABILITY_FLOOR,
        "n_human": n_human,
        "n_ai": n_ai,
        "abstentions": abstentions,
        "max_human_score": _round6(scores[-1]),
        "human_score_quantiles": {
            f"p{int(p * 100)}": _round6(quantile(scores, p)) for p in (0.5, 0.9, 0.95, 0.99)
        },
        "human_score_mean": _round6(statistics.mean(scores)),
        "human_score_median": _round6(statistics.median(scores)),
        "within_below_threshold": {
            f"{delta}": count_within_below(scores, NATIVE_THRESHOLD, delta)
            for delta in (0.01, 0.02, 0.05)
        },
        "human_scores_at_or_above_threshold": sum(1 for s in scores if s >= NATIVE_THRESHOLD),
        "sensitivity": [{**entry, "rate": _round6(entry["rate"])} for entry in sensitivity],
        "top_human_rows": top_rows,
        "near_threshold_rows": [
            {
                "source_id": row["source_id"],
                "text_sha256": row["text_sha256"],
                "score": row["score"],
                "reliability": row["reliability"],
                "verdict": row["verdict"],
                "words": row["words"],
                "domain": row["domain"],
                "lang": row["lang"],
                "analyzers": row["analyzers"],
                "features": row["features"],
            }
            for row in near
        ],
        "near_threshold_count": len(near),
        "near_threshold_by_domain": {
            domain: sum(1 for row in near if row["domain"] == domain)
            for domain in sorted({row["domain"] for row in near})
        },
        "near_threshold_by_lang": {
            lang: sum(1 for row in near if row["lang"] == lang)
            for lang in sorted({row["lang"] for row in near})
        },
        "human_by_domain": {
            domain: sum(1 for row in human_rows if row["domain"] == domain)
            for domain in sorted({row["domain"] for row in human_rows})
        },
        "human_by_lang": {
            lang: sum(1 for row in human_rows if row["lang"] == lang)
            for lang in sorted({row["lang"] for row in human_rows})
        },
        "near_threshold_word_median": (
            statistics.median([row["words"] for row in near]) if near else None
        ),
        "all_human_word_median": statistics.median([row["words"] for row in human_rows]),
        "single_paragraph_fraction_human": _round6(
            sum(1 for row in human_rows if row["features"]["paragraph_length_cv"] == 0.0)
            / len(human_rows)
        ),
        "single_paragraph_fraction_ai": _round6(ai_single_paragraph / n_ai),
        "analyzer_means": {
            "all_human": {
                name: _round6(value) for name, value in analyzer_mean_scores(human_rows).items()
            },
            "top_10_human": {
                name: _round6(value)
                for name, value in analyzer_mean_scores(human_rows[:10]).items()
            },
            "near_threshold": {
                name: _round6(value) for name, value in analyzer_mean_scores(near).items()
            },
        },
        "feature_means": {
            "all_human": {
                name: _round6(value) for name, value in feature_means(human_rows).items()
            },
            "near_threshold": {name: _round6(value) for name, value in feature_means(near).items()},
        },
        "ai_score_context": {
            "max": _round6(max(ai_scores)),
            "mean": _round6(statistics.mean(ai_scores)),
            "median": _round6(statistics.median(ai_scores)),
            "n_at_or_above_threshold": sum(1 for s in ai_scores if s >= NATIVE_THRESHOLD),
        },
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "non_conclusion": (
            "Threshold-robustness evidence only. The native ai_like "
            "threshold 0.68 is UNCHANGED by this measurement: the "
            "sensitivity rows report what the human FPR would be at "
            "perturbed thresholds, they do not propose moving the "
            "threshold (AGENTS.md rule 17). The zero-FPR result at 0.68 "
            "does NOT survive a -0.02 perturbation (one row flips at "
            "0.66); it survives a +0.02 perturbation (still 0/137 at "
            "0.70). No claim is restated and no record status changes."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="measure and print only; write no summary file",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="summary JSON path (default: write nothing, print only)",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="dataset cache dir (default: XDG cache / TEXTFORENSICS_DATASETS_DIR)",
    )
    args = parser.parse_args(argv)
    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    summary = measure_ghostwriter(cache_dir=cache_dir)

    print(
        f"GhostWriter {summary['record_id']}: n_human={summary['n_human']} "
        f"n_ai={summary['n_ai']} abstentions={summary['abstentions']} "
        f"max_human_score={summary['max_human_score']:.4f} "
        f"(threshold {summary['native_threshold']})"
    )
    print(
        "human score quantiles: "
        + ", ".join(f"{k}={v:.4f}" for k, v in summary["human_score_quantiles"].items())
    )
    print(
        "within below 0.68: "
        + ", ".join(
            f"{delta}={count}" for delta, count in summary["within_below_threshold"].items()
        )
    )
    for entry in summary["sensitivity"]:
        print(
            f"threshold {entry['threshold']:.2f}: FPR {entry['k']}/{entry['n']} "
            f"= {entry['rate']:.4f} Wilson95=[{entry['ci_lower']:.4f}, "
            f"{entry['ci_upper']:.4f}]"
        )
    for row in summary["top_human_rows"]:
        print(
            f"top {row['score']:.4f} {row['domain']} {row['lang']} "
            f"{row['words']}w rel={row['reliability']:.4f} "
            f"verdict={row['verdict']} analyzers={row['analyzers']}"
        )
    print(summary["non_conclusion"])
    if args.output:
        output = Path(args.output)
        output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {output} (sha256 {_sha256_file(output)})")
    if args.check:
        print("check mode: no summary file written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
