#!/usr/bin/env python3
"""seed_validation.py — Seed the U1 validation-evidence registry from the wave-1 caches.

Loads the cached JSONL samples (NO network, NO re-fetch — caches live
in the XDG cache dir / ``TEXTFORENSICS_DATASETS_DIR``), re-runs
``BuiltinHeuristicDetector`` (deterministic) over the labelled rows of
each wave-1 dataset, and builds one ``ValidationRecord`` per dataset
(RAID, MAGE, Beemo, OpAI-Bench) via the Package A API
(``textforensics.validation``). Every record is checked against BOTH
validators — the JSON schema (``validate_evidence_record``) and the
Python validator (``validate_record``) — before it is registered, and
every record's ``run_artifact_sha256`` is verified against the actual
U7 artifact file AND the U7 evidence registry entry for it.

Per dataset the script computes AUROC, TPR@1% FPR, TPR@5% FPR,
native-verdict FPR (P(verdict=ai_like | human)) and native TPR,
abstention rate and coverage — EACH with a bootstrap 95% CI (1000
resamples, seed 20261106; ``ci_method`` recorded verbatim) — plus
length statistics (whitespace word count: min/median/max) and
domain/generator aggregation from row ``meta`` where present. Where
a sample's ``meta`` does not carry per-row domain/generator info,
the record states the dataset-documented scope with its source and
flags the limitation — per-row attribution is never invented.

Native TPR has no slot in the ``evidence-record/v1`` schema, so it
is reported in this script's output and in ``docs/validation/
README.md``, not in the records themselves.

MixSet has NO record: its licence is unresolved, and the record
schema forbids a record without a licence (see the README).

Usage:
    python scripts/seed_validation.py [--only raid,mage] [--check]
    python scripts/seed_validation.py --check   # build + validate, write nothing
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import platform
import random
import statistics
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from measure_datasets import SAMPLE_PLAN, auroc, tpr_at_fpr  # noqa: E402

from textforensics.datasets import (  # noqa: E402
    cache_path,
    get_spec,
    manifest_path,
    read_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.evidence import MetricEstimate  # noqa: E402
from textforensics.schema import load_schema, validate_evidence_record  # noqa: E402
from textforensics.validation import (  # noqa: E402
    DropItem,
    GeneratorInfo,
    HumanPopulation,
    LengthBucket,
    RecordData,
    RecordLimits,
    Regime,
    RunInfo,
    SliceMetrics,
    ValidationRecord,
    ValidationRegistry,
    compute_signature,
    default_next_revalidation_due,
    effective_status,
    validate_record,
)

BOOTSTRAP_RESAMPLES = 1000
BOOTSTRAP_SEED = 20261106
CI_METHOD = "bootstrap, 1000 resamples, seed 20261106"
NATIVE_OPERATING_POINT = "builtin-heuristic native verdict (analyze_text); no score threshold"
CONTAMINATION_JUSTIFICATION = (
    "contamination_flag is 'no' because the builtin detector is a "
    "hand-written stylometric heuristic with no training: it was not "
    "trained on this dataset or on any other text corpus, so it cannot "
    "have memorised evaluation rows"
)
ROW_HASH_METHOD = "sha256 of normalised text (benchmark fingerprint)"
REPORTING_RULES = (
    "Labelled rows only; abstentions counted separately from AUROC/TPR "
    "(abstained rows still contribute their score); no score threshold "
    "fitted — AUROC and TPR@FPR are threshold-free; native FPR/TPR at "
    "the detector's native categorical verdict; bootstrap 95% CIs, 1000 "
    "resamples, seed 20261106"
)

# Per-dataset regime/scope facts, each with its source. Domain and
# generator lists are filled at run time from the cached rows' meta
# (see aggregate_scope); the fields below are the parts the cache
# cannot supply, stated with their source.
SEED_CONFIGS = {
    "raid": {
        "record_id": "evr-20261106-raid-builtin-heuristic",
        "dataset_name": "RAID",
        "genre": "multi-domain benchmark sample (abstracts, books, news, poetry)",
        "editing_regime": "raw",
        "vintage": "2022-2023 (generators in the RAID release; Dugan et al. 2024)",
        "populations": ["general human authors"],
        "determined_how": (
            "Dataset documentation (RAID paper, Dugan et al. 2024): human "
            "texts sourced from arXiv abstracts, books, news, poetry and "
            "other upstream corpora; no per-author demographics recorded"
        ),
        "known_failure_modes": [
            "heuristic score distributions for human and machine text overlap heavily",
            "adversarial attack variants (whitespace, case, paragraph insertion, "
            "article deletion) are pooled into this slice and not reported separately",
            "only 92 human rows: the human slice is below the 100-row minimum "
            "for a supported slice",
        ],
        "limitations_extra": [
            "attack slices are not reported separately in this record (wave-2 concern)",
            "the strided sample covers only the domains observed in the cache "
            "(abstracts, books, news, poetry); other RAID domains are not "
            "represented in this sample",
        ],
        "appeal_note": (
            "A larger human slice (>= 100 humans), a reviewed assessment, "
            "and per-attack reporting would change this record"
        ),
    },
    "mage": {
        "record_id": "evr-20261106-mage-builtin-heuristic",
        "dataset_name": "MAGE",
        "genre": "multi-testbed benchmark sample",
        "editing_regime": "raw",
        "vintage": "2023 and earlier (generators in the MAGE release; Li et al. 2023)",
        "populations": ["general human authors"],
        "determined_how": (
            "Dataset documentation (MAGE paper, Li et al. 2023): human texts "
            "drawn from 10 source datasets (CMV, ELI5, SQuAD, XSum, WP, "
            "ROCStories, HellaSwag, TL;DR, SciGen, Yelp); no per-author "
            "demographics recorded"
        ),
        "known_failure_modes": [
            "heuristic is near chance on this multi-generator slice",
            "generator attribution for bare size labels (7B/13B/30B/65B) is "
            "limited to the dataset's src string — the model family is not "
            "named in the cached sample",
        ],
        "limitations_extra": [
            "per-testbed metrics are not reported in this record (wave-2 concern)",
            "generator families are the dataset's src suffixes verbatim; see "
            "the generator limitation in known_failure_modes",
        ],
        "appeal_note": ("A reviewed assessment and per-testbed reporting would change this record"),
    },
    "beemo": {
        "record_id": "evr-20261106-beemo-builtin-heuristic",
        "dataset_name": "Beemo",
        "genre": "expert-edited benchmark sample",
        "editing_regime": "human-edited",
        "vintage": (
            "2024 (Llama-2, Mistral, Gemma, Tulu, Zephyr generators; "
            "editors Llama-3.1-70B and GPT-4o; Artemova et al. 2024)"
        ),
        "populations": ["expert human editors", "general human authors"],
        "determined_how": (
            "Dataset documentation (Beemo paper, Artemova et al. 2024): "
            "human_output from No Robots and expert (Toloka) human editors; "
            "no per-author demographics recorded"
        ),
        "known_failure_modes": [
            "expert-edited human text scores higher than machine text: AUROC "
            "below chance on this slice — the expert-edited regime inverts "
            "the baseline",
            "single-split dataset: no train/test disjointness check was possible",
            "many rows are near the detector's 80-word minimum, so the abstention rate is high",
        ],
        "limitations_extra": [
            "per-kind metrics (plain human vs human-edited vs LLM-edited) are "
            "not reported in this record (wave-2 concern)",
            "no second split exists, so disjointness against a held-out split was not checked",
            "the slice mixes plain, human-edited and LLM-edited rows under one "
            "human-edited regime label; the mixture is documented here, not "
            "separated",
        ],
        "appeal_note": ("A reviewed assessment and per-kind reporting would change this record"),
    },
    "opai_bench": {
        "record_id": "evr-20261106-opai-bench-builtin-heuristic",
        "dataset_name": "OpAI-Bench",
        "genre": "progressively edited benchmark, endpoint slice only (v0/v8)",
        "editing_regime": "raw",
        "vintage": "2026 (gemini-2.5-flash, gpt-5.4 family; Bsharat et al. 2026)",
        "populations": ["general human authors"],
        "determined_how": (
            "Dataset documentation (OpAI-Bench card, Bsharat et al. 2026): "
            "human documents from news, essays, reports and abstracts; no "
            "per-author demographics recorded"
        ),
        "known_failure_modes": [
            "fully machine text (v8) scores lower than pure human text (v0) "
            "on this slice: AUROC below chance — the endpoint comparison "
            "inverts the baseline",
            "only the v0/v8 endpoint rows carry binary labels; the partial "
            "rows are excluded from this record",
            "both TPR@1% and TPR@5% FPR are 0.0 on this slice",
        ],
        "limitations_extra": [
            "the partial (mixed-origin) rows are the U4 spine, not U1 "
            "evidence, and are excluded from this record",
            "per-version and per-operation detector curves are not reported "
            "in this record (wave-2 concern)",
        ],
        "appeal_note": ("A reviewed assessment and per-version reporting would change this record"),
    },
}

BASE_LIMITATIONS = [
    "not validated for non-English text",
    "not validated for texts below 80 words (the detector's minimum)",
    "not validated for generators newer than the record's declared vintage",
    "not validated for human populations outside the record's declared population",
    "no reviewer has assessed this record; it is a preliminary seed, not a reviewed validation",
    "the sample is a strided subset of the split, not a full-corpus evaluation",
    "near-duplicate rate was not measured for this sample",
    CONTAMINATION_JUSTIFICATION,
]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def bootstrap_ci(
    stat_fn, items, *, resamples: int = BOOTSTRAP_RESAMPLES, seed: int = BOOTSTRAP_SEED
):
    """Percentile bootstrap 95% CI for ``stat_fn`` over resampled ``items``.

    Deterministic: a fresh ``random.Random(seed)`` per call. Resamples
    on which the statistic is undefined (for example an AUROC resample
    with a single class) are skipped; fewer than 100 successful
    resamples is a hard error, not a silent CI.
    """
    if resamples < 1:
        raise ValueError("resamples must be positive.")
    if not items:
        raise ValueError("bootstrap needs at least one item.")
    rng = random.Random(seed)
    estimates: list[float] = []
    for _ in range(resamples):
        sample = [rng.choice(items) for _ in items]
        try:
            estimates.append(float(stat_fn(sample)))
        except ValueError:
            continue
    if len(estimates) < 100:
        raise ValueError(
            f"bootstrap produced only {len(estimates)} usable resamples "
            f"of {resamples} — the statistic is undefined on this sample."
        )
    estimates.sort()
    lower = estimates[int(0.025 * (len(estimates) - 1))]
    upper = estimates[int(0.975 * (len(estimates) - 1))]
    return lower, upper


def metric_with_ci(value: float, n: int, ci: tuple[float, float]) -> MetricEstimate:
    """Build a MetricEstimate, rounding to 4 decimals.

    A percentile bootstrap CI can exclude the point estimate on a
    discrete statistic (for example TPR@FPR with few humans); the
    bounds are then widened to include it, because MetricEstimate
    requires the value to lie inside its CI. The widening is the
    minimal change that keeps the interval honest about the point.
    """
    rounded_value = round(float(value), 4)
    lower = min(round(float(ci[0]), 4), rounded_value)
    upper = max(round(float(ci[1]), 4), rounded_value)
    lower = max(0.0, lower)
    upper = min(1.0, upper)
    return MetricEstimate(
        value=rounded_value, n=n, ci_lower=lower, ci_upper=upper, method=CI_METHOD
    )


def measure_triples(triples: list[tuple[int, float, str]]) -> dict:
    """Compute per-slice metrics with bootstrap CIs from (label, score, verdict) triples.

    ``triples`` are (label 1 = machine / 0 = human, detector score,
    detector verdict). AUROC and TPR@FPR reuse the implementations in
    ``scripts/measure_datasets.py``. Returns MetricEstimates for auroc,
    tpr_at_fpr_0_01, tpr_at_fpr_0_05, fpr_native and tpr_native, plus
    abstention_rate / coverage floats and the class counts.
    """
    labels = [label for label, _, _ in triples]
    scores = [score for _, score, _ in triples]
    verdicts = [verdict for _, _, verdict in triples]
    n_human = sum(1 for label in labels if label == 0)
    n_ai = sum(1 for label in labels if label == 1)
    if n_human == 0 or n_ai == 0:
        raise ValueError("measure_triples needs both classes present.")

    pairs = list(zip(labels, scores, strict=True))
    auroc_value = auroc(labels, scores)
    auroc_ci = bootstrap_ci(
        lambda sample: auroc([lab for lab, _ in sample], [s for _, s in sample]),
        [(lab, s) for lab, s in pairs],
    )
    tpr_01_value = tpr_at_fpr(labels, scores, 0.01)
    tpr_01_ci = bootstrap_ci(
        lambda sample: tpr_at_fpr([lab for lab, _ in sample], [s for _, s in sample], 0.01),
        [(lab, s) for lab, s in pairs],
    )
    tpr_05_value = tpr_at_fpr(labels, scores, 0.05)
    tpr_05_ci = bootstrap_ci(
        lambda sample: tpr_at_fpr([lab for lab, _ in sample], [s for _, s in sample], 0.05),
        [(lab, s) for lab, s in pairs],
    )

    human_verdicts = [v for lab, v in zip(labels, verdicts, strict=True) if lab == 0]
    machine_verdicts = [v for lab, v in zip(labels, verdicts, strict=True) if lab == 1]
    fpr_value = sum(1 for v in human_verdicts if v == "ai_like") / n_human
    fpr_ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "ai_like") / len(sample),
        human_verdicts,
    )
    tpr_native_value = sum(1 for v in machine_verdicts if v == "ai_like") / n_ai
    tpr_native_ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "ai_like") / len(sample),
        machine_verdicts,
    )
    abstentions = sum(1 for v in verdicts if v == "abstain")
    abstention_rate = abstentions / len(triples)
    abstention_ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "abstain") / len(sample),
        verdicts,
    )

    return {
        "auroc": metric_with_ci(auroc_value, len(triples), auroc_ci),
        "tpr_at_fpr_0_01": metric_with_ci(tpr_01_value, n_ai, tpr_01_ci),
        "tpr_at_fpr_0_05": metric_with_ci(tpr_05_value, n_ai, tpr_05_ci),
        "fpr_native": metric_with_ci(fpr_value, n_human, fpr_ci),
        "tpr_native": metric_with_ci(tpr_native_value, n_ai, tpr_native_ci),
        "abstention_rate": round(abstention_rate, 4),
        "abstention_ci": (round(abstention_ci[0], 4), round(abstention_ci[1], 4)),
        "coverage": round(1.0 - abstention_rate, 4),
        "n_human": n_human,
        "n_ai": n_ai,
    }


# ---------------------------------------------------------------------------
# Scope aggregation from cached row meta (never invented)
# ---------------------------------------------------------------------------


def aggregate_scope(key: str, labelled_rows) -> dict[str, list[str]]:
    """Aggregate domain/generator scope from the labelled rows' meta.

    Only values actually present in the cached rows are returned.
    MAGE generator labels are the dataset's ``src`` suffixes verbatim
    (mode stripped: ``continuation_7B`` -> ``7B``); bare size labels
    do not name the model family, which the record flags as a
    limitation. Beemo generators are the ``generator`` meta values
    plus the LLM editors named in the row kinds.
    """
    if key == "raid":
        domains = sorted({str(r.meta.get("domain")) for r in labelled_rows if r.meta.get("domain")})
        generators = sorted(
            {
                str(r.meta.get("model"))
                for r in labelled_rows
                if r.meta.get("model") and r.meta.get("model") != "human"
            }
        )
    elif key == "mage":
        domains = sorted(
            {
                str(r.meta["src"])[: -len("_human")]
                if str(r.meta["src"]).endswith("_human")
                else str(r.meta["src"]).split("_machine_", 1)[0]
                for r in labelled_rows
                if r.meta.get("src")
            }
        )
        generators = set()
        for row in labelled_rows:
            src = str(row.meta.get("src", ""))
            if "_machine_" in src:
                suffix = src.split("_machine_", 1)[1]
                for mode in ("continuation_", "specified_", "topical_"):
                    if suffix.startswith(mode):
                        suffix = suffix[len(mode) :]
                        break
                generators.add(suffix)
        generators = sorted(generators)
    elif key == "beemo":
        domains = sorted(
            {str(r.meta.get("category")) for r in labelled_rows if r.meta.get("category")}
        )
        generators = sorted(
            {str(r.meta.get("generator")) for r in labelled_rows if r.meta.get("generator")}
            | {
                kind.split("_")[0]
                for r in labelled_rows
                for kind in [str(r.meta.get("kind", ""))]
                if kind.startswith(("llama-", "gpt-"))
            }
        )
    elif key == "opai_bench":
        domains = sorted({str(r.meta.get("domain")) for r in labelled_rows if r.meta.get("domain")})
        generators = sorted(
            {str(r.meta.get("generator")) for r in labelled_rows if r.meta.get("generator")}
        )
    else:
        raise ValueError(f"no seed config for dataset {key!r}")
    if not domains or not generators:
        raise ValueError(
            f"{key}: cannot aggregate scope from cached meta "
            f"(domains={domains}, generators={generators})"
        )
    return {"domains": domains, "generators": generators}


# ---------------------------------------------------------------------------
# Run-artifact verification
# ---------------------------------------------------------------------------


def verify_run_artifact(key: str, *, repo_root: Path) -> dict:
    """Verify a dataset's U7 run artifact against the U7 registry.

    Returns the run provenance the record needs. Raises ValueError
    (loudly) when the artifact file is missing, when the U7 registry
    has no entry for it, or when the registry's
    ``run_artifact_sha256`` differs from the recomputed SHA-256 of
    the artifact file.
    """
    artifact_name = f"EV-20261106-dataset-{key.replace('_', '-')}.json"
    artifact_path = repo_root / "docs" / "evidence" / "runs" / artifact_name
    if not artifact_path.exists():
        raise ValueError(f"U7 run artifact missing: {artifact_path}")
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    actual_sha = _sha256_file(artifact_path)
    registry_path = repo_root / "docs" / "evidence" / "registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    entry = next(
        (
            item
            for item in registry.get("records", [])
            if item.get("evidence_record_id") == artifact.get("evidence_record_id")
        ),
        None,
    )
    if entry is None:
        raise ValueError(f"U7 registry has no entry for {artifact.get('evidence_record_id')}")
    if entry.get("run_artifact_sha256") != actual_sha:
        raise ValueError(
            f"run_artifact_sha256 mismatch for {artifact.get('evidence_record_id')}: "
            f"U7 registry says {entry.get('run_artifact_sha256')}, "
            f"recomputed SHA-256 of {artifact_path} is {actual_sha}"
        )
    return {
        "run_id": str(artifact["evidence_record_id"]),
        "run_artifact": f"docs/evidence/runs/{artifact_name}",
        "run_artifact_sha256": actual_sha,
        "run_date": str(artifact["run_date"]),
        "code_version": str(artifact["code_version"]),
        "drops": list(artifact.get("drops", [])),
    }


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def record_from_triples(
    key: str,
    triples: list[tuple[int, float, str]],
    *,
    word_counts: list[int],
    domains: list[str],
    generators: list[str],
    artifact: dict,
    n_partial: int = 0,
    cache_file_sha256: str,
) -> tuple[ValidationRecord, dict]:
    """Build (and dual-validate) one seed ValidationRecord from measured triples.

    ``artifact`` is the verified run provenance from
    :func:`verify_run_artifact`. The record is stored as ``partial``:
    no reviewer has assessed it, the samples are preliminary strided
    subsets, and (for RAID) the human slice is below 100 rows. The
    record is signed, then checked against BOTH the JSON schema and
    the Python validator; any issue raises ValueError. Returns the
    record and the full measurements dict (which also carries native
    TPR — a value the record schema has no slot for).
    """
    if key not in SEED_CONFIGS:
        raise ValueError(f"no seed config for dataset {key!r}")
    config = SEED_CONFIGS[key]
    spec = get_spec(key)
    measurements = measure_triples(triples)
    if not word_counts:
        raise ValueError(f"{key}: no labelled rows to measure length statistics.")
    ordered_counts = sorted(word_counts)
    measured_min = ordered_counts[0]
    measured_median = int(statistics.median_low(ordered_counts))
    measured_max = ordered_counts[-1]
    run_date = artifact["run_date"]

    drops = [DropItem(item=item["item"], reason=item["reason"]) for item in artifact["drops"]]
    drops.append(
        DropItem(
            item="per-slice breakdowns (per-domain / per-generator / per-attack)",
            reason=(
                "this seed record reports one pooled slice per dataset; "
                "finer slices are wave-2 work"
            ),
        )
    )
    if key == "opai_bench" and n_partial:
        drops.append(
            DropItem(
                item=f"{n_partial} partial (mixed-origin) rows",
                reason=(
                    "rows with 0 < ai_sentence_ratio < 1 carry no binary label; "
                    "they are the U4 spine, not U1 evidence"
                ),
            )
        )

    record = ValidationRecord(
        record_id=config["record_id"],
        detector_id=BuiltinHeuristicDetector.detector_id,
        detector_version=BuiltinHeuristicDetector.detector_version,
        detector_family=BuiltinHeuristicDetector.detector_family,
        calibration_id=None,
        status="partial",
        supersedes=None,
        regime=Regime(
            language="en",
            script="Latn",
            language_variety=None,
            length_bucket=LengthBucket(
                min_words=80,
                max_words=None,
                floor_words=80,
                measured_min_words=measured_min,
                measured_median_words=measured_median,
                measured_max_words=measured_max,
            ),
            domain=tuple(domains),
            genre=config["genre"],
            generator=GeneratorInfo(
                families=tuple(generators),
                vintage=config["vintage"],
                current_as_of=run_date,
            ),
            editing_regime=config["editing_regime"],
            human_population=HumanPopulation(
                populations=tuple(config["populations"]),
                determined_how=config["determined_how"],
            ),
            attack_slice=None,
        ),
        data=RecordData(
            dataset_name=config["dataset_name"],
            dataset_version=f"{spec.hf_id} snapshot {run_date} (no versioned release)",
            file_sha256=cache_file_sha256,
            row_hash_method=ROW_HASH_METHOD,
            split=SAMPLE_PLAN[key]["split"],
            split_role="test",
            n_human=measurements["n_human"],
            n_ai=measurements["n_ai"],
            licence=str(spec.licence),
            licence_reference=spec.source_url,
            contamination_flag="no",
            near_duplicate_rate=None,
            near_duplicate_method=None,
        ),
        run=RunInfo(
            run_id=artifact["run_id"],
            run_artifact=artifact["run_artifact"],
            run_artifact_sha256=artifact["run_artifact_sha256"],
            run_date=run_date,
            runner="U1 seed (scripts/seed_validation.py)",
            code_version=artifact["code_version"],
            dependency_lock_sha=None,
            hardware=f"{platform.machine()} ({platform.system()} {platform.release()})",
            runtime=f"CPython {platform.python_version()} on {sys.platform}",
            seeds={"bootstrap_seed": BOOTSTRAP_SEED},
            command=f"python scripts/seed_validation.py --only {key}",
            drops_manifest=tuple(drops),
            reporting_rules=REPORTING_RULES,
        ),
        metrics=(
            SliceMetrics(
                slice_id=f"{key}-builtin-heuristic",
                n_human=measurements["n_human"],
                n_ai=measurements["n_ai"],
                auroc=measurements["auroc"],
                tpr_at_fpr_0_01=measurements["tpr_at_fpr_0_01"],
                tpr_at_fpr_0_05=measurements["tpr_at_fpr_0_05"],
                fpr_native=measurements["fpr_native"],
                coverage=measurements["coverage"],
                abstention_rate=measurements["abstention_rate"],
                worst_slice=True,
                fpr_operating_point=NATIVE_OPERATING_POINT,
            ),
        ),
        limits=RecordLimits(
            known_failure_modes=tuple(config["known_failure_modes"]),
            limitations=tuple(BASE_LIMITATIONS + config["limitations_extra"]),
            next_revalidation_due=default_next_revalidation_due(run_date),
            appeal_note=config["appeal_note"],
            reviewer=None,
            review_date=None,
            demoted_by=None,
        ),
        signature="0" * 64,
    )
    signed = dataclasses.replace(record, signature=compute_signature(record))
    payload = signed.to_dict()
    schema_issues = validate_evidence_record(payload)
    if schema_issues:
        raise ValueError(f"{key}: record fails JSON schema: {schema_issues}")
    python_issues = validate_record(payload)
    if python_issues:
        raise ValueError(f"{key}: record fails Python validator: {python_issues}")
    return signed, measurements


def build_record(
    key: str, *, cache_dir: Path | None = None, repo_root: Path = REPO_ROOT
) -> tuple[ValidationRecord, dict]:
    """Build one seed record from the cached sample (no network).

    Re-runs the detector over the cached labelled rows, verifies the
    cache manifest hash against the recomputed cache SHA-256 and the
    U7 artifact hash against the U7 registry, then builds the record.
    Returns the record and the full measurements dict (native TPR
    included — the record schema has no slot for it).
    """
    if key not in SEED_CONFIGS:
        raise ValueError(f"no seed config for dataset {key!r} (MixSet has no record: no licence)")
    spec = get_spec(key)
    plan = SAMPLE_PLAN[key]
    rows = read_sample_cache(spec, plan["config"], plan["split"], cache_dir=cache_dir)
    cache_file = cache_path(spec.key, plan["config"], plan["split"], cache_dir=cache_dir)
    manifest = json.loads(
        manifest_path(spec.key, plan["config"], plan["split"], cache_dir=cache_dir).read_text(
            encoding="utf-8"
        )
    )
    cache_sha = _sha256_file(cache_file)
    if manifest["file_sha256"] != cache_sha:
        raise ValueError(
            f"{key}: cache manifest file_sha256 {manifest['file_sha256']} != "
            f"recomputed SHA-256 {cache_sha} of {cache_file}"
        )
    labelled = [row for row in rows if row.label is not None]
    n_partial = len(rows) - len(labelled)
    detector = BuiltinHeuristicDetector()
    triples: list[tuple[int, float, str]] = []
    word_counts: list[int] = []
    for row in labelled:
        prediction = detector.detect(row.text)
        triples.append((int(row.label), float(prediction.score), str(prediction.verdict)))
        word_counts.append(len(row.text.split()))
    scope = aggregate_scope(key, labelled)
    artifact = verify_run_artifact(key, repo_root=repo_root)
    return record_from_triples(
        key,
        triples,
        word_counts=word_counts,
        domains=scope["domains"],
        generators=scope["generators"],
        artifact=artifact,
        n_partial=n_partial,
        cache_file_sha256=cache_sha,
    )


def seed_registry(
    keys, *, cache_dir: Path | None = None, repo_root: Path = REPO_ROOT
) -> tuple[ValidationRegistry, dict[str, dict]]:
    """Build all seed records; return the registry and per-record measurements.

    The registry dict is also checked against the validation-registry
    JSON schema. Nothing is written here.
    """
    records: list[ValidationRecord] = []
    measurements: dict[str, dict] = {}
    for key in keys:
        record, measured = build_record(key, cache_dir=cache_dir, repo_root=repo_root)
        records.append(record)
        measurements[record.record_id] = measured
    registry = ValidationRegistry(records)
    payload = registry.to_dict()
    import jsonschema

    validator = jsonschema.Draft202012Validator(load_schema("validation-registry"))
    errors = [str(error.message) for error in validator.iter_errors(payload)]
    if errors:
        raise ValueError(f"Validation registry fails JSON schema: {errors}")
    return registry, measurements


def _print_summary(records, measurements: dict[str, dict]) -> None:
    print(
        f"{'dataset':<12} {'n_hum':>5} {'n_ai':>5} {'auroc':>7} {'tpr1%':>6} {'tpr5%':>6} {'fpr_nat':>7} {'tpr_nat':>7} {'abst':>5}"
    )
    for record in records:
        metrics = record.metrics[0]
        tpr_native = measurements[record.record_id]["tpr_native"]
        print(
            f"{record.data.dataset_name:<12} {metrics.n_human:>5} {metrics.n_ai:>5} "
            f"{metrics.auroc.value:>7.4f} {metrics.tpr_at_fpr_0_01.value:>6.4f} "
            f"{metrics.tpr_at_fpr_0_05.value:>6.4f} {metrics.fpr_native.value:>7.4f} "
            f"{tpr_native.value:>7.4f} {metrics.abstention_rate:>5.4f}"
        )
        print(
            f"  {record.record_id}: stored={record.status}, "
            f"effective={effective_status(record, detector_version=record.detector_version)}, "
            f"fpr_native 95% CI [{metrics.fpr_native.ci_lower:.4f}, "
            f"{metrics.fpr_native.ci_upper:.4f}], tpr_native 95% CI "
            f"[{tpr_native.ci_lower:.4f}, {tpr_native.ci_upper:.4f}], "
            f"next revalidation {record.limits.next_revalidation_due}"
        )
    print(
        "Native TPR is not a field of evidence-record/v1; it is reported "
        "here and in docs/validation/README.md, not in the records."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default="", help="comma-separated dataset keys (default: all)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="build + validate the records without writing the registry",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="dataset cache dir (default: XDG cache / TEXTFORENSICS_DATASETS_DIR)",
    )
    parser.add_argument(
        "--registry",
        default=None,
        help="registry path to write (default: docs/validation/registry.json)",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="repo root for U7 artifacts and the default registry path",
    )
    args = parser.parse_args(argv)

    keys = [k for k in SEED_CONFIGS if not args.only or k in args.only.split(",")]
    unknown = set(args.only.split(",")) - set(SEED_CONFIGS) if args.only else set()
    if unknown:
        print(f"unknown dataset keys: {sorted(unknown)} (known: {sorted(SEED_CONFIGS)})")
        return 2
    repo_root = Path(args.repo_root) if args.repo_root else REPO_ROOT
    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    registry, measurements = seed_registry(keys, cache_dir=cache_dir, repo_root=repo_root)
    _print_summary(registry.records, measurements)
    if args.check:
        print(
            f"--check: {len(registry.records)} record(s) built and dual-validated, nothing written."
        )
        return 0
    registry_path = (
        Path(args.registry)
        if args.registry
        else repo_root / "docs" / "validation" / "registry.json"
    )
    registry.save(registry_path)
    reloaded = ValidationRegistry.load(registry_path)
    print(
        f"Wrote {registry_path} with {len(reloaded.records)} records "
        f"(registry_id {reloaded.registry_id[:12]}...), reloaded and re-verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
