#!/usr/bin/env python3
"""seed_validation.py — Seed the U1 validation-evidence registry from the wave-1/wave-2 caches.

Loads the cached JSONL samples (NO network, NO re-fetch — caches live
in the XDG cache dir / ``TEXTFORENSICS_DATASETS_DIR``), re-runs
``BuiltinHeuristicDetector`` (deterministic) over the labelled rows of
each dataset, and builds one ``ValidationRecord`` per dataset
(RAID, MAGE, Beemo, OpAI-Bench, GhostWriter and DetectRL-X in wave 2) via the Package A API
(``textforensics.validation``). Every record is checked against BOTH
validators — the JSON schema (``validate_evidence_record``) and the
Python validator (``validate_record``) — before it is registered, and
every record's ``run_artifact_sha256`` is verified against the actual
U7 artifact file AND the U7 evidence registry entry for it.

The U7 artifact is found by run date: ``--run-date`` takes a
``YYYYMMDD`` stamp (default: the latest ``EV-*-dataset-<key>.json``
in ``docs/evidence/runs``), so no date is hardcoded — wave-1 seeds
used 20261106, the GhostWriter seed uses 20261107.

By default the script rebuilds the registry from the requested keys
(the U1 seeding behaviour). ``--append`` instead loads the existing
``docs/validation/registry.json``, appends the newly built records
(duplicate record ids are rejected) and saves the merged registry —
the existing records are carried over untouched and the registry id
is recomputed from the merged record set, as always.

Per dataset the script computes AUROC, TPR@1% FPR, TPR@5% FPR,
native-verdict FPR (P(verdict=ai_like | human)) and native TPR,
abstention rate and coverage — EACH with a bootstrap 95% CI (1000
resamples, seed 20261106; ``ci_method`` recorded verbatim) — plus
length statistics (whitespace word count: min/median/max) and
domain/generator aggregation from row ``meta`` where present. Where
a sample's ``meta`` does not carry per-row domain/generator info,
the record states the dataset-documented scope with its source and
flags the limitation — per-row attribution is never invented.

Native TPR is the pair of native FPR at the same operating point and
is carried in the records as the optional ``tpr_native`` metric
(evidence-record/v1); it is also reported in this script's output
and in ``docs/validation/README.md``.

MixSet has NO record: its licence is unresolved, and the record
schema forbids a record without a licence (see the README).

Usage:
    python scripts/seed_validation.py [--only raid,mage] [--check]
    python scripts/seed_validation.py --check   # build + validate, write nothing
    python scripts/seed_validation.py --only ghostwriter --append
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
from textforensics.evidence import (  # noqa: E402
    DEFAULT_FPR_CEILING,
    MIN_AI_SAMPLES,
    MIN_HUMAN_SAMPLES,
    MetricEstimate,
)
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
    contamination_label,
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
    "opai_bench_segments": {
        # U4 segment-level record: sentences, not documents, from the
        # SAME 500-row strided OpAI-Bench train sample as the document
        # record evr-20261106-opai-bench-builtin-heuristic (re-fetched
        # with segment ground truth; the document cache is untouched).
        # editing_regime "LLM-edited" is deliberate AND load-bearing:
        # no input regime maps to it (validation.py
        # INPUT_EDITING_REGIME_MAP), so segment FPR can never pollute
        # a document-level Trust Map dimension. Stored "partial" never
        # upgrades to "supported" on its own.
        "record_id": "evr-20261107-opai-bench-builtin-heuristic",
        "dataset_name": "OpAI-Bench (segment-level)",
        "genre": "segment-level (sentence) slice — OpAI-Bench v0–v8 edit ladder",
        "editing_regime": "LLM-edited",
        "vintage": "2026 (gemini-2.5-flash, gpt-5.4 family; Bsharat et al. 2026)",
        "populations": ["general human authors"],
        "determined_how": (
            "Dataset documentation (OpAI-Bench card, Bsharat et al. 2026): "
            "human documents from news, essays, reports and abstracts; no "
            "per-author demographics recorded; sentence labels are the "
            "dataset's own sentence_labels field"
        ),
        "known_failure_modes": [
            "segment scores are evidence scores, not sentence authorship "
            "probabilities; per-segment F1 is modest and the segment "
            "method is weak by design (research §8.2)",
            "segments under 20 words never carry a verdict, so short "
            "sentences contribute abstentions, not evidence",
            "the ai→human direction has no data source in v1.0: every "
            "OpAI-Bench row is human→ai, so those cells are unknown",
            "no population-labelled source exists, so the human-slice "
            "segment FPR is pooled by domain only, never by population",
        ],
        "limitations_extra": [
            "per-segment precision/recall/F1 by version, operation and "
            "length live in the U7 run artifact (the evidence-record "
            "schema has no slots for them), not in this record",
            "the operation-hypothesis accuracy and the verdict "
            "distribution on mixed documents live in the U7 run artifact",
            "the record covers the train split only; the dev-50 slice "
            "is a replication reported in the artifact, not pooled here",
            "this record is segment-level evidence: it must never be "
            "read as a document-level claim and never auto-matches a "
            "Trust Map dimension",
            "native FPR/TPR here are at the segment operating point "
            "(score >=0.68 / <=0.32, segments under 20 words abstain), "
            "not at the document detector's reliability-gated verdict — "
            "the document verdict abstains on all short text by "
            "construction (length_reliability = word_count/250), so it "
            "would zero out every segment-level native metric",
        ],
        "appeal_note": (
            "A reviewed assessment, a dedicated mixed-origin calibration "
            "set, and per-(operation × direction) cells with n>=100 "
            "segments would change this record"
        ),
    },
    "detectrl_x": {
        "record_id": "evr-20261107-detectrl-x-builtin-heuristic",
        "dataset_name": "DetectRL-X",
        # Multilingual sample: 100 labelled rows per language (50 human
        # + 50 machine each). "mul" is the BCP 47 tag for multiple
        # languages; the split is recorded in language_variety and the
        # limitations, and per-language metrics are not reported
        # separately. Script is "mul" too: the 8 languages span Arab,
        # Hans, Cyrl and Latn.
        "language": "mul",
        "language_variety": (
            "ar + zh + en + fr + de + pt + ru + es "
            "(100 labelled rows each: 50 human + 50 machine per language)"
        ),
        "script": "mul",
        "genre": "multilingual benchmark sample, binary slice (human/llm text pairs)",
        "editing_regime": "raw",
        "vintage": (
            "current commercial LLMs at the DetectRL-X release "
            "(deepseek-v3, gemini-2.5-flash, gpt-4o, qwen-max; Wu et al., ACL 2026)"
        ),
        "populations": ["general human authors"],
        "determined_how": (
            "Dataset documentation (DetectRL-X paper and README, Wu et al. "
            "2026): human texts from 6 domains (Academic, News, Novel, "
            "Wiki, SEO, Webtext) in 8 languages; no per-author "
            "demographics recorded"
        ),
        "known_failure_modes": [
            "heuristic separates weakly on this multilingual slice (AUROC 0.5972)",
            "abstentions are uneven across languages (chinese 28/100, english "
            "22/100, spanish 22/100; russian 0/100)",
            "TPR@1% FPR is 0.005 and TPR@5% FPR is 0.0825 on this slice",
            "only one Binary file (general) of 16 was measured; the other "
            "strategy files and Ternary files are unmeasured",
        ],
        "limitations_extra": [
            "per-language AUROC/TPR metrics are not reported in this record "
            "(pooled slice only); per-language label counts and abstentions "
            "are in the U7 run artifact",
            "the sample mixes 8 languages under one `mul` regime; the "
            "record's script is `mul` (multiple scripts: Arab, Hans, Cyrl, Latn)",
            "three-way licence conflict (GitHub README Apache-2.0 + "
            "non-commercial academic research restriction, HF MIT, ACL 2026 "
            "paper noncommercial restriction); the strictest reading "
            "(non-commercial academic research only) governs; no redistribution",
            "single-file preliminary slice: only Binary/binary_general_open.json was measured",
        ],
        "appeal_note": (
            "A reviewed assessment and per-language reporting would change this record"
        ),
    },
    "ghostwriter": {
        "record_id": "evr-20261107-ghostwriter-builtin-heuristic",
        "dataset_name": "GhostWriter",
        # Bilingual sample: 288 English + 59 German labelled rows.
        # "mul" is the BCP 47 tag for multiple languages; the split is
        # recorded in language_variety and the limitations, and
        # per-language metrics are not reported separately.
        "language": "mul",
        "language_variety": "en-EN + de-DE (288 + 59 labelled rows)",
        "genre": "mixed-origin benchmark sample, binary slice only (human/ai fulltext endpoints)",
        "editing_regime": "raw",
        "vintage": (
            "2024-2025 (gemma2, gpt-4o-mini, phi3, nemotron, deepseek-r1 "
            "agents in the GhostWriter release; Schaaf et al. 2026)"
        ),
        "populations": ["general human authors"],
        "determined_how": (
            "Dataset documentation (GhostWriter card, Schaaf et al. 2026): "
            "human texts from CNN news, arXiv papers, blogs, Bundestag "
            "proceedings, House of Commons debates, EU court cases, "
            "student essays and Project Gutenberg; no per-author "
            "demographics recorded"
        ),
        "known_failure_modes": [
            "heuristic scores human text higher than machine text: AUROC "
            "below chance on this slice (0.436)",
            "fusion rows are all chunks and labelled rows are all "
            "fulltext: the binary slice is fulltext-only, so chunk "
            "behaviour is unmeasured",
            "the sample mixes English (288 labelled rows) and German (59 "
            "labelled rows); per-language metrics are not reported "
            "separately",
            "TPR@1% FPR is 0.0 and TPR@5% FPR is 0.0048 on this slice",
        ],
        "limitations_extra": [
            "the 153 fusion (mixed-origin) rows are the U4 spine, not U1 "
            "evidence, and are excluded from this record",
            "per-domain and per-generator metrics are not reported in this record (wave-2 concern)",
            "two domains (euro_court_cases, student_essays) are CC-BY-NC-SA "
            "4.0 and blog_authorship_corpus is non-commercial-research-only; "
            "use is non-commercial research evaluation only",
        ],
        "appeal_note": (
            "A reviewed assessment and per-domain / per-language reporting would change this record"
        ),
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


def metric_with_ci(
    value: float, n: int, ci: tuple[float, float], *, method: str | None = None
) -> MetricEstimate:
    """Build a MetricEstimate, rounding to 4 decimals.

    A percentile bootstrap CI can exclude the point estimate on a
    discrete statistic (for example TPR@FPR with few humans); the
    bounds are then widened to include it, because MetricEstimate
    requires the value to lie inside its CI. The widening is the
    minimal change that keeps the interval honest about the point.
    ``method`` defaults to the module CI_METHOD (seed 20261106); a
    re-seed passes its own method string verbatim.
    """
    rounded_value = round(float(value), 4)
    lower = min(round(float(ci[0]), 4), rounded_value)
    upper = max(round(float(ci[1]), 4), rounded_value)
    lower = max(0.0, lower)
    upper = min(1.0, upper)
    return MetricEstimate(
        value=rounded_value, n=n, ci_lower=lower, ci_upper=upper, method=method or CI_METHOD
    )


def ci_method_for_seed(seed: int) -> str:
    """The verbatim CI method string for a bootstrap seed (seed = run date)."""
    if seed == BOOTSTRAP_SEED:
        return CI_METHOD
    return f"bootstrap, 1000 resamples, seed {seed}"


def reporting_rules_for_seed(seed: int) -> str:
    """The verbatim reporting-rules string for a bootstrap seed."""
    if seed == BOOTSTRAP_SEED:
        return REPORTING_RULES
    return REPORTING_RULES.replace("seed 20261106", f"seed {seed}")


def measure_triples(
    triples: list[tuple[int, float, str]], *, bootstrap_seed: int = BOOTSTRAP_SEED
) -> dict:
    """Compute per-slice metrics with bootstrap CIs from (label, score, verdict) triples.

    ``triples`` are (label 1 = machine / 0 = human, detector score,
    detector verdict). AUROC and TPR@FPR reuse the implementations in
    ``scripts/measure_datasets.py``. Returns MetricEstimates for auroc,
    tpr_at_fpr_0_01, tpr_at_fpr_0_05, fpr_native and tpr_native, plus
    abstention_rate / coverage floats and the class counts. The
    bootstrap seed is the run date (U1 used 20261106); a re-seed passes
    its own seed and the method string records it verbatim.
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
        seed=bootstrap_seed,
    )
    tpr_01_value = tpr_at_fpr(labels, scores, 0.01)
    tpr_01_ci = bootstrap_ci(
        lambda sample: tpr_at_fpr([lab for lab, _ in sample], [s for _, s in sample], 0.01),
        [(lab, s) for lab, s in pairs],
        seed=bootstrap_seed,
    )
    tpr_05_value = tpr_at_fpr(labels, scores, 0.05)
    tpr_05_ci = bootstrap_ci(
        lambda sample: tpr_at_fpr([lab for lab, _ in sample], [s for _, s in sample], 0.05),
        [(lab, s) for lab, s in pairs],
        seed=bootstrap_seed,
    )

    human_verdicts = [v for lab, v in zip(labels, verdicts, strict=True) if lab == 0]
    machine_verdicts = [v for lab, v in zip(labels, verdicts, strict=True) if lab == 1]
    fpr_value = sum(1 for v in human_verdicts if v == "ai_like") / n_human
    fpr_ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "ai_like") / len(sample),
        human_verdicts,
        seed=bootstrap_seed,
    )
    tpr_native_value = sum(1 for v in machine_verdicts if v == "ai_like") / n_ai
    tpr_native_ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "ai_like") / len(sample),
        machine_verdicts,
        seed=bootstrap_seed,
    )
    abstentions = sum(1 for v in verdicts if v == "abstain")
    abstention_rate = abstentions / len(triples)
    abstention_ci = bootstrap_ci(
        lambda sample: sum(1 for v in sample if v == "abstain") / len(sample),
        verdicts,
        seed=bootstrap_seed,
    )

    ci_method = ci_method_for_seed(bootstrap_seed)
    return {
        "auroc": metric_with_ci(auroc_value, len(triples), auroc_ci, method=ci_method),
        "tpr_at_fpr_0_01": metric_with_ci(tpr_01_value, n_ai, tpr_01_ci, method=ci_method),
        "tpr_at_fpr_0_05": metric_with_ci(tpr_05_value, n_ai, tpr_05_ci, method=ci_method),
        "fpr_native": metric_with_ci(fpr_value, n_human, fpr_ci, method=ci_method),
        "tpr_native": metric_with_ci(tpr_native_value, n_ai, tpr_native_ci, method=ci_method),
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
    elif key == "ghostwriter":
        domains = sorted({str(r.meta.get("domain")) for r in labelled_rows if r.meta.get("domain")})
        # Generators are the `agent` values; human rows carry agent
        # "human" and are not generators.
        generators = sorted(
            {
                str(r.meta.get("agent"))
                for r in labelled_rows
                if r.meta.get("agent") and r.meta.get("agent") != "human"
            }
        )
    elif key == "detectrl_x":
        domains = sorted({str(r.meta.get("domain")) for r in labelled_rows if r.meta.get("domain")})
        generators = sorted(
            {str(r.meta.get("model")) for r in labelled_rows if r.meta.get("model")}
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


def verify_run_artifact(
    key: str,
    *,
    repo_root: Path,
    run_date: str | None = None,
    require_registry_entry: bool = True,
) -> dict:
    """Verify a dataset's U7 run artifact against the U7 registry.

    ``run_date`` is the ``YYYYMMDD`` stamp in the artifact filename
    (``EV-<run_date>-dataset-<key>.json``). When omitted, the latest
    matching artifact in ``docs/evidence/runs`` is used, so no date
    is hardcoded — wave-1 seeds used 20261106, the GhostWriter seed
    uses 20261107. Returns the run provenance the record needs.
    Raises ValueError (loudly) when the artifact file is missing,
    when the U7 registry has no entry for it, or when the registry's
    ``run_artifact_sha256`` differs from the recomputed SHA-256 of
    the artifact file.

    ``require_registry_entry=False`` skips the registry cross-check
    and trusts only the recomputed SHA-256 of the artifact file. It
    exists for the registry-hold workflow (Phase 5 RAID humans-100):
    the new run artifact is written as a standalone file and its
    registry record is delivered as a patch file for the parent to
    apply, so no registry entry exists yet at build time. The parent's
    apply step rebuilds the evidence registry, which then pins the
    artifact SHA-256; the record's ``run_artifact_sha256`` is the
    recomputed file hash either way, so later tampering is still
    caught by the evidence registry and the claims gate.
    """
    runs_dir = repo_root / "docs" / "evidence" / "runs"
    slug = key.replace("_", "-")
    if run_date is None:
        candidates = sorted(runs_dir.glob(f"EV-*-dataset-{slug}.json"))
        if not candidates:
            raise ValueError(f"U7 run artifact missing: no EV-*-dataset-{slug}.json in {runs_dir}")
        artifact_path = candidates[-1]  # YYYYMMDD sorts; the last is the latest
    else:
        if not run_date.isdigit() or len(run_date) != 8:
            raise ValueError(f"run_date must be a YYYYMMDD stamp, got {run_date!r}")
        artifact_path = runs_dir / f"EV-{run_date}-dataset-{slug}.json"
    artifact_name = artifact_path.name
    if not artifact_path.exists():
        raise ValueError(f"U7 run artifact missing: {artifact_path}")
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    actual_sha = _sha256_file(artifact_path)
    if not require_registry_entry:
        return {
            "run_id": str(artifact["evidence_record_id"]),
            "run_artifact": f"docs/evidence/runs/{artifact_name}",
            "run_artifact_sha256": actual_sha,
            "run_date": str(artifact["run_date"]),
            "code_version": str(artifact["code_version"]),
            "drops": list(artifact.get("drops", [])),
        }
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


def support_gate_blockers(record: ValidationRecord, measurements: dict) -> list[str]:
    """Reasons a record cannot hold ``supported`` status (empty when it can).

    The EIGHT conditions for ``supported``, verified from the code:

    1. stored status is ``supported`` (the candidate is built that way);
    2. no missing mandatory-for-supported fields
       (``validation._MANDATORY_FOR_SUPPORTED``, 39 fields);
    3. detector version matches the version the status is evaluated at;
    4. ``limits.demoted_by`` is unset;
    5. ``now`` is not past ``limits.next_revalidation_due`` (run date + 90 days);
       conditions 1–5 are exactly what ``effective_status`` computes —
       a stored ``supported`` that fails any of them comes back ``partial``
       (missing fields) or ``stale`` (version / demotion / due date);
    6. ``n_human >= 100`` AND ``n_ai >= 100`` (``evidence.MIN_HUMAN_SAMPLES`` /
       ``MIN_AI_SAMPLES`` — the ``_support_blockers`` sample check);
    7. ``contamination_flag == "no"`` (``contamination_label`` is None);
    8. ``fpr_native`` carries a CI with ``ci_upper <= 0.05``
       (``evidence.DEFAULT_FPR_CEILING`` — the ``_fpr_blockers`` check for
       the human_false_positive_evidence dimension).

    The temporal_version_stability longitudinal blocker (U3 clean runs)
    is NOT a record-level condition: it caps only that one Trust Map
    dimension, never the record's effective status.
    """
    blockers: list[str] = []
    effective = effective_status(
        record, detector_version=record.detector_version, now=record.run.run_date
    )
    if effective != "supported":
        blockers.append(f"effective record status is {effective!r}")
    if record.data.n_human < MIN_HUMAN_SAMPLES or record.data.n_ai < MIN_AI_SAMPLES:
        blockers.append(
            f"sample counts are thin (n_human={record.data.n_human}, "
            f"n_ai={record.data.n_ai}; at least {MIN_HUMAN_SAMPLES} each "
            "are required)"
        )
    label = contamination_label(record)
    if label is not None:
        blockers.append(label)
    fpr_native = measurements["fpr_native"]
    if not fpr_native.has_ci:
        blockers.append("no fpr_native metric carries a confidence interval")
    elif fpr_native.ci_upper is not None and fpr_native.ci_upper > DEFAULT_FPR_CEILING:
        blockers.append(
            f"fpr_native ci_upper is {fpr_native.ci_upper}, which exceeds "
            f"the ceiling {DEFAULT_FPR_CEILING}"
        )
    return blockers


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
    spec_key: str | None = None,
    slice_id: str | None = None,
    split: str | None = None,
    command: str | None = None,
    runner: str | None = None,
    length_floor: int = 80,
    bootstrap_seed: int | None = None,
    record_id: str | None = None,
    supersedes: str | None = None,
    allow_supported: bool = False,
    known_failure_modes: list[str] | tuple[str, ...] | None = None,
    limitations_extra: list[str] | tuple[str, ...] | None = None,
    appeal_note: str | None = None,
) -> tuple[ValidationRecord, dict]:
    """Build (and dual-validate) one seed ValidationRecord from measured triples.

    ``artifact`` is the verified run provenance from
    :func:`verify_run_artifact`. By default the record is stored as
    ``partial``: no reviewer has assessed it, the samples are
    preliminary strided subsets, and (for RAID) the human slice is
    below 100 rows. With ``allow_supported=True`` the stored status is
    ``supported`` ONLY when every condition in
    :func:`support_gate_blockers` holds (all eight: stored supported,
    no missing mandatory fields, version match, not demoted, due date
    not passed, n_human/n_ai >= 100, contamination ``no``, fpr_native
    CI upper <= 0.05); any failing condition keeps the record
    ``partial`` and the failing conditions are reported in
    ``measurements["support_blockers"]``. The record is signed, then
    checked against BOTH the JSON schema and the Python validator; any
    issue raises ValueError. Returns the record and the full
    measurements dict (which also carries native TPR — a value the
    record schema has no slot for).

    ``bootstrap_seed`` is the run date as a YYYYMMDD stamp (U1 used
    20261106); it is recorded verbatim in every metric method string,
    ``run.seeds.bootstrap_seed`` and the reporting rules. The
    ``record_id`` / ``supersedes`` / ``known_failure_modes`` /
    ``limitations_extra`` / ``appeal_note`` overrides exist for a
    re-seed that supersedes an earlier record (Phase 5 RAID humans-100)
    without rewriting the original seed config — the original config
    still reproduces the original record.

    The ``spec_key`` / ``slice_id`` / ``split`` / ``command`` /
    ``runner`` / ``length_floor`` overrides exist for the U4 segment
    record, whose triples are segments (not documents) from the
    OpAI-Bench sample: its spec is ``opai_bench``, its slice is
    ``opai_bench_segments-builtin-heuristic``, its length floor is 1
    (segments are sentences — a floor of 80 words would misdescribe
    the slice), and its command/runner name the segment script.
    Defaults preserve the document-record behaviour exactly.
    """
    if key not in SEED_CONFIGS:
        raise ValueError(f"no seed config for dataset {key!r}")
    config = SEED_CONFIGS[key]
    spec = get_spec(spec_key or key)
    seed = BOOTSTRAP_SEED if bootstrap_seed is None else bootstrap_seed
    measurements = measure_triples(triples, bootstrap_seed=seed)
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
    if key == "ghostwriter" and n_partial:
        drops.append(
            DropItem(
                item=f"{n_partial} fusion (mixed-origin) rows",
                reason=(
                    "rows with label 2 carry no binary label; "
                    "they are the U4 spine, not U1 evidence"
                ),
            )
        )

    failure_modes = tuple(
        known_failure_modes if known_failure_modes is not None else config["known_failure_modes"]
    )
    extra_limitations = tuple(
        limitations_extra if limitations_extra is not None else config["limitations_extra"]
    )
    note = appeal_note if appeal_note is not None else config["appeal_note"]
    new_record_id = record_id or config["record_id"]
    new_supersedes = supersedes if supersedes is not None else config.get("supersedes")

    def assemble(stored_status: str) -> ValidationRecord:
        record = ValidationRecord(
            record_id=new_record_id,
            detector_id=BuiltinHeuristicDetector.detector_id,
            detector_version=BuiltinHeuristicDetector.detector_version,
            detector_family=BuiltinHeuristicDetector.detector_family,
            calibration_id=None,
            status=stored_status,
            supersedes=new_supersedes,
            regime=Regime(
                language=config.get("language", "en"),
                script=config.get("script", "Latn"),
                language_variety=config.get("language_variety"),
                length_bucket=LengthBucket(
                    min_words=length_floor,
                    max_words=None,
                    floor_words=length_floor,
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
                split=split or SAMPLE_PLAN[key]["split"],
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
                runner=runner or "U1 seed (scripts/seed_validation.py)",
                code_version=artifact["code_version"],
                dependency_lock_sha=None,
                hardware=f"{platform.machine()} ({platform.system()} {platform.release()})",
                runtime=f"CPython {platform.python_version()} on {sys.platform}",
                seeds={"bootstrap_seed": seed},
                command=command or f"python scripts/seed_validation.py --only {key}",
                drops_manifest=tuple(drops),
                reporting_rules=reporting_rules_for_seed(seed),
            ),
            metrics=(
                SliceMetrics(
                    slice_id=slice_id or f"{key}-builtin-heuristic",
                    n_human=measurements["n_human"],
                    n_ai=measurements["n_ai"],
                    auroc=measurements["auroc"],
                    tpr_at_fpr_0_01=measurements["tpr_at_fpr_0_01"],
                    tpr_at_fpr_0_05=measurements["tpr_at_fpr_0_05"],
                    fpr_native=measurements["fpr_native"],
                    tpr_native=measurements["tpr_native"],
                    coverage=measurements["coverage"],
                    abstention_rate=measurements["abstention_rate"],
                    worst_slice=True,
                    fpr_operating_point=NATIVE_OPERATING_POINT,
                ),
            ),
            limits=RecordLimits(
                known_failure_modes=failure_modes,
                limitations=tuple(BASE_LIMITATIONS + list(extra_limitations)),
                next_revalidation_due=default_next_revalidation_due(run_date),
                appeal_note=note,
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
        return signed

    if not allow_supported:
        return assemble("partial"), measurements
    candidate = assemble("supported")
    blockers = support_gate_blockers(candidate, measurements)
    measurements["support_blockers"] = blockers
    if blockers:
        return assemble("partial"), measurements
    return candidate, measurements


def build_record(
    key: str,
    *,
    cache_dir: Path | None = None,
    repo_root: Path = REPO_ROOT,
    run_date: str | None = None,
    cache_filename: str | None = None,
    bootstrap_seed: int | None = None,
    record_id: str | None = None,
    supersedes: str | None = None,
    allow_supported: bool = False,
    known_failure_modes: list[str] | tuple[str, ...] | None = None,
    limitations_extra: list[str] | tuple[str, ...] | None = None,
    appeal_note: str | None = None,
    command: str | None = None,
    runner: str | None = None,
    require_registry_entry: bool = True,
) -> tuple[ValidationRecord, dict]:
    """Build one seed record from the cached sample (no network).

    Re-runs the detector over the cached labelled rows, verifies the
    cache manifest hash against the recomputed cache SHA-256 and the
    U7 artifact hash against the U7 registry, then builds the record.
    Returns the record and the full measurements dict (native TPR
    included — the record schema has no slot for it).

    ``cache_filename`` reads a coexisting second sample of the same
    config/split (e.g. the Phase 5 RAID ``train-6000.jsonl`` next to
    the U1 ``train.jsonl``) instead of the default cache file; its
    manifest is the matching ``.manifest.json``. The remaining
    overrides are passed through to :func:`record_from_triples` (a
    re-seed with its own bootstrap seed / record id / supersedes, and
    the ``supported`` gate); ``require_registry_entry=False`` is the
    registry-hold path, see :func:`verify_run_artifact`.
    """
    if key not in SEED_CONFIGS:
        raise ValueError(f"no seed config for dataset {key!r} (MixSet has no record: no licence)")
    spec = get_spec(key)
    plan = SAMPLE_PLAN[key]
    rows = read_sample_cache(
        spec, plan["config"], plan["split"], cache_dir=cache_dir, filename=cache_filename
    )
    cache_file = cache_path(spec.key, plan["config"], plan["split"], cache_dir=cache_dir)
    if cache_filename is not None:
        cache_file = cache_file.with_name(cache_filename)
        manifest_file = cache_file.with_suffix(".manifest.json")
    else:
        manifest_file = manifest_path(spec.key, plan["config"], plan["split"], cache_dir=cache_dir)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
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
    artifact = verify_run_artifact(
        key, repo_root=repo_root, run_date=run_date, require_registry_entry=require_registry_entry
    )
    return record_from_triples(
        key,
        triples,
        word_counts=word_counts,
        domains=scope["domains"],
        generators=scope["generators"],
        artifact=artifact,
        n_partial=n_partial,
        cache_file_sha256=cache_sha,
        bootstrap_seed=bootstrap_seed,
        record_id=record_id,
        supersedes=supersedes,
        allow_supported=allow_supported,
        known_failure_modes=known_failure_modes,
        limitations_extra=limitations_extra,
        appeal_note=appeal_note,
        command=command,
        runner=runner,
    )


# Segment cache file names (U4). The segment caches live next to the
# OpAI-Bench document caches and hold the SAME strided samples with
# segment ground truth in row meta; the document caches are untouched.
TRAIN_SEGMENTS_FILENAME = "train-segments.jsonl"
DEV_SEGMENTS_FILENAME = "dev-segments.jsonl"
SEGMENT_KEY = "opai_bench_segments"


def build_segment_record(
    *,
    cache_dir: Path | None = None,
    repo_root: Path = REPO_ROOT,
    run_date: str | None = None,
) -> tuple[ValidationRecord, dict]:
    """Build the U4 OpAI-Bench segment record and append it to the registry.

    Reads the segment cache (``train-segments.jsonl``, written by
    scripts/measure_segments.py — the SAME 500-row strided train
    sample as the document record, re-fetched with segment ground
    truth), verifies the manifest hash, expands each cached row into
    its dataset sentences, scores each sentence with the report
    builder's segment scorer (``analyze_text(include_robustness=False)``
    + the declared 0.68/0.32 operating point via
    ``mixed_origin.segment_verdict``), and builds the record via
    :func:`record_from_triples` with the segment overrides. The
    record is appended to the existing validation registry (duplicate
    record ids refused), reloaded and re-verified — the same merge
    discipline as ``seed_validation.py --append``.
    """
    from textforensics.engine import analyze_text
    from textforensics.mixed_origin import segment_verdict

    key = SEGMENT_KEY
    spec = get_spec("opai_bench")
    rows = read_sample_cache(
        spec, "default", "train", cache_dir=cache_dir, filename=TRAIN_SEGMENTS_FILENAME
    )
    cache_file = cache_path("opai_bench", "default", "train", cache_dir=cache_dir).with_name(
        TRAIN_SEGMENTS_FILENAME
    )
    manifest = json.loads(cache_file.with_suffix(".manifest.json").read_text(encoding="utf-8"))
    cache_sha = _sha256_file(cache_file)
    if manifest["file_sha256"] != cache_sha:
        raise ValueError(
            f"{key}: cache manifest file_sha256 {manifest['file_sha256']} != "
            f"recomputed SHA-256 {cache_sha} of {cache_file}"
        )
    triples: list[tuple[int, float, str]] = []
    word_counts: list[int] = []
    domains: set[str] = set()
    generators: set[str] = set()
    for row in rows:
        if row.meta.get("domain"):
            domains.add(str(row.meta["domain"]))
        if row.meta.get("generator"):
            generators.add(str(row.meta["generator"]))
        sentences = row.meta.get("sentences")
        labels = row.meta.get("sentence_labels")
        if (
            not isinstance(sentences, list)
            or not isinstance(labels, list)
            or len(sentences) != len(labels)
        ):
            raise ValueError(
                f"{key}: cached row {row.source_id!r} lacks valid segment meta — "
                "re-run scripts/measure_segments.py"
            )
        for sentence, label in zip(sentences, labels, strict=True):
            result = analyze_text(sentence, include_robustness=False)
            score = float(result.score)
            n_words = len(sentence.split())
            triples.append((int(label), score, segment_verdict(score, n_words)))
            word_counts.append(n_words)
    artifact = verify_run_artifact(key, repo_root=repo_root, run_date=run_date)
    record, measurements = record_from_triples(
        key,
        triples,
        word_counts=word_counts,
        domains=sorted(domains),
        generators=sorted(generators),
        artifact=artifact,
        n_partial=0,
        cache_file_sha256=cache_sha,
        spec_key="opai_bench",
        slice_id="opai_bench_segments-builtin-heuristic",
        split="train",
        command="python scripts/measure_segments.py",
        runner="U4 segment seed (scripts/measure_segments.py)",
        length_floor=1,
    )
    registry_path = repo_root / "docs" / "validation" / "registry.json"
    if not registry_path.exists():
        raise ValueError(f"no existing registry at {registry_path}")
    existing = ValidationRegistry.load(registry_path)
    if existing.record(record.record_id) is not None:
        raise ValueError(f"{record.record_id} already in {registry_path}; refusing")
    merged = ValidationRegistry(
        list(existing.records) + [record],
        created_at_utc=existing.created_at_utc,
    )
    merged.save(registry_path)
    reloaded = ValidationRegistry.load(registry_path)
    print(
        f"Appended segment record {record.record_id} to {registry_path}: "
        f"{len(existing.records)} -> {len(reloaded.records)} records "
        f"(registry_id {reloaded.registry_id[:12]}...), reloaded and re-verified."
    )
    return record, measurements


def seed_registry(
    keys, *, cache_dir: Path | None = None, repo_root: Path = REPO_ROOT, run_date: str | None = None
) -> tuple[ValidationRegistry, dict[str, dict]]:
    """Build all seed records; return the registry and per-record measurements.

    The registry dict is also checked against the validation-registry
    JSON schema. Nothing is written here.
    """
    records: list[ValidationRecord] = []
    measurements: dict[str, dict] = {}
    for key in keys:
        record, measured = build_record(
            key, cache_dir=cache_dir, repo_root=repo_root, run_date=run_date
        )
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
        "Native TPR is carried in the records as the optional tpr_native "
        "metric (evidence-record/v1), paired with fpr_native."
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
        "--run-date",
        default=None,
        help="YYYYMMDD stamp of the U7 artifact to seed from "
        "(default: latest EV-*-dataset-<key>.json in docs/evidence/runs)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="append the new records to the existing registry instead of "
        "rebuilding it from the requested keys (duplicate record ids rejected)",
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
    registry, measurements = seed_registry(
        keys, cache_dir=cache_dir, repo_root=repo_root, run_date=args.run_date
    )
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
    if args.append:
        if not registry_path.exists():
            print(f"--append: no existing registry at {registry_path}")
            return 2
        existing = ValidationRegistry.load(registry_path)
        for record in registry.records:
            if existing.record(record.record_id) is not None:
                print(f"--append: {record.record_id} already in {registry_path}; refusing")
                return 2
        merged = ValidationRegistry(
            list(existing.records) + list(registry.records),
            created_at_utc=existing.created_at_utc,
        )
        merged.save(registry_path)
        reloaded = ValidationRegistry.load(registry_path)
        print(
            f"Appended {len(registry.records)} record(s) to {registry_path}: "
            f"{len(existing.records)} -> {len(reloaded.records)} records "
            f"(registry_id {reloaded.registry_id[:12]}...), reloaded and re-verified."
        )
        return 0
    registry.save(registry_path)
    reloaded = ValidationRegistry.load(registry_path)
    print(
        f"Wrote {registry_path} with {len(reloaded.records)} records "
        f"(registry_id {reloaded.registry_id[:12]}...), reloaded and re-verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
