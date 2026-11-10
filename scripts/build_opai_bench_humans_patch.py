#!/usr/bin/env python3
"""build_opai_bench_humans_patch.py — Build the OpAI-Bench humans-100 registry record as a patch file.

Reads the Phase 5 OpAI-Bench growth sample (``train-2000.jsonl``,
written by ``scripts/measure_opai_bench_humans.py``) and its run
artifact (``EV-20261110-dataset-opai-bench``), builds the superseding
validation record (``evr-20261110-opai-bench-builtin-heuristic``,
superseding ``evr-20261106-opai-bench-builtin-heuristic``) via
``scripts/seed_validation.py`` with bootstrap seed 20261110, and
writes the full record JSON to
``docs/evidence/EV-20261110-opai-bench-registry-patch.json``.

The sample file holds the kept rows only: 2000 rows were fetched and
4 were excluded by ``measure_opai_bench_humans.py`` as U1 duplicates
by content hash (OpAI-Bench repeats each pure-human v0 document once
per generator), so the cache holds 1996 rows and the exclusion is
stated in the record's limitations.

REGISTRY HOLD: this script writes the patch file ONLY. It does NOT
edit ``docs/validation/registry.json`` and does NOT edit
``docs/evidence/registry.json`` — the parent applies the patch. It
also does not run ``seed_evidence``. The run artifact has no evidence
registry entry yet, so the record is built with the registry-hold
verification path (``require_registry_entry=False``); the parent's
apply step rebuilds the evidence registry, which then pins the
artifact SHA-256.

The stored status is ``supported`` ONLY when every condition in
``seed_validation.support_gate_blockers`` holds; otherwise the record
stays ``partial`` and the failing conditions are printed and carried
in the record's limits. The native FPR is reported loudly either way:
a non-zero native FPR on the larger human slice is a finding, not a
detail to bury. The honest Wilson 95% interval for the native FPR
(the bootstrap ``fpr_native`` CI is degenerate ``[0.0, 0.0]`` at zero
false positives) is computed with the repo's own ``wilson_ci`` and
stated in the record's limitations (zero FPs) or failure modes
(non-zero FPs), and printed here.

Usage:
    python scripts/build_opai_bench_humans_patch.py [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from seed_validation import (  # noqa: E402
    aggregate_scope,
    build_record,
    measure_triples,
)

from textforensics.datasets import cache_path, get_spec, read_sample_cache  # noqa: E402
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402
from textforensics.schema import validate_evidence_record  # noqa: E402
from textforensics.validation import (  # noqa: E402
    effective_status,
    missing_mandatory_fields,
    validate_record,
    verify_signature,
)

RUN_DATE = "20261110"
RUN_DATE_ISO = "2026-11-10"
BOOTSTRAP_SEED = 20261110
NEW_FILENAME = "train-2000.jsonl"
FETCHED_ROWS = 2000  # rows fetched by the measure script; the cache holds the kept rows only
RECORD_ID = "evr-20261110-opai-bench-builtin-heuristic"
SUPERSEDES = "evr-20261106-opai-bench-builtin-heuristic"
PATCH_FILENAME = "EV-20261110-opai-bench-registry-patch.json"
COMMAND = "python scripts/build_opai_bench_humans_patch.py"
RUNNER = "Phase 5 release-gate (scripts/build_opai_bench_humans_patch.py)"
APPEAL_NOTE = "A reviewed assessment and per-version reporting would change this record"


def compose_opai_texts(
    measurements: dict,
    domains: list[str],
    *,
    n_partial: int,
    wilson_lo: float,
    wilson_hi: float,
    n_excluded: int = 0,
) -> dict:
    """Compose the new record's failure modes / limitations / appeal note.

    Everything is derived from the measured numbers, never copied from
    the U1 record: the "only 56 human rows" failure mode is gone (the
    human slice is past 100 by construction of this wave), the AUROC
    figure is the new sample's, the TPR@FPR zeros are stated only if
    they are still zero, and the native FPR is stated with its count
    and its Wilson 95% interval — as a failure mode when it is
    non-zero, as a limitation note when it is zero.
    """
    n_human = measurements["n_human"]
    n_ai = measurements["n_ai"]
    n_total = n_human + n_ai
    auroc = measurements["auroc"]
    fpr = measurements["fpr_native"]
    fpr_count = int(round(fpr.value * fpr.n))
    tpr_01 = measurements["tpr_at_fpr_0_01"]
    tpr_05 = measurements["tpr_at_fpr_0_05"]

    known_failure_modes = []
    if auroc.value < 0.5:
        known_failure_modes.append(
            "fully machine text (v8) scores lower than pure human text (v0) "
            f"on this slice: AUROC {auroc.value:.4f} on this sample — the "
            "endpoint comparison inverts the baseline"
        )
    else:
        known_failure_modes.append(
            "heuristic score distributions for human and machine text overlap "
            f"heavily (AUROC {auroc.value:.4f} on this sample)"
        )
    known_failure_modes.append(
        "only the v0/v8 endpoint rows carry binary labels; the partial "
        "rows are excluded from this record"
    )
    if tpr_01.value == 0.0 and tpr_05.value == 0.0:
        known_failure_modes.append("both TPR@1% and TPR@5% FPR are 0.0 on this slice")
    if n_human < 100:
        known_failure_modes.append(
            f"only {n_human} human rows: the human slice is below the "
            "100-row minimum for a supported slice"
        )
    elif fpr.value > 0:
        known_failure_modes.append(
            "native false-positive rate is "
            f"{fpr.value:.4f} ({fpr_count} of {fpr.n} human rows verdict "
            "ai_like at the native operating point; bootstrap 95% CI "
            f"[{fpr.ci_lower:.4f}, {fpr.ci_upper:.4f}], Wilson 95% CI "
            f"[{wilson_lo:.4f}, {wilson_hi:.4f}])"
        )

    limitations_extra = [
        f"the {n_partial} partial (mixed-origin) rows in this sample are "
        "the U4 spine, not U1 evidence, and are excluded from this record",
        "per-version and per-operation detector curves are not reported "
        "in this record (wave-2 concern)",
        "this sample supersedes the U1 500-row sample "
        f"({SUPERSEDES}); the U1 cache is preserved and the two samples "
        "are disjoint by content hash",
        (
            f"phase-shifted strided sample (n={n_total + n_partial + n_excluded} "
            f"rows fetched, {n_excluded} excluded as U1 duplicates by content "
            f"hash, n={n_total + n_partial} kept; +49 rows; endpoint density "
            f"{n_total / (n_total + n_partial):.4f})"
            if n_excluded
            else f"phase-shifted strided sample (n={n_total + n_partial} rows fetched, "
            f"+49 rows; endpoint density {n_total / (n_total + n_partial):.4f})"
        ),
    ]
    if fpr.value == 0:
        limitations_extra.append(
            "native false-positive rate is 0.0 on this sample "
            f"(0 of {fpr.n} human rows verdict ai_like at the native operating point; "
            f"Wilson 95% CI [{wilson_lo:.4f}, {wilson_hi:.4f}])"
        )
    return {
        "known_failure_modes": known_failure_modes,
        "limitations_extra": limitations_extra,
        "appeal_note": APPEAL_NOTE,
    }


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_patch(*, cache_dir: Path | None = None, repo_root: Path = REPO_ROOT) -> dict:
    """Build the record and return its payload dict (no file written)."""
    spec = get_spec("opai_bench")
    rows = read_sample_cache(spec, "default", "train", cache_dir=cache_dir, filename=NEW_FILENAME)
    cache_file = cache_path("opai_bench", "default", "train", cache_dir=cache_dir).with_name(
        NEW_FILENAME
    )
    manifest_path = cache_file.with_suffix(".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_sha = _sha256_file(cache_file)
    if manifest["file_sha256"] != cache_sha:
        raise ValueError(
            f"OpAI-Bench cache manifest file_sha256 {manifest['file_sha256']} != "
            f"recomputed SHA-256 {cache_sha} of {cache_file}"
        )
    print(f"[opai] new cache verified: {len(rows)} rows, sha256 {cache_sha}")

    detector = BuiltinHeuristicDetector()
    labelled = [row for row in rows if row.label is not None]
    n_partial = len(rows) - len(labelled)
    triples = []
    for row in labelled:
        prediction = detector.detect(row.text)
        triples.append((int(row.label), float(prediction.score), str(prediction.verdict)))
    measurements = measure_triples(triples, bootstrap_seed=BOOTSTRAP_SEED)
    n_human = measurements["n_human"]
    k_fp = sum(1 for lab, _, verdict in triples if lab == 0 and verdict == "ai_like")
    wilson_lo, wilson_hi = wilson_ci(k_fp, n_human)
    scope = aggregate_scope("opai_bench", labelled)
    # Rows fetched (2000) minus rows kept in the cache: the difference
    # is the U1-duplicate exclusion performed by the measure script.
    n_excluded = FETCHED_ROWS - len(rows)
    if n_excluded < 0:
        raise ValueError(f"cache holds {len(rows)} rows, more than the {FETCHED_ROWS} fetched")
    texts = compose_opai_texts(
        measurements,
        scope["domains"],
        n_partial=n_partial,
        wilson_lo=wilson_lo,
        wilson_hi=wilson_hi,
        n_excluded=n_excluded,
    )
    print(
        f"[opai] phase-A measurement: n_human={measurements['n_human']} "
        f"n_ai={measurements['n_ai']} n_partial={n_partial} "
        f"auroc={measurements['auroc'].value:.4f} "
        f"fpr_native={measurements['fpr_native'].value:.4f} "
        f"({k_fp} of {n_human}; Wilson 95% CI [{wilson_lo:.4f}, {wilson_hi:.4f}])"
    )

    record, rebuilt = build_record(
        "opai_bench",
        cache_dir=cache_dir,
        repo_root=repo_root,
        run_date=RUN_DATE,
        cache_filename=NEW_FILENAME,
        bootstrap_seed=BOOTSTRAP_SEED,
        record_id=RECORD_ID,
        supersedes=SUPERSEDES,
        allow_supported=True,
        known_failure_modes=texts["known_failure_modes"],
        limitations_extra=texts["limitations_extra"],
        appeal_note=texts["appeal_note"],
        command=COMMAND,
        runner=RUNNER,
        require_registry_entry=False,
    )
    # The phase-B build re-runs the deterministic detector; it must
    # agree with the phase-A measurement the texts were composed from.
    for name in ("auroc", "tpr_at_fpr_0_01", "tpr_at_fpr_0_05", "fpr_native", "tpr_native"):
        if rebuilt[name].value != measurements[name].value:
            raise ValueError(
                f"phase-A/phase-B mismatch on {name}: "
                f"{measurements[name].value} != {rebuilt[name].value}"
            )
    if rebuilt["n_human"] != measurements["n_human"] or rebuilt["n_ai"] != measurements["n_ai"]:
        raise ValueError("phase-A/phase-B mismatch on class counts")
    rebuilt_k_fp = int(round(rebuilt["fpr_native"].value * rebuilt["fpr_native"].n))
    if rebuilt_k_fp != k_fp:
        raise ValueError(f"phase-A/phase-B mismatch on false positives: {k_fp} != {rebuilt_k_fp}")

    payload = record.to_dict()
    schema_issues = validate_evidence_record(payload)
    if schema_issues:
        raise ValueError(f"record fails JSON schema: {schema_issues}")
    python_issues = validate_record(payload)
    if python_issues:
        raise ValueError(f"record fails Python validator: {python_issues}")
    if not verify_signature(payload):
        raise ValueError("record signature does not verify")
    effective = effective_status(record, detector_version=record.detector_version, now=RUN_DATE_ISO)
    blockers = rebuilt.get("support_blockers", [])
    print(f"[opai] record {record.record_id}: stored={record.status}, effective={effective}")
    print(
        f"[opai] support gate blockers: {blockers if blockers else 'none — all 8 conditions hold'}"
    )
    print(
        "[opai] gate conditions: "
        f"stored={record.status!r}; "
        f"missing_mandatory={missing_mandatory_fields(payload)}; "
        f"version={record.detector_version!r}; "
        f"demoted_by={record.limits.demoted_by!r}; "
        f"next_revalidation_due={record.limits.next_revalidation_due}; "
        f"n_human={record.data.n_human} n_ai={record.data.n_ai}; "
        f"contamination={record.data.contamination_flag!r}; "
        f"fpr_native CI=[{record.metrics[0].fpr_native.ci_lower}, "
        f"{record.metrics[0].fpr_native.ci_upper}]; "
        f"fpr_native Wilson 95% CI=[{wilson_lo:.4f}, {wilson_hi:.4f}]"
    )
    if record.metrics[0].fpr_native.value > 0:
        print(
            "!!! NATIVE FPR IS NO LONGER 0.0000: "
            f"{record.metrics[0].fpr_native.value:.4f} "
            f"({k_fp} of {n_human} human rows) !!!"
        )
    return {"record": record, "measurements": rebuilt, "payload": payload}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace the existing patch file if one is already present",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="dataset cache dir (default: XDG cache / TEXTFORENSICS_DATASETS_DIR)",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="repo root for the run artifact and the patch file",
    )
    args = parser.parse_args(argv)
    repo_root = Path(args.repo_root) if args.repo_root else REPO_ROOT
    cache_dir = Path(args.cache_dir) if args.cache_dir else None
    built = build_patch(cache_dir=cache_dir, repo_root=repo_root)
    payload = built["payload"]
    patch_path = repo_root / "docs" / "evidence" / PATCH_FILENAME
    if patch_path.exists() and not args.force:
        print(f"patch file exists, refusing to overwrite (use --force): {patch_path}")
        return 2
    patch_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"[opai] wrote {patch_path} (sha256 {_sha256_file(patch_path)})")
    record = built["record"]
    metrics = record.metrics[0]
    print(
        f"[opai] {record.record_id}: status={record.status} "
        f"n_human={metrics.n_human} n_ai={metrics.n_ai} "
        f"auroc={metrics.auroc.value:.4f} [{metrics.auroc.ci_lower:.4f}, {metrics.auroc.ci_upper:.4f}] "
        f"tpr@1%={metrics.tpr_at_fpr_0_01.value:.4f} "
        f"tpr@5%={metrics.tpr_at_fpr_0_05.value:.4f} "
        f"fpr_native={metrics.fpr_native.value:.4f} "
        f"[{metrics.fpr_native.ci_lower:.4f}, {metrics.fpr_native.ci_upper:.4f}] "
        f"tpr_native={metrics.tpr_native.value:.4f} "
        f"abstention={metrics.abstention_rate:.4f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
