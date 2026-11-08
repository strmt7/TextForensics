#!/usr/bin/env python3
"""build_raid_humans_patch.py — Build the RAID humans-100 registry record as a patch file.

Reads the Phase 5 RAID sample (``train-6000.jsonl``, written by
``scripts/measure_raid_humans.py``) and its run artifact
(``EV-20261108-dataset-raid``), builds the superseding validation
record (``evr-20261108-raid-builtin-heuristic``, superseding
``evr-20261106-raid-builtin-heuristic``) via
``scripts/seed_validation.py`` with bootstrap seed 20261108, and
writes the full record JSON to
``docs/evidence/EV-20261108-raid-humans-registry-patch.json``.

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
detail to bury.

Usage:
    python scripts/build_raid_humans_patch.py [--force]
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
from textforensics.schema import validate_evidence_record  # noqa: E402
from textforensics.validation import (  # noqa: E402
    effective_status,
    missing_mandatory_fields,
    validate_record,
    verify_signature,
)

RUN_DATE = "20261108"
RUN_DATE_ISO = "2026-11-08"
BOOTSTRAP_SEED = 20261108
NEW_FILENAME = "train-6000.jsonl"
RECORD_ID = "evr-20261108-raid-builtin-heuristic"
SUPERSEDES = "evr-20261106-raid-builtin-heuristic"
PATCH_FILENAME = "EV-20261108-raid-humans-registry-patch.json"
COMMAND = "python scripts/build_raid_humans_patch.py"
RUNNER = "Phase 5 release-gate (scripts/build_raid_humans_patch.py)"
APPEAL_NOTE = "A reviewed assessment and per-attack reporting would change this record"


def compose_raid_texts(measurements: dict, domains: list[str]) -> dict:
    """Compose the new record's failure modes / limitations / appeal note.

    Everything is derived from the measured numbers, never copied from
    the U1 record: the "only 92 human rows" failure mode is gone (the
    human slice is past 100 by construction of this wave), the AUROC
    figure is the new sample's, and the native FPR is stated with its
    count — as a failure mode when it is non-zero, as a limitation
    note when it is zero.
    """
    n_human = measurements["n_human"]
    n_ai = measurements["n_ai"]
    n_total = n_human + n_ai
    auroc = measurements["auroc"]
    fpr = measurements["fpr_native"]
    fpr_count = int(round(fpr.value * fpr.n))

    known_failure_modes = [
        "heuristic score distributions for human and machine text overlap "
        f"heavily (AUROC {auroc.value:.4f} on this sample)",
        "adversarial attack variants (whitespace, case, paragraph insertion, "
        "article deletion) are pooled into this slice and not reported separately",
    ]
    if n_human < 100:
        known_failure_modes.append(
            f"only {n_human} human rows: the human slice is below the "
            "100-row minimum for a supported slice"
        )
    elif fpr.value > 0:
        known_failure_modes.append(
            "native false-positive rate is "
            f"{fpr.value:.4f} ({fpr_count} of {fpr.n} human rows verdict "
            "ai_like at the native operating point; 95% CI "
            f"[{fpr.ci_lower:.4f}, {fpr.ci_upper:.4f}])"
        )

    limitations_extra = [
        "attack slices are not reported separately in this record (wave-2 concern)",
        "the strided sample covers only the domains observed in the cache "
        f"({', '.join(domains)}); other RAID domains are not "
        "represented in this sample",
        "this sample supersedes the U1 3000-row sample "
        f"({SUPERSEDES}); the U1 cache is preserved and the two samples "
        "are disjoint by content hash",
        f"phase-shifted strided sample (n={n_total}, +189 rows; "
        f"human density {n_human / n_total:.4f})",
    ]
    if fpr.value == 0:
        limitations_extra.append(
            "native false-positive rate is 0.0 on this sample "
            f"(0 of {fpr.n} human rows verdict ai_like at the native operating point)"
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
    spec = get_spec("raid")
    rows = read_sample_cache(spec, "raid", "train", cache_dir=cache_dir, filename=NEW_FILENAME)
    cache_file = cache_path("raid", "raid", "train", cache_dir=cache_dir).with_name(NEW_FILENAME)
    manifest_path = cache_file.with_suffix(".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_sha = _sha256_file(cache_file)
    if manifest["file_sha256"] != cache_sha:
        raise ValueError(
            f"RAID cache manifest file_sha256 {manifest['file_sha256']} != "
            f"recomputed SHA-256 {cache_sha} of {cache_file}"
        )
    print(f"[raid] new cache verified: {len(rows)} rows, sha256 {cache_sha}")

    detector = BuiltinHeuristicDetector()
    labelled = [row for row in rows if row.label is not None]
    triples = []
    for row in labelled:
        prediction = detector.detect(row.text)
        triples.append((int(row.label), float(prediction.score), str(prediction.verdict)))
    measurements = measure_triples(triples, bootstrap_seed=BOOTSTRAP_SEED)
    scope = aggregate_scope("raid", labelled)
    texts = compose_raid_texts(measurements, scope["domains"])
    print(
        f"[raid] phase-A measurement: n_human={measurements['n_human']} "
        f"n_ai={measurements['n_ai']} auroc={measurements['auroc'].value:.4f} "
        f"fpr_native={measurements['fpr_native'].value:.4f}"
    )

    record, rebuilt = build_record(
        "raid",
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
    print(f"[raid] record {record.record_id}: stored={record.status}, effective={effective}")
    print(
        f"[raid] support gate blockers: {blockers if blockers else 'none — all 8 conditions hold'}"
    )
    print(
        "[raid] gate conditions: "
        f"stored={record.status!r}; "
        f"missing_mandatory={missing_mandatory_fields(payload)}; "
        f"version={record.detector_version!r}; "
        f"demoted_by={record.limits.demoted_by!r}; "
        f"next_revalidation_due={record.limits.next_revalidation_due}; "
        f"n_human={record.data.n_human} n_ai={record.data.n_ai}; "
        f"contamination={record.data.contamination_flag!r}; "
        f"fpr_native CI=[{record.metrics[0].fpr_native.ci_lower}, "
        f"{record.metrics[0].fpr_native.ci_upper}]"
    )
    if record.metrics[0].fpr_native.value > 0:
        print(
            "!!! NATIVE FPR IS NO LONGER 0.0000: "
            f"{record.metrics[0].fpr_native.value:.4f} "
            f"({int(round(record.metrics[0].fpr_native.value * record.metrics[0].fpr_native.n))} "
            f"of {record.metrics[0].fpr_native.n} human rows) !!!"
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
    print(f"[raid] wrote {patch_path} (sha256 {_sha256_file(patch_path)})")
    record = built["record"]
    metrics = record.metrics[0]
    print(
        f"[raid] {record.record_id}: status={record.status} "
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
