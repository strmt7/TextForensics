#!/usr/bin/env python3
"""build_human_fpr_run_artifact.py — Re-express the human-FPR evidence as a
run-artifact/v1 record, without changing any value and without
misrepresenting what the artifact is.

Question answered here (2026-11-10): can the standalone human-FPR evidence
(``docs/evidence/EV-20261108-human-fpr.json``, schema
``textforensics.human-fpr-evidence/v1`` — not a registered schema, so it
cannot be pinned in the evidence registry) conform to the registered
``textforensics.run-artifact/v1`` schema? Answer: YES — and this script is
the proof, by construction. It re-runs the measurement fresh (importing
``scripts/measure_human_fpr.py``'s own measurement code, same 7 slices),
checks the fresh values reproduce the 2026-11-08 artifact exactly, then
re-expresses them in run-artifact shape and validates the result with the
repo's own gate validator (``scripts/check_claims.py`` ``_schema_errors``
against ``run-artifact.schema.json``). Any validation error or any
reproduction mismatch fails loudly; nothing is written.

Why the re-expression is honest, not a hack:

* The FPR measurement IS one measured run: ``python
  scripts/measure_human_fpr.py`` re-ran the deterministic detector over
  cached rows and produced measured numbers. ``kind: "command"`` is the
  same kind every dataset run artifact carries (e.g.
  ``EV-20261108-dataset-raid.json``), and ``results`` is a free-form
  object that already carries nested measurement tables in those
  artifacts. Nothing here claims a benchmark run the artifact is not.
* Every measured value is preserved verbatim, relocated into ``results``
  (slices table, pooled numbers, worst-slice Wilson uppers, method,
  detector id/family/version). The two assessments (``pooling_assessment``
  and ``still_unknown``) are prose, so they move verbatim into ``notes``.
  ``check_value_preservation`` verifies this field by field; a dropped
  or altered value fails the build.
* The report-card lead does NOT change. The gate's ``worst_slice_fpr``
  looks for ``results["worst_slice_human_fpr"]`` (or
  ``results["human_fpr"]["worst_slice"]``). The preserved key is
  ``worst_slice_wilson_ci_upper`` — a Wilson upper bound on a 0/56 rate,
  not a measured FPR point rate — and this builder REFUSES to introduce
  either lead-flipping key: relabelling a confidence bound as "the
  worst-slice FPR" would misrepresent a bound as a rate and flip the
  report-card lead to a number no claim supports. Even if the parent pins
  this artifact, the lead stays "unknown" until a claim is written and
  the lead logic changes by parent decision.
* ``badge`` is ``available`` (committed and hash-verified once pinned).
  ``functional``/``reproduced`` are not claimed: the gate has not re-run
  this command and CI has not reproduced these numbers.
* No claim is added or restated, no registry file is edited by this
  script, and ``EV-20261108-human-fpr.json`` is untouched. Pinning the
  new artifact in ``docs/evidence/registry.json`` is a parent apply step.

Drops (honest exclusions of this run): the fresh RAID record
``evr-20261108-raid-builtin-heuristic`` (n=171 humans) is NOT measured
here — this run reproduces the 2026-11-08 slice set, whose RAID row is
the 20261106 record (n=92); per-language / per-domain / per-generator
finer slices are not reported separately; Python versions other than the
run's own are not measured here.

One documented drift between the 2026-11-08 artifact and this re-run:
each slice's ``registry_fpr_native`` quotes the validation registry at
run time, and the parent applied the Wilson-CI replacement on 2026-11-08,
so the fresh quotation carries the Wilson upper bound and method where
the old artifact quoted the degenerate bootstrap ``[0.0, 0.0]``. The
measured values are identical; only the registry quotation moved, and
only in that exact pattern (``check_reproduction`` enforces it and the
drift is disclosed in the artifact's notes). No other field drifts.

Usage:
    python scripts/build_human_fpr_run_artifact.py [--check]
    python scripts/build_human_fpr_run_artifact.py --output <path>
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

RUN_DATE = "2026-11-10"
ARTIFACT_ID = "EV-20261110-human-fpr"
SOURCE_ARTIFACT_ID = "EV-20261108-human-fpr"
RUN_ARTIFACT_SCHEMA = "textforensics.run-artifact/v1"

DROPS = [
    {
        "item": "RAID record evr-20261108-raid-builtin-heuristic (n=171 humans)",
        "reason": (
            "this run reproduces the 2026-11-08 slice set, whose RAID row "
            "is the 20261106 record (n=92 humans); the n=171 record is "
            "separate evidence with its own run artifact "
            "EV-20261108-dataset-raid"
        ),
    },
    {
        "item": "per-language / per-domain / per-generator finer slices",
        "reason": (
            "the registry reports one pooled slice per dataset; finer "
            "slices are wave-2 work and were not measured by this run"
        ),
    },
    {
        "item": "human populations and regimes outside the registry slices",
        "reason": (
            "non-English document text outside DetectRL-X/GhostWriter, "
            "ESL human text, texts below 80 words, generators newer than "
            "each record's declared vintage — none of these are in the "
            "measured slices"
        ),
    },
    {
        "item": "Python 3.11, 3.13, 3.14, 3.15",
        "reason": "measured on the local interpreter only; CI covers the matrix",
    },
]

# Keys the gate's worst_slice_fpr() reads to set the report-card lead.
# A Wilson CI upper bound is not a measured FPR point rate, so neither
# key may appear in this artifact's results. Enforced by reshape.
LEAD_FLIPPING_KEYS = ("worst_slice_human_fpr", "human_fpr")

NON_CONCLUSION = (
    "This artifact re-expresses EV-20261108-human-fpr in run-artifact/v1 "
    "shape with every measured value unchanged. It is not a new claim and "
    "it does not change the report-card lead: the gate reads "
    'results["worst_slice_human_fpr"] for the lead, and this artifact '
    "deliberately carries no such key — 0.0642 is the Wilson 95% upper "
    "bound on a 0/56 rate (OpAI-Bench 20261106), not a measured FPR point "
    "rate. No claim cites this record; the worst-slice human FPR as a "
    "supported claim remains unknown."
)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _code_version() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reshape_fpr_to_run_artifact(
    old: dict,
    *,
    evidence_record_id: str,
    run_date: str,
    code_version: str,
    command: str,
    drops: list[dict],
    badge: str = "available",
    environment: dict | None = None,
    provenance_note: str | None = None,
) -> dict:
    """Re-express a human-FPR evidence dict in run-artifact/v1 shape.

    Pure function. Every measured value moves verbatim into ``results``;
    the two prose assessments move verbatim into ``notes``. Raises
    ``ValueError`` if the input already carries a lead-flipping key or
    lacks a field the re-expression needs — a lossy or misleading input
    must never produce a conforming-looking artifact. ``provenance_note``
    (when given) is appended to ``notes`` verbatim, e.g. to disclose a
    registry change between the source run and this re-run.
    """
    for key in LEAD_FLIPPING_KEYS:
        if key in old:
            raise ValueError(
                f"refusing to reshape: input already carries {key!r}, "
                "which the gate reads as the report-card lead"
            )
    required = (
        "detector",
        "detector_version",
        "detector_family",
        "method",
        "pooling_assessment",
        "slices",
        "pooled_documents_only",
        "pooled_all_slices_including_segments",
        "worst_slice_wilson_ci_upper",
        "worst_document_slice_wilson_ci_upper",
        "still_unknown",
        "environment",
    )
    missing = [key for key in required if key not in old]
    if missing:
        raise ValueError(f"input is missing fields the re-expression needs: {missing}")
    if not isinstance(old["still_unknown"], list) or not all(
        isinstance(item, str) for item in old["still_unknown"]
    ):
        raise ValueError("input still_unknown must be a list of strings")
    notes = (
        old["pooling_assessment"]
        + "\n\nStill unknown:\n"
        + "\n".join(f"- {item}" for item in old["still_unknown"])
        + "\n\n"
        + NON_CONCLUSION
    )
    if provenance_note:
        notes += "\n\n" + provenance_note
    artifact = {
        "schema": RUN_ARTIFACT_SCHEMA,
        "evidence_record_id": evidence_record_id,
        "kind": "command",
        "command": command,
        "environment": dict(environment if environment is not None else old["environment"]),
        "code_version": code_version,
        "run_date": run_date,
        "results": {
            "detector": old["detector"],
            "detector_family": old["detector_family"],
            "detector_version": old["detector_version"],
            "method": old["method"],
            "slices": old["slices"],
            "pooled_documents_only": old["pooled_documents_only"],
            "pooled_all_slices_including_segments": (old["pooled_all_slices_including_segments"]),
            "worst_slice_wilson_ci_upper": old["worst_slice_wilson_ci_upper"],
            "worst_document_slice_wilson_ci_upper": (old["worst_document_slice_wilson_ci_upper"]),
        },
        "drops": drops,
        "badge": badge,
        "detector_version": old["detector_version"],
        "notes": notes,
    }
    return artifact


def check_value_preservation(old: dict, new: dict) -> list[str]:
    """Verify every value of the old artifact survives in the new one.

    Pure function. Returns a list of mismatch descriptions (empty means
    fully preserved). Compares measured values by deep equality and
    prose assessments by verbatim containment in ``notes``.
    """
    mismatches: list[str] = []
    results = new.get("results", {})
    for key in (
        "detector",
        "detector_version",
        "detector_family",
        "method",
        "slices",
        "pooled_documents_only",
        "pooled_all_slices_including_segments",
        "worst_slice_wilson_ci_upper",
        "worst_document_slice_wilson_ci_upper",
    ):
        if results.get(key) != old.get(key):
            mismatches.append(f"results[{key!r}] differs from the source artifact")
    notes = new.get("notes", "")
    if old.get("pooling_assessment", "") not in notes:
        mismatches.append("pooling_assessment is not verbatim in notes")
    for item in old.get("still_unknown", []):
        if item not in notes:
            mismatches.append(f"still_unknown item not verbatim in notes: {item[:60]!r}")
    if new.get("detector_version") != old.get("detector_version"):
        mismatches.append("top-level detector_version differs from the source artifact")
    if new.get("schema") != RUN_ARTIFACT_SCHEMA:
        mismatches.append("schema is not textforensics.run-artifact/v1")
    for key in LEAD_FLIPPING_KEYS:
        if key in results:
            mismatches.append(f"results carries {key!r}, which would flip the report-card lead")
    return mismatches


def validate_run_artifact(artifact: dict, root: Path | None = None) -> list[str]:
    """Validate an artifact with the repo's own gate validator.

    Loads ``run-artifact.schema.json`` and runs
    ``scripts/check_claims.py::_schema_errors`` — the exact function
    ``verify_registry_records`` uses for every pinned registry artifact.
    Returns the error list (empty means the artifact conforms).
    """
    root = root or REPO_ROOT
    check_claims = _load_module("check_claims_for_validation", root / "scripts" / "check_claims.py")
    schema = check_claims._load_schema(root, "run-artifact.schema.json")
    return check_claims._schema_errors(schema, artifact)


def measure_fresh_fpr(*, cache_dir: Path | None = None) -> dict:
    """Fresh re-measurement of the 7 FPR slices, in old-artifact shape.

    Imports ``scripts/measure_human_fpr.py`` and calls its own
    measurement functions (same slices, same registry checks, same
    Wilson helpers) so the fresh numbers are produced by the same code
    that produced EV-20261108-human-fpr.json. Returns the assembled
    old-shape artifact dict (no files written).
    """
    measure = _load_module("measure_human_fpr", REPO_ROOT / "scripts" / "measure_human_fpr.py")
    registry = json.loads(
        (REPO_ROOT / "docs" / "validation" / "registry.json").read_text(encoding="utf-8")
    )
    slices = [
        measure.measure_slice(slice_def, registry, cache_dir=cache_dir)
        for slice_def in measure.SLICES
    ]
    doc_counts = [
        (s["fpr_native_wilson"]["k"], s["n_human"]) for s in slices if s["slice_kind"] == "document"
    ]
    all_counts = [(s["fpr_native_wilson"]["k"], s["n_human"]) for s in slices]
    pooled_documents = measure._rate_out(measure.pooled_rate(doc_counts)) if doc_counts else None
    pooled_all = measure._rate_out(measure.pooled_rate(all_counts)) if all_counts else None
    return {
        "schema": "textforensics.human-fpr-evidence/v1",
        "evidence_record_id": SOURCE_ARTIFACT_ID,
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
        "worst_slice_wilson_ci_upper": (
            max(s["fpr_native_wilson"]["ci_upper"] for s in slices) if slices else None
        ),
        "worst_document_slice_wilson_ci_upper": (
            max(s["fpr_native_wilson"]["ci_upper"] for s in slices if s["slice_kind"] == "document")
            if doc_counts
            else None
        ),
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


def check_reproduction(fresh: dict, committed: dict) -> dict:
    """Fresh re-run must reproduce the committed 2026-11-08 values exactly.

    Returns ``{"mismatches": [...], "registry_echo_drift": [...]}``.
    Measured values (slice counts, Wilson rates, max scores, pooled
    numbers, worst uppers, method, assessments) must match exactly — any
    difference is a mismatch and fails the build.

    One documented exception: each slice's ``registry_fpr_native`` is a
    quotation of the validation registry at run time, and the registry
    moved between the two runs — the parent applied the Wilson-CI
    replacement on 2026-11-08, so the fresh quotation carries the Wilson
    upper bound and method where the committed artifact quoted the
    degenerate bootstrap ``[0.0, 0.0]``. That drift is allowed ONLY in
    its exact pattern (value and n identical; fresh method is the Wilson
    method; fresh ci_upper equals the slice's own Wilson fpr ci_upper;
    ci_lower stays 0.0) and is reported in ``registry_echo_drift`` for
    disclosure in the artifact's notes. Any other registry-echo
    difference — including any drift in ``registry_tpr_native``, which
    the replacement did not touch — is a mismatch.
    """
    mismatches: list[str] = []
    echo_drift: list[str] = []
    for key in (
        "pooled_documents_only",
        "pooled_all_slices_including_segments",
        "worst_slice_wilson_ci_upper",
        "worst_document_slice_wilson_ci_upper",
        "method",
        "pooling_assessment",
        "still_unknown",
        "detector",
        "detector_version",
        "detector_family",
    ):
        if fresh.get(key) != committed.get(key):
            mismatches.append(f"{key!r} differs between the fresh run and {SOURCE_ARTIFACT_ID}")
    echo_fields = ("registry_fpr_native", "registry_tpr_native")
    fresh_slices = [
        {k: v for k, v in s.items() if k not in echo_fields} for s in fresh.get("slices", [])
    ]
    committed_slices = [
        {k: v for k, v in s.items() if k not in echo_fields} for s in committed.get("slices", [])
    ]
    if fresh_slices != committed_slices:
        mismatches.append(
            f"'slices' measured values differ between the fresh run and {SOURCE_ARTIFACT_ID}"
        )
    fresh_by_id = {s["record_id"]: s for s in fresh.get("slices", [])}
    committed_by_id = {s["record_id"]: s for s in committed.get("slices", [])}
    if set(fresh_by_id) != set(committed_by_id):
        mismatches.append(f"slice record_ids differ between the fresh run and {SOURCE_ARTIFACT_ID}")
    for record_id in sorted(set(fresh_by_id) & set(committed_by_id)):
        fresh_slice = fresh_by_id[record_id]
        committed_slice = committed_by_id[record_id]
        for field in echo_fields:
            fresh_echo = fresh_slice.get(field)
            committed_echo = committed_slice.get(field)
            if fresh_echo is None or committed_echo is None:
                mismatches.append(
                    f"{record_id}: {field!r} missing in the fresh run or in {SOURCE_ARTIFACT_ID}"
                )
                continue
            if fresh_echo == committed_echo:
                continue
            if (
                field == "registry_fpr_native"
                and fresh_echo["value"] == committed_echo["value"]
                and fresh_echo["n"] == committed_echo["n"]
                and fresh_echo["ci_lower"] == committed_echo["ci_lower"] == 0.0
                and committed_echo["method"].startswith("bootstrap")
                and fresh_echo["method"].startswith("Wilson")
                and fresh_echo["ci_upper"] == fresh_slice["fpr_native_wilson"]["ci_upper"]
            ):
                echo_drift.append(
                    f"{record_id}: registry_fpr_native quotes the registry "
                    "as of 2026-11-10 (Wilson ci_upper "
                    f"{fresh_echo['ci_upper']}, Wilson method) where "
                    f"{SOURCE_ARTIFACT_ID} quoted the degenerate "
                    "bootstrap [0.0, 0.0]; value and n unchanged"
                )
                continue
            mismatches.append(
                f"{record_id}: {field!r} differs between the fresh run and "
                f"{SOURCE_ARTIFACT_ID} outside the documented Wilson "
                "replacement pattern"
            )
    return {"mismatches": mismatches, "registry_echo_drift": echo_drift}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="measure, reshape and validate only; write no artifact file",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="artifact path (default: docs/evidence/runs/EV-20261110-human-fpr.json)",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="dataset cache dir (default: XDG cache / TEXTFORENSICS_DATASETS_DIR)",
    )
    args = parser.parse_args(argv)
    cache_dir = Path(args.cache_dir) if args.cache_dir else None

    committed_path = REPO_ROOT / "docs" / "evidence" / f"{SOURCE_ARTIFACT_ID}.json"
    committed = json.loads(committed_path.read_text(encoding="utf-8"))
    fresh = measure_fresh_fpr(cache_dir=cache_dir)
    repro = check_reproduction(fresh, committed)
    if repro["mismatches"]:
        print(
            f"REPRODUCTION FAILURE: fresh re-run does not reproduce {SOURCE_ARTIFACT_ID}:",
            file=sys.stderr,
        )
        for item in repro["mismatches"]:
            print(f"  - {item}", file=sys.stderr)
        return 2
    provenance_note = None
    if repro["registry_echo_drift"]:
        provenance_note = (
            "Registry-echo note (2026-11-10 re-run): each slice's "
            "registry_fpr_native quotes the validation registry as it "
            "stands now. The parent applied the Wilson-CI replacement on "
            "2026-11-08, so the fresh quotation carries the Wilson upper "
            "bound and method where EV-20261108-human-fpr quoted the "
            "degenerate bootstrap [0.0, 0.0]; the registry fpr value and n "
            "are unchanged, and every measured value reproduces "
            "EV-20261108-human-fpr exactly. Detail per slice:\n"
            + "\n".join(f"- {line}" for line in repro["registry_echo_drift"])
        )

    artifact = reshape_fpr_to_run_artifact(
        fresh,
        evidence_record_id=ARTIFACT_ID,
        run_date=RUN_DATE,
        code_version=_code_version(),
        command="python scripts/build_human_fpr_run_artifact.py",
        drops=DROPS,
        environment={
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        provenance_note=provenance_note,
    )
    preservation = check_value_preservation(fresh, artifact)
    if preservation:
        print("PRESERVATION FAILURE: values lost in the re-expression:", file=sys.stderr)
        for item in preservation:
            print(f"  - {item}", file=sys.stderr)
        return 2
    errors = validate_run_artifact(artifact)
    print(f"fresh re-run reproduces {SOURCE_ARTIFACT_ID} exactly ({len(fresh['slices'])} slices)")
    print(
        f"registry-echo drift (documented Wilson replacement): "
        f"{len(repro['registry_echo_drift'])} slices"
    )
    for line in repro["registry_echo_drift"]:
        print(f"  - {line}")
    print(f"value preservation: {len(preservation)} mismatches")
    print(f"run-artifact/v1 validation errors: {len(errors)}")
    for error in errors:
        print(f"  - {error}")
    if errors:
        return 2
    print(
        "verdict: CAN honestly conform — every value preserved, "
        "0 schema errors, report-card lead unchanged "
        "(no worst_slice_human_fpr key)"
    )
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
