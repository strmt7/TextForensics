#!/usr/bin/env python3
"""Exact-SHA candidate-promotion gate for TextForensics (ENG-04 / ENG-14).

A candidate source SHA may be promoted (GitHub Release publication or
container tag promotion) only when every REQUIRED acceptance result exists
and passed for that exact SHA. Missing, skipped, failed, stale-SHA or
incomplete required results all block promotion.

Gate-status vocabulary (shared contract, W0): ``pass``, ``fail``,
``skipped``, ``unavailable``, ``not_applicable``, ``zero_work``. Required
gates accept ONLY ``pass``.

The gate reads GitHub check-runs for the candidate SHA with a read-only
``gh api`` GET. It never creates releases, tags, or registry writes, and
never invokes a remote-writing command. Exit codes mirror the canonical
verification command contract: 0 promotion allowed, 1 blocked, 2 the gate
itself could not be evaluated (check-runs unavailable).

Required-check set (check-run display names are "<workflow> / <job>";
prefix matching covers matrix jobs, where EVERY matched run must pass):

- claims:             CI / Claims-to-evidence gate (U7)
- full-pytest:        CI / Core Python (matrix 3.11-3.15, canonical pytest)
- pinned:             CI / Pinned requirements install
- locked-sbom:        CI / Checked-in SBOM is not stale
- installed-web:      CI / Build and wheel-install (installed-distribution
                       checks; the web-UI resource defect ENG-01 is W6-owned
                       and the job's own coverage of it is limited)
- pip-audit:          Supply-chain security / pip-audit gate
- supply-chain-sbom:  Supply-chain security / Software Bill of Materials
- reproducibility:    Reproducibility / Build Reproducibility
- integrity-sigstore: Repository Integrity / Sigstore Verification
- integrity-provenance: Repository Integrity / Build Provenance
- deep-verification:  Enterprise Deep Verification / Full Test Suite (matrix)

Note: the integrity and deep-verification workflows run on schedule /
workflow_dispatch, not on push. They must be explicitly dispatched for the
candidate SHA before promotion; until their check-runs exist for that SHA
the gate reports ``unavailable`` and blocks promotion. That is intentional:
absence of evidence is not evidence of passing.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

GATE_STATUSES = ("pass", "fail", "skipped", "unavailable", "not_applicable", "zero_work")

# Each entry: key, check-run display-name prefix, human description.
# "matrix": True means several check-runs share the prefix (one per matrix
# leg); ALL of them must pass.
REQUIRED_CHECKS: list[dict] = [
    {
        "key": "claims",
        "check": "CI / Claims-to-evidence gate (U7)",
        "description": "claims-to-evidence gate (U7)",
    },
    {
        "key": "full-pytest",
        "check": "CI / Core Python",
        "description": "full canonical pytest collection (matrix)",
        "matrix": True,
    },
    {
        "key": "pinned",
        "check": "CI / Pinned requirements install",
        "description": "pinned-requirements install",
    },
    {
        "key": "locked-sbom",
        "check": "CI / Checked-in SBOM is not stale",
        "description": "locked SBOM is not stale",
    },
    {
        "key": "installed-web",
        "check": "CI / Build and wheel-install",
        "description": "installed wheel / packaged-schema checks",
    },
    {
        "key": "pip-audit",
        "check": "Supply-chain security / pip-audit gate (baseline, fail on new findings)",
        "description": "pip-audit gate (baseline, fail on new findings)",
    },
    {
        "key": "supply-chain-sbom",
        "check": "Supply-chain security / Software Bill of Materials",
        "description": "supply-chain SBOM generation",
    },
    {
        "key": "reproducibility",
        "check": "Reproducibility / Build Reproducibility",
        "description": "build reproducibility",
    },
    {
        "key": "integrity-sigstore",
        "check": "Repository Integrity / Sigstore Verification",
        "description": "repository integrity (Sigstore verification)",
    },
    {
        "key": "integrity-provenance",
        "check": "Repository Integrity / Build Provenance",
        "description": "repository integrity (build provenance)",
    },
    {
        "key": "deep-verification",
        "check": "Enterprise Deep Verification / Full Test Suite",
        "description": "enterprise deep verification full test suite (matrix)",
        "matrix": True,
    },
]


class PromotionGateError(Exception):
    """The gate itself could not be evaluated (exit 2)."""


def _matches(name: str, prefix: str) -> bool:
    """Exact display-name match, or a matrix leg of that job."""
    return name == prefix or name.startswith(prefix + " ")


def _status_for(run: dict, candidate_sha: str) -> tuple[str, str]:
    """Map one check-run record to (status, reason) in gate vocabulary."""
    if run.get("head_sha") != candidate_sha:
        return "fail", f"stale SHA {run.get('head_sha')} != candidate {candidate_sha}"
    if run.get("status") != "completed":
        return "unavailable", f"check-run not completed (status={run.get('status')})"
    conclusion = run.get("conclusion")
    if conclusion == "success":
        return "pass", "success at candidate SHA"
    if conclusion == "skipped":
        return "skipped", "required check was skipped"
    if conclusion in ("failure", "cancelled", "timed_out", "action_required"):
        return "fail", f"conclusion={conclusion}"
    if conclusion is None:
        return "unavailable", "no conclusion recorded"
    return "unavailable", f"unrecognised conclusion={conclusion!r}"


def evaluate_gate(
    check_runs: list[dict],
    candidate_sha: str,
    required: list[dict] | None = None,
) -> dict:
    """Decide promotion for ``candidate_sha`` from check-run records.

    Returns ``{"overall_pass": bool, "gates": {key: {"status", "reason",
    "matched"}}}``. Every required gate must be ``pass`` with positive
    executed work at the exact candidate SHA; anything else blocks.
    """
    required = REQUIRED_CHECKS if required is None else required
    gates: dict[str, dict] = {}
    overall = True
    for spec in required:
        matched = [r for r in check_runs if _matches(r.get("name", ""), spec["check"])]
        if not matched:
            gates[spec["key"]] = {
                "status": "unavailable",
                "reason": f"no check-run named {spec['check']!r} for candidate SHA",
                "matched": [],
            }
            overall = False
            continue
        statuses = [_status_for(r, candidate_sha) for r in matched]
        # Worst status wins: fail > skipped > unavailable > pass.
        order = {"fail": 0, "skipped": 1, "unavailable": 2, "pass": 3}
        worst_status, worst_reason = min(statuses, key=lambda s: order[s[0]])
        gates[spec["key"]] = {
            "status": worst_status,
            "reason": worst_reason,
            "matched": [r.get("name") for r in matched],
        }
        if worst_status != "pass":
            overall = False
    return {"overall_pass": overall, "gates": gates}


def fetch_check_runs(
    owner: str,
    repo: str,
    sha: str,
    runner=None,
) -> list[dict]:
    """Read-only fetch of check-runs for ``sha`` via ``gh api`` (GET).

    ``runner`` is an injectable ``subprocess.run``-compatible callable used
    by tests; the default performs the real read-only call. Only a GET is
    ever issued; no remote-writing ``gh`` subcommand is used here.
    """
    run = runner or subprocess.run
    endpoint = f"repos/{owner}/{repo}/commits/{sha}/check-runs?per_page=100"
    try:
        result = run(
            ["gh", "api", endpoint],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as exc:  # subprocess / gh failure: gate unevaluated
        raise PromotionGateError(f"could not fetch check-runs for {sha}: {exc}") from exc
    try:
        payload = json.loads(result.stdout)
    except (json.JSONDecodeError, AttributeError) as exc:
        raise PromotionGateError(f"could not parse check-runs for {sha}: {exc}") from exc
    runs = payload.get("check_runs", [])
    return [
        {
            "name": r.get("name"),
            "status": r.get("status"),
            "conclusion": r.get("conclusion"),
            "head_sha": r.get("head_sha"),
        }
        for r in runs
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", default=None, help="Candidate source SHA (full).")
    parser.add_argument("--repo", default=None, help="Repository as OWNER/NAME.")
    parser.add_argument(
        "--extra-required",
        action="append",
        default=[],
        metavar="KEY=PREFIX",
        help="Additional required check (KEY=display-name prefix); repeatable.",
    )
    parser.add_argument(
        "--list-required",
        action="store_true",
        help="Print the required-check set and exit 0.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_required:
        for spec in REQUIRED_CHECKS:
            print(f"{spec['key']}: {spec['check']}")
        return 0
    if not args.sha or not args.repo:
        print("ERROR: --sha and --repo are required", file=sys.stderr)
        return 2
    parts = args.repo.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        print("ERROR: --repo must be OWNER/NAME", file=sys.stderr)
        return 2
    owner, repo = parts
    required = list(REQUIRED_CHECKS)
    for extra in args.extra_required:
        if "=" not in extra:
            print("ERROR: --extra-required must be KEY=PREFIX", file=sys.stderr)
            return 2
        key, prefix = extra.split("=", 1)
        required.append({"key": key, "check": prefix, "description": "extra required check"})
    try:
        check_runs = fetch_check_runs(owner, repo, args.sha)
    except PromotionGateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    result = evaluate_gate(check_runs, args.sha, required=required)
    for key, gate in result["gates"].items():
        print(f"{key}: {gate['status']} ({gate['reason']})")
    if result["overall_pass"]:
        print(f"Promotion gate PASS for {args.sha}")
        return 0
    print(
        f"Promotion gate BLOCKED for {args.sha}: "
        "a required acceptance result is missing, skipped, failed, "
        "stale, or incomplete.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
