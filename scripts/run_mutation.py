#!/usr/bin/env python3
"""Mutation testing runner for TextForensics using Cosmic Ray 8.x.

Supports three modes:

- diff: Mutate only changed modules (git diff against a base SHA) — for push/PR.
- full: Full mutation on all configured modules (weekly).
- safety-critical: Deep mutation on safety-critical modules only.

Cosmic Ray 8.x model (verified against 8.7.0)
----------------------------------------------
The 7.x CLI (``baseline <config> <session>``, ``run``, ``report``) and the
YAML config format do not exist in 8.x. The 8.x flow is::

    cosmic-ray baseline <config.toml> [--session-file <session>]
    cosmic-ray init <config.toml> <session>
    cosmic-ray exec <config.toml> <session>
    cosmic-ray dump <session>        # JSONL: [work_item, work_result | null]

The config is TOML-only, with ``[cosmic-ray]`` keys ``module-path``
(filesystem paths, a string or a list), ``test-command``, ``timeout`` and
``[cosmic-ray.distributor] name = "local"``. This runner generates the TOML
for each run from the module list (see :func:`build_toml_config`); the
checked-in ``.cosmic-ray.toml`` documents the full target set and is directly
usable with the CLI.

Two 8.x behaviours shape this runner and are NOT bugs in it:

1. Operator selection: 8.x runs *every* no-arg core operator (213 in 8.7.0)
   for every module, unconditionally — the ``operators`` config table only
   parameterises operators that take arguments (``VariableReplacer`` /
   ``VariableInserter``). There is no way to select a subset via config,
   and the 7.x operator names (``number_replacer``,
   ``arithmetic_operator_replacement``, ...) do not exist in 8.x.
2. No mutation cap: 8.x has no ``--max-mutations``. The ``--budget`` option
   is therefore enforced here by trimming the session to the first ``budget``
   work items in deterministic order (module path, operator, occurrence)
   after ``init``, using only the public ``cosmic_ray.work_db.WorkDB`` API.
   ``--budget 0`` means no cap. Trimming is deterministic but biased toward
   alphabetically-early operators; it bounds CI time, it is not a sample.

Test-command scoping: the 7.x config ran the *whole* test suite per mutant.
Per-mutant cost is dominated by test startup, so this runner scopes the test
command to the dedicated test file(s) of the module(s) under test
(``tests/test_<module>.py``) when every module has one, and falls back to the
full suite otherwise.

No-op case: a diff run with no relevant module changed writes a summary with
``skipped_reason: "no-relevant-changes"`` and exits 0. :func:`check_results`
accepts that marker. "Nothing to mutate" is therefore a pass, distinct from
"mutation failed" (exit 1) and "surviving mutants" (exit 2).

Exit codes:

- 0: All executed mutations killed, or a legitimate no-op.
- 1: Runner / baseline / cosmic-ray failure, or a summary with no mutations
  and no ``skipped_reason``.
- 2: Surviving mutants detected.
- 3: Mutation budget exceeded (timeout ratio above 10%).
"""

import argparse
import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

# Target modules (kept in sync with .cosmic-ray.toml and the module filter in
# .github/workflows/mutation.yml — change all three together).
TARGET_MODULES = [
    "textforensics.benchmark",
    "textforensics.trust",
    "textforensics.consensus",
    "textforensics.calibration",
    "textforensics.detectors",
    "textforensics.analyzers",
    "textforensics.engine",
    "textforensics.policy",
    "textforensics.casefile",
]

# Safety-critical modules (subset for deep mutation).
SAFETY_CRITICAL_MODULES = [
    "textforensics.benchmark",
    "textforensics.trust",
    "textforensics.consensus",
    "textforensics.calibration",
]

#: Marker written into a summary when a run legitimately mutated nothing.
SKIPPED_REASON_NO_CHANGES = "no-relevant-changes"

#: Default per-mutant test timeout (seconds), matching .cosmic-ray.toml.
DEFAULT_TIMEOUT = 30

#: Default mutation budget (work items) per run; 0 means no cap.
DEFAULT_BUDGET = 200


def run_command(
    cmd: list[str], cwd: Path | None = None, timeout: int | None = None
) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd)}", file=sys.stderr)
        raise


def module_path(module: str, project_root: Path) -> Path:
    """Convert a dotted module name to its source file path."""
    relative = Path(*module.split(".")).with_suffix(".py")
    return project_root / "src" / relative


def test_command_for(modules: list[str], project_root: Path) -> str:
    """Build the per-mutant test command for the given modules.

    Scoped to each module's dedicated test file when every module has one;
    otherwise the full suite (slow but correct — a module without a dedicated
    test file must not silently lose coverage).
    """
    test_files: list[str] = []
    for module in modules:
        stem = module.split(".")[-1]
        test_file = project_root / "tests" / f"test_{stem}.py"
        if test_file.is_file():
            test_files.append(f"tests/test_{stem}.py")
        else:
            print(
                f"No dedicated test file for {module} "
                f"(expected tests/test_{stem}.py); falling back to the full suite.",
                file=sys.stderr,
            )
            return "python -m pytest tests/ -x -q --tb=short"
    joined = " ".join(test_files)
    return f"python -m pytest {joined} -x -q"


def load_base_config(config_path: Path) -> dict[str, Any]:
    """Load optional defaults (timeout, excluded-modules) from a TOML config.

    Returns an empty dict when the file does not exist, so a generated config
    still works standalone. Only ``timeout`` and ``excluded-modules`` are
    honoured here: ``module-path`` and ``test-command`` are derived per run.
    """
    if not config_path.is_file():
        return {}
    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    cosmic_ray = data.get("cosmic-ray", {})
    if not isinstance(cosmic_ray, dict):
        raise ValueError(f"Invalid cosmic-ray config (expected a table): {config_path}")
    return {
        "timeout": cosmic_ray.get("timeout", DEFAULT_TIMEOUT),
        "excluded-modules": cosmic_ray.get("excluded-modules", []),
    }


def _toml_str(value: str) -> str:
    """Render a string as a TOML basic string (paths here contain no quotes)."""
    return json.dumps(value)


def build_toml_config(
    modules: list[str],
    project_root: Path,
    timeout: float,
    excluded_modules: list[str] | None = None,
) -> str:
    """Generate the cosmic-ray 8.x TOML config for the given modules.

    ``module-path`` is a list of filesystem paths (cosmic-ray resolves them
    relative to the config file's location, and the runner writes the config
    into a temp dir, so absolute paths are used to stay unambiguous).
    """
    paths = [str(module_path(m, project_root)) for m in modules]
    test_command = test_command_for(modules, project_root)
    lines = [
        "# Generated by scripts/run_mutation.py — do not edit. Canonical config: .cosmic-ray.toml",
        "[cosmic-ray]",
        "module-path = [" + ", ".join(_toml_str(p) for p in paths) + "]",
        "test-command = " + _toml_str(test_command),
        f"timeout = {float(timeout)}",
        "excluded-modules = [" + ", ".join(_toml_str(m) for m in (excluded_modules or [])) + "]",
        "",
        "# 8.x runs every no-arg core operator; the operators table is left",
        "# empty on purpose (it only parameterises argument-taking operators).",
        "[cosmic-ray.operators]",
        "",
        "[cosmic-ray.distributor]",
        'name = "local"',
        "",
    ]
    return "\n".join(lines)


def get_changed_modules(base_sha: str, target_modules: list[str]) -> list[str]:
    """Get list of changed modules from git diff."""
    try:
        result = run_command(["git", "diff", "--name-only", f"{base_sha}...HEAD"])
        if result.returncode != 0:
            print(f"Git diff failed: {result.stderr}", file=sys.stderr)
            return []

        changed_files = result.stdout.strip().split("\n")
        changed_modules = []

        for file in changed_files:
            file = file.strip()
            if not file:
                continue
            # Convert file path to module name
            if file.startswith("src/textforensics/") and file.endswith(".py"):
                module = file.replace("src/", "").replace(".py", "").replace("/", ".")
                if module in target_modules:
                    changed_modules.append(module)

        return changed_modules
    except Exception as e:
        print(f"Error getting changed modules: {e}", file=sys.stderr)
        return []


def _trim_session_to_budget(session_path: Path, budget: int) -> tuple[int, int]:
    """Trim a session to the first ``budget`` work items, deterministically.

    Uses only the public ``cosmic_ray.work_db.WorkDB`` API: read all work
    items, clear, re-add the first ``budget`` sorted by (module path,
    operator, occurrence). Returns ``(total_before, total_after)``.
    """
    from cosmic_ray.work_db import WorkDB, use_db

    with use_db(session_path, WorkDB.Mode.open) as db:
        items = list(db.work_items)
        total_before = len(items)

        def sort_key(item: Any) -> tuple[str, str, int]:
            mutation = item.mutations[0]
            return (
                str(mutation.module_path),
                mutation.operator_name,
                mutation.occurrence,
            )

        items.sort(key=sort_key)
        kept = items[:budget] if budget > 0 else items
        db.clear()
        if kept:
            db.add_work_items(kept)
        return total_before, len(kept)


def run_cosmic_ray(
    modules: list[str],
    config_path: Path,
    session_name: str,
    timeout: int = DEFAULT_TIMEOUT,
    budget: int = DEFAULT_BUDGET,
    project_root: Path | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Run cosmic-ray 8.x (baseline → init → exec → dump).

    Returns ``(exit_code, dump_records)`` where each dump record is a
    ``{"work_item": ..., "result": ... | None}`` dict parsed from
    ``cosmic-ray dump`` JSONL output. ``result`` is ``None`` for pending
    (unexecuted) work items.
    """
    root = project_root or Path.cwd()
    base = load_base_config(config_path)
    effective_timeout = float(
        timeout if timeout is not None else base.get("timeout", DEFAULT_TIMEOUT)
    )
    excluded = base.get("excluded-modules", [])

    with tempfile.TemporaryDirectory(prefix="cosmic-ray-") as tmpdir:
        tmp = Path(tmpdir)
        run_config = tmp / "cosmic-ray.toml"
        run_config.write_text(build_toml_config(modules, root, effective_timeout, excluded))
        session_path = (root / f"{session_name}.sqlite").resolve()
        baseline_session = tmp / "baseline.sqlite"
        dump_path = root / f"{session_name}.json"

        # 1. Baseline: the unmutated test command must pass.
        print(f"Running baseline tests for {len(modules)} module(s)...")
        result = run_command(
            [
                "cosmic-ray",
                "baseline",
                str(run_config),
                "--session-file",
                str(baseline_session),
            ],
            timeout=600,
        )
        if result.returncode != 0:
            print(f"Baseline tests failed: {result.stderr or result.stdout}", file=sys.stderr)
            return 1, [{"error": "baseline_failed", "stderr": result.stderr}]

        # 2. Init: build the session (all core operators, all occurrences).
        print(f"Initialising mutation session for {len(modules)} module(s)...")
        result = run_command(
            ["cosmic-ray", "init", str(run_config), str(session_path)],
            timeout=600,
        )
        if result.returncode != 0:
            print(f"Session init failed: {result.stderr or result.stdout}", file=sys.stderr)
            return 1, [{"error": "init_failed", "stderr": result.stderr}]

        # 3. Enforce the budget (8.x has no --max-mutations).
        if budget > 0:
            total_before, total_after = _trim_session_to_budget(session_path, budget)
            print(
                f"Session initialised with {total_before} work item(s); "
                f"budget {budget} applied, {total_after} will run."
            )
            if total_after == 0:
                print("No work items after budget trim.", file=sys.stderr)
                return 1, [{"error": "no_work_items"}]
        else:
            from cosmic_ray.work_db import WorkDB, use_db

            with use_db(session_path, WorkDB.Mode.open) as db:
                print(f"Session initialised with {db.num_work_items} work item(s); no budget cap.")

        # 4. Exec: run the pending work items with the local distributor.
        # Wall-clock bound scales with the budget and the per-test timeout;
        # the CI job timeout is the outer bound.
        exec_timeout = int(budget * (effective_timeout + 15)) if budget > 0 else 3600
        print("Running mutation testing...")
        result = run_command(
            ["cosmic-ray", "exec", str(run_config), str(session_path)],
            timeout=max(exec_timeout, 600),
        )
        if result.returncode != 0:
            print(
                f"Mutation execution failed (exit {result.returncode}): "
                f"{result.stderr or result.stdout}",
                file=sys.stderr,
            )
            return 1, [{"error": "exec_failed", "stderr": result.stderr}]

        # 5. Dump: JSONL, one [work_item, work_result | null] per line.
        result = run_command(["cosmic-ray", "dump", str(session_path)], timeout=300)
        if result.returncode != 0:
            print(f"Dump failed: {result.stderr or result.stdout}", file=sys.stderr)
            return 1, [{"error": "dump_failed", "stderr": result.stderr}]

        dump_path.write_text(result.stdout)
        print(f"Dump written to {dump_path}")

        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                work_item, work_result = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                print(f"Skipping unparsable dump line: {line[:200]}", file=sys.stderr)
                continue
            records.append({"work_item": work_item, "result": work_result})
        return 0, records


def parse_results(records: list[dict[str, Any]] | dict[str, Any]) -> dict[str, Any]:
    """Parse cosmic-ray 8.x ``dump`` records into summary statistics.

    Accepts the list returned by :func:`run_cosmic_ray`. A record carrying an
    ``"error"`` key (baseline/init/exec/dump failure) sets ``error`` to 1.
    ``total`` counts completed work items only; unexecuted items are reported
    separately as ``pending``.
    """
    summary: dict[str, Any] = {
        "total": 0,
        "killed": 0,
        "surviving": 0,
        "timeout": 0,
        "error": 0,
        "skipped": 0,
        "incompetent": 0,
        "pending": 0,
    }

    if isinstance(records, dict):
        # Error path (e.g. baseline/init failure): keep the error marker and
        # a zero summary so check_results fails loudly instead of passing.
        if "error" in records:
            summary["error"] = 1
        return summary

    for record in records:
        if "error" in record:
            # Error path (e.g. baseline/init failure): fail loudly.
            summary["error"] = 1
            continue
        result = record.get("result")
        if result is None:
            summary["pending"] += 1
            continue
        summary["total"] += 1
        worker_outcome = str(result.get("worker_outcome", "")).lower()
        test_outcome = str(result.get("test_outcome") or "").lower()

        if worker_outcome in ("exception", "abnormal", "no-test"):
            summary["error"] += 1
        elif worker_outcome == "skipped":
            summary["skipped"] += 1
        elif test_outcome == "killed":
            summary["killed"] += 1
        elif test_outcome == "survived":
            summary["surviving"] += 1
        elif test_outcome == "incompetent":
            # Mutant could not be applied / did not compile: no test signal,
            # neither a kill nor a survival.
            summary["incompetent"] += 1
        else:
            summary["error"] += 1

    return summary


def write_summary(summary: dict[str, Any], output_dir: Path) -> None:
    """Write mutation summary to JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary written to {summary_path}")


def check_results(summary_path: Path) -> int:
    """Check mutation results and return appropriate exit code."""
    with open(summary_path) as f:
        summary = json.load(f)

    print(f"Mutation Summary: {json.dumps(summary, indent=2)}")

    # Legitimate no-op: nothing relevant changed. This is a pass, not a
    # failure — it must stay distinguishable from "mutation failed".
    if summary.get("skipped_reason") == SKIPPED_REASON_NO_CHANGES:
        print("[OK] No relevant modules changed - mutation testing skipped (pass).")
        return 0

    if summary.get("error"):
        print("Mutation testing failed with errors")
        return 1

    if summary.get("surviving", 0) > 0:
        print(f"[WARNING] {summary['surviving']} surviving mutant(s) detected!")
        return 2

    if summary.get("timeout", 0) > 0:
        print(f"[WARNING] {summary['timeout']} mutation(s) timed out")
        # Timeouts don't necessarily mean failure, but could indicate budget issues
        if summary.get("total", 0) > 0 and summary["timeout"] / summary["total"] > 0.1:
            print("[WARNING] High timeout ratio - mutation budget may be exceeded")
            return 3

    if summary.get("total", 0) == 0:
        print("No mutations were run")
        return 1

    print("[OK] All mutations caught!")
    return 0


def _no_op_summary() -> dict[str, Any]:
    """Summary for the legitimate no-op case (nothing relevant changed)."""
    return {
        "total": 0,
        "killed": 0,
        "surviving": 0,
        "timeout": 0,
        "error": 0,
        "skipped": 0,
        "incompetent": 0,
        "pending": 0,
        "skipped_reason": SKIPPED_REASON_NO_CHANGES,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run mutation testing for TextForensics")
    parser.add_argument(
        "--mode", choices=["diff", "full", "safety-critical"], default="diff", help="Mutation mode"
    )
    parser.add_argument("--base-sha", default="origin/main", help="Base SHA for diff mode")
    parser.add_argument(
        "--config", default=".cosmic-ray.toml", help="Path to cosmic-ray TOML config"
    )
    parser.add_argument("--check-results", help="Check results from summary.json file")
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout per test run (seconds)"
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=DEFAULT_BUDGET,
        help="Maximum mutations per session (8.x has no --max-mutations; "
        "the runner trims the session to this many work items; 0 = no cap)",
    )
    parser.add_argument(
        "--modules",
        default=None,
        help="Comma-separated dotted module names to mutate (overrides --mode "
        "selection; must be a subset of the configured target modules). "
        "For manual / verification runs.",
    )

    args = parser.parse_args()

    # Handle check-results mode
    if args.check_results:
        return check_results(Path(args.check_results))

    config_path = Path(args.config)
    project_root = Path.cwd()

    if args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        unknown = [m for m in modules if m not in TARGET_MODULES]
        if unknown:
            print(
                f"Unknown module(s) (not a configured target): {', '.join(unknown)}",
                file=sys.stderr,
            )
            return 1
        print(f"Mutating explicitly requested modules: {', '.join(modules)}")
    elif args.mode == "diff":
        print(f"Running diff-based mutation against {args.base_sha}")
        modules = get_changed_modules(args.base_sha, TARGET_MODULES)
        if not modules:
            print("No relevant modules changed - skipping mutation testing")
            write_summary(_no_op_summary(), Path("mutation-results"))
            return 0
        print(f"Mutating {len(modules)} changed module(s): {', '.join(modules)}")

    elif args.mode == "full":
        print("Running full mutation testing on all target modules")
        modules = TARGET_MODULES

    elif args.mode == "safety-critical":
        print("Running safety-critical deep mutation testing")
        modules = SAFETY_CRITICAL_MODULES
        # Increase budget for safety-critical
        args.budget = 500

    # Run cosmic-ray
    session_name = f"cosmic-ray-{args.mode}"
    exit_code, records = run_cosmic_ray(
        modules=modules,
        config_path=config_path,
        session_name=session_name,
        timeout=args.timeout,
        budget=args.budget,
        project_root=project_root,
    )

    # Parse and write results
    summary = parse_results(records)
    write_summary(summary, Path("mutation-results"))

    # Return appropriate exit code based on results
    if exit_code == 0:
        return check_results(Path("mutation-results/summary.json"))
    else:
        # Cosmic-ray itself failed
        return 1


if __name__ == "__main__":
    sys.exit(main())
