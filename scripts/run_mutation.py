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

Exec timeout and resume (``--budget 0`` / full sessions)
--------------------------------------------------------
A full session takes ~20 h, so a budget-0 run has NO wall-clock cap: the
old 3600 s exec timeout killed the run mid-mutant, left a mutant baked
into the source file, and produced no dump and no summary — the session
could only be recovered by hand. :func:`exec_timeout_for` returns ``None``
(no ``subprocess`` timeout) for budget 0 unless the operator passes an
explicit ``--exec-timeout``. A budgeted run keeps the old scaled cap
(``budget * (per-test timeout + 15)``, floored at 600 s).

When an exec IS interrupted — an explicit ``--exec-timeout`` expiring, or
the operator killing the process — the run fails loudly (exit 1) but
cleanly: :func:`_exec_session` dumps the partial session first, so
completed work items are kept and the rest stay ``pending`` in the
sqlite session, and the summary is still written. A partial summary
never passes: :func:`check_results` fails (exit 1) while ``pending > 0``.

Every run persists its generated config as the resume TOML,
``mutation-results/<session>.toml`` (next to ``<session>.sqlite`` and
``<session>.json`` in the repo root), before exec starts. Resume with
the runner (preferred — it refuses to exec against a dirty target
module, dumps, and gates on the result exactly like a fresh run)::

    python scripts/run_mutation.py --resume cosmic-ray-full.sqlite

or, when the runner itself is unavailable, directly with cosmic-ray
from the repo root (after restoring the source — step 1 below)::

    cosmic-ray exec mutation-results/cosmic-ray-full.toml cosmic-ray-full.sqlite

Resume procedure (also in CONTRIBUTING.md §2.3 — read it before resuming):

1. Restore the source: a killed exec leaves the mutant it was running
   baked into the module file. ``git status -- src/textforensics/``
   shows it; restore it with ``git checkout -- <module file>`` and
   re-check that the tree is clean before resuming — resuming against
   a contaminated file shifts occurrence numbering and produces bogus
   kills / ``no-test`` records (measured twice, 2026-11-08).
2. Remove a stale git lock only when no git process is running:
   ``rm .git/index.lock`` (a lock left by a killed git is the usual
   cause of ``fatal: Unable to create '.git/index.lock': File exists``).
3. Resume (runner form above, or the direct ``cosmic-ray exec`` form).
   ``cosmic-ray exec`` only runs the session's remaining work items:
   completed items are neither lost nor re-run.
4. After the resumed exec finishes, confirm no mutant is left behind
   (``git status -- src/textforensics/`` clean) and gate on the fresh
   summary (the runner writes ``mutation-results/summary.json`` and
   exits 0/1/2/3 as usual; a direct ``cosmic-ray exec`` resume writes
   no summary, so run ``python scripts/run_mutation.py --resume
   <session>.sqlite`` once afterwards — with nothing pending it just
   dumps and gates).

Sessions started before this fix have no persisted resume TOML; resume
those with ``--resume-toml .cosmic-ray.toml`` (checked-in config: same
per-mutant timeout, full-suite test command — correct, just slower).

Equivalent-mutant baseline (``mutation-baseline.toml``)
--------------------------------------------------------
Some mutants cannot be killed by any test. Five kinds are recognised:

(a) Annotation mutants: a ``|`` inside a function annotation of a module
    using ``from __future__ import annotations`` (PEP 563), where the
    annotation is a string stored unevaluated. Such mutants are recorded
    in ``mutation-baseline.toml``, one entry per mutant, carrying the
    annotation text, the enclosing function and a per-entry reason.
(b) Unreachable-condition mutants (kind ``"unreachable-condition"``): a
    ``NumberReplacer`` mutant inside a branch condition that is provably
    dead — the condition reduces to a constant ``False`` for every
    replacement the operator can produce at that position, so no input
    can distinguish the mutant from the original. Each entry carries the
    exact original source text at the position and a SHA-256 fingerprint
    of the enclosing function (whitespace-normalised source), so any
    change to that function fails the entry loudly instead of passing
    silently. The proof for each entry is recorded in the baseline file.
(c) Unobservable-value mutants (kind ``"unobservable-value"``): a
    ``NumberReplacer`` mutant whose replacement value is provably
    unobservable — the mutated expression's value never affects any
    observable behaviour for any input (e.g. a tier-order constant
    above every requirement it is ever compared against, a
    ``dict.get`` default below every value it is ever compared
    against, or an ``lru_cache`` ``maxsize`` on a zero-argument
    function, whose cache can never hold more than one entry). The
    entry carries the same source-text + function-fingerprint pinning
    as (b), and the proof for each entry is recorded in the baseline
    file. A new runtime kind needs its own validator first; the loader
    rejects unknown kinds loudly rather than accepting them blind.
(d) Domain-equivalent mutants (kind ``"domain-equivalent"``): a mutant
    whose replacement coincides with the original on every value the
    mutated expression can take within its enclosing function —
    restricted value domains, branch-established facts, zero-valued
    terms, a dead tiebreak, dead code, a redundant guard, or a dead
    ``except`` handler. The entry's ``reason`` must name the proof
    shape. Validated exactly like (b)/(c): source text + enclosing
    function + function fingerprint.
(e) ULP-equivalent mutants (kind ``"ulp-equivalent"``): a mutant whose
    replacement differs from the original only in the last few units
    in the last place (ULPs) of a floating-point result — a difference
    no behavioural test can meaningfully distinguish, because it is
    below the precision of the computation's own inputs. Validated
    like (b)/(c) plus two required per-entry fields that the bound
    records: ``ulp_bound_ulps`` (int, the maximum ULPs observed over
    the swept domain) and ``swept_domain`` (string naming the swept
    domain). An entry missing either field, or with a non-integer or
    negative bound, is rejected.

Entries are keyed by ``(module, operator, start_pos, end_pos,
occurrence)``. ``occurrence`` is part of the key — not provenance only —
because one operator can generate several distinct mutants at one
position: ``trust_map_from_capability_ledger`` L628:54 proves it, with
``max(1, ...)`` -> ``max(2, ...)`` equivalent but ``max(1, ...)`` ->
``max(0, ...)`` killable (``0 >= 0`` becomes True). Position-only
matching would conflate the two. An occurrence renumbering (a new
mutation point earlier in the file) makes the entry dormant and the
survivor unexplained, so the gate fails loudly (exit 2) rather than
passing silently.

This is a hybrid mechanism, deliberately NOT a blanket structural rule:
a pure "ignore mutants inside annotations" rule would silently accept
any future annotation mutant with no human review, including one that
later becomes behaviour-changing. Instead the baseline is explicit AND
re-validated: on every run the runner checks each entry against the
current source (AST — for annotation entries the position must still
hold the operator inside an annotation, the annotation text must be
unchanged, the enclosing function must match, and the module must
still use postponed evaluation; for runtime entries (kinds
``"unreachable-condition"``, ``"unobservable-value"``, ``"domain-equivalent"`` and
``"ulp-equivalent"``) the
position must still hold the recorded source text inside the recorded
function and the function's fingerprint must be unchanged). The summary
reports ``equivalent`` (accepted survivors), ``unexplained_surviving``
(the count the gate fails on), ``equivalent_dormant`` (valid entries
whose mutant was not executed in this run, e.g. outside the budget
prefix), ``equivalent_superseded`` (entries whose mutant was executed
and KILLED — the entry is now unnecessary and should be removed) and
``stale_baseline_entries``. Raw counts are never relabelled: ``total`` /
``killed`` / ``surviving`` keep their measured meanings and equivalent
mutants are never counted as killed (rule 17).

Exit codes:

- 0: All executed mutations killed (or accepted as equivalent), or a legitimate no-op.
- 1: Runner / baseline / cosmic-ray failure, a stale baseline entry, or a summary with no mutations
  and no ``skipped_reason``.
- 2: Unexplained surviving mutants detected.
- 3: Mutation budget exceeded (timeout ratio above 10%).
"""

import argparse
import ast
import hashlib
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
    # W1: the shared execution-policy channel (stop gate, consent,
    # redacting error contract) is safety-relevant decision logic.
    "textforensics.execution_policy",
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

#: Default equivalent-mutant baseline file (repo root, next to .cosmic-ray.toml).
DEFAULT_BASELINE = "mutation-baseline.toml"

#: Annotation kinds the baseline validator understands (see
#: :func:`_annotation_spans`). A new kind needs span support first; the
#: loader rejects unknown kinds loudly rather than accepting them blind.
BASELINE_ANNOTATION_KINDS = {"arg", "return", "annassign"}

#: Runtime kinds the baseline validator understands. ``"unreachable-
#: condition"`` covers a NumberReplacer mutant inside a branch condition
#: that is provably dead (see :func:`_validate_runtime_entry` and the
#: baseline file's header): the condition reduces to a constant
#: ``False`` for every replacement the operator can produce at that
#: position. ``"unobservable-value"`` covers a NumberReplacer mutant
#: whose replacement value is provably unobservable (the mutated
#: expression's value never affects any observable behaviour for any
#: input). ``"domain-equivalent"`` covers a mutant whose replacement
#: coincides with the original on every value the mutated expression can
#: take within its enclosing function (restricted value domains,
#: branch-established facts, zero-valued terms, a dead tiebreak, dead
#: code, a redundant guard, or a dead ``except`` handler); the entry's
#: ``reason`` must name the proof shape. ``"ulp-equivalent"`` covers a
#: mutant whose replacement differs from the original only in the last
#: few units in the last place (ULPs) of a floating-point result — a
#: difference no behavioural test can meaningfully distinguish, because
#: it is below the precision of the computation's own inputs. An
#: ``"ulp-equivalent"`` entry additionally records ``ulp_bound_ulps``
#: (int, the maximum ULPs observed, e.g. 2) and ``swept_domain``
#: (string, the swept domain, e.g. ``"[-20, 20], 40,000 points"``);
#: both are required and validated (see :func:`_validate_ulp_fields`).
#: All four kinds are validated the same way — the recorded source
#: text at the recorded position inside the recorded function, pinned
#: by that function's fingerprint — because all four proofs depend on
#: the enclosing function's behaviour as a whole. A new runtime kind
#: needs its own validator first; the loader rejects unknown kinds
#: loudly rather than accepting them blind.
BASELINE_RUNTIME_KINDS = {
    "unreachable-condition",
    "unobservable-value",
    "domain-equivalent",
    "ulp-equivalent",
}

#: All baseline kinds (annotation + runtime).
BASELINE_KINDS = BASELINE_ANNOTATION_KINDS | BASELINE_RUNTIME_KINDS

#: Fields every [[equivalent]] baseline entry must carry.
BASELINE_COMMON_FIELDS = {
    "id",
    "module",
    "operator",
    "occurrence",
    "start_pos",
    "end_pos",
    "function",
    "kind",
    "reason",
}

#: Extra fields an annotation-kind entry must carry (the annotation text
#: the entry pins; see :func:`_validate_annotation_entry`).
BASELINE_ANNOTATION_FIELDS = {"annotation"}

#: Extra fields a runtime-kind entry must carry: the exact
#: original source text at the position (e.g. ``"0"``) and a SHA-256
#: fingerprint of the enclosing function (see
#: :func:`_function_fingerprint`).
BASELINE_RUNTIME_FIELDS = {"source_text", "source_fingerprint"}

#: Extra fields an ``"ulp-equivalent"`` entry must carry on top of
#: :data:`BASELINE_RUNTIME_FIELDS`: ``ulp_bound_ulps`` (int, the maximum
#: ULPs observed between the original and the mutant over the swept
#: domain, e.g. 2) and ``swept_domain`` (string naming the swept domain,
#: e.g. ``"[-20, 20], 40,000 points"``). The bound is part of the
#: equivalence claim — without it, "differs only by a few ULPs" would be
#: an unbounded assertion — so both fields are required and validated
#: (see :func:`_validate_ulp_fields`); no other kind requires them.
BASELINE_ULP_FIELDS = {"ulp_bound_ulps", "swept_domain"}


def run_command(
    cmd: list[str], cwd: Path | None = None, timeout: int | None = None
) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"Command timed out: {' '.join(cmd)}", file=sys.stderr)
        raise


def exec_timeout_for(
    budget: int, per_test_timeout: float, exec_timeout: int | None = None
) -> int | None:
    """Wall-clock cap (seconds) for the ``cosmic-ray exec`` step, or None.

    - An explicit ``--exec-timeout`` wins: a positive value is the cap,
      ``0`` means no cap. A negative value is rejected (``ValueError``).
    - Otherwise a budgeted run scales with the budget, as before:
      ``budget * (per-test timeout + 15)``.
    - Otherwise (``budget == 0``, a full session) there is NO cap: a
      full session takes ~20 h, and the old hard 3600 s kill died
      mid-mutant, left a mutant baked into the source, and produced no
      dump and no summary. The outer bound for a full run is the
      operator's own session (terminal / CI job), and an interrupted
      run is resumed with ``--resume`` (see the module docstring).
    """
    if exec_timeout is not None:
        if exec_timeout < 0:
            raise ValueError(f"--exec-timeout must be >= 0 (got {exec_timeout})")
        return int(exec_timeout) if exec_timeout > 0 else None
    if budget > 0:
        return int(budget * (per_test_timeout + 15))
    return None


def _resume_instructions(session_name: str, resume_toml: Path, session_path: Path) -> str:
    """Resume instructions printed when an exec is interrupted.

    Paths are relative to the repo root, exactly as the operator types
    them. The runner form is preferred (it guards against resuming
    with a contaminated source); the direct form is the fallback when
    the runner itself cannot run.
    """
    try:
        resume_toml_display = str(resume_toml.relative_to(Path.cwd()))
    except ValueError:
        resume_toml_display = str(resume_toml)
    return (
        "Mutation exec interrupted before the session finished.\n"
        "Completed work items are kept in the session; the rest stay pending.\n"
        "1. Restore the source first — a killed exec leaves the mutant it was\n"
        "   running baked into the module file. Check with:\n"
        "       git status -- src/textforensics/\n"
        "   and restore any modified module with:\n"
        "       git checkout -- <module file>\n"
        "   Do NOT resume against a modified source: it shifts occurrence\n"
        "   numbering and produces bogus kills / no-test records.\n"
        "   If git itself reports a stale lock (no git process is running):\n"
        "       rm .git/index.lock\n"
        "2. Resume with the runner (preferred):\n"
        f"       python scripts/run_mutation.py --resume {session_path.name}\n"
        "   or directly with cosmic-ray:\n"
        f"       cosmic-ray exec {resume_toml_display} {session_path.name}\n"
        "3. After the resumed exec finishes, confirm the tree is clean\n"
        "   (git status -- src/textforensics/) and gate on the fresh summary."
    )


def _dump_session(
    session_path: Path, dump_path: Path, timeout: int = 300
) -> tuple[list[dict[str, Any]], str | None]:
    """Dump a session sqlite to JSONL records.

    Returns ``(records, error)``; ``error`` is None on success. Each
    record is ``{"work_item": ..., "result": ... | None}`` with
    ``result`` None for pending (unexecuted) work items. The dump file
    is written even for a partial (interrupted) session, so completed
    work is never lost to an interruption.
    """
    result = run_command(["cosmic-ray", "dump", str(session_path)], timeout=timeout)
    if result.returncode != 0:
        return [], f"Dump failed: {result.stderr or result.stdout}"
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
    return records, None


def _exec_session(
    config_path: Path,
    session_path: Path,
    dump_path: Path,
    exec_timeout: int | None,
    session_name: str,
    resume_toml: Path,
) -> tuple[int, list[dict[str, Any]]]:
    """Run ``cosmic-ray exec`` for a session and dump the result.

    Returns ``(exit_code, dump_records)``. Exit 0 only when exec itself
    succeeded and the dump parsed. On a timeout (explicit
    ``--exec-timeout``) or keyboard interrupt, exec is stopped, the
    partial session is dumped, the resume instructions are printed,
    and exit 1 is returned with an ``exec_timeout`` / ``exec_interrupted``
    error record appended — so the summary still records the completed
    work, the gate fails loudly instead of passing on a partial run,
    and the operator can resume with ``--resume``. The gate exit
    semantics are unchanged: this path never returns 0, 2 or 3.
    """
    print("Running mutation testing...")
    try:
        result = run_command(
            ["cosmic-ray", "exec", str(config_path), str(session_path)],
            timeout=exec_timeout,
        )
    except subprocess.TimeoutExpired:
        print(
            f"Mutation exec timed out after {exec_timeout}s (explicit --exec-timeout).",
            file=sys.stderr,
        )
        print(_resume_instructions(session_name, resume_toml, session_path))
        records, dump_error = _dump_session(session_path, dump_path)
        if dump_error is not None:
            print(dump_error, file=sys.stderr)
            return 1, [{"error": "exec_timeout", "detail": dump_error}]
        records.append({"error": "exec_timeout"})
        return 1, records
    except KeyboardInterrupt:
        print("Mutation exec interrupted.", file=sys.stderr)
        print(_resume_instructions(session_name, resume_toml, session_path))
        records, dump_error = _dump_session(session_path, dump_path)
        if dump_error is not None:
            print(dump_error, file=sys.stderr)
            return 1, [{"error": "exec_interrupted", "detail": dump_error}]
        records.append({"error": "exec_interrupted"})
        return 1, records
    if result.returncode != 0:
        print(
            f"Mutation execution failed (exit {result.returncode}): "
            f"{result.stderr or result.stdout}",
            file=sys.stderr,
        )
        # The session may still hold completed work items (e.g. the
        # unexplained cosmic-ray exit 120 seen in the calibration full
        # session); dump them so the summary records what did run.
        records, dump_error = _dump_session(session_path, dump_path)
        if dump_error is not None:
            return 1, [{"error": "exec_failed", "stderr": result.stderr}]
        records.append({"error": "exec_failed", "stderr": result.stderr})
        return 1, records
    records, dump_error = _dump_session(session_path, dump_path)
    if dump_error is not None:
        print(dump_error, file=sys.stderr)
        return 1, [{"error": "dump_failed", "stderr": dump_error}]
    return 0, records


def _dirty_target_modules(project_root: Path) -> tuple[list[str], str | None]:
    """Tracked ``src/textforensics/*.py`` files modified in the worktree.

    Returns ``(paths, error)``; ``error`` is set when ``git status``
    itself fails (e.g. a stale ``.git/index.lock`` — see the module
    docstring). Only tracked modifications count: a leftover mutant
    from a killed exec shows up here, an untracked file does not
    affect occurrence numbering. A resume must refuse on a non-empty
    list: resuming against a modified source shifts occurrence
    numbering and contaminates the results.
    """
    result = run_command(
        ["git", "status", "--porcelain", "--", "src/textforensics/"],
        cwd=project_root,
    )
    if result.returncode != 0:
        return [], (
            "git status failed: "
            f"{result.stderr.strip() or result.stdout.strip() or 'unknown error'} — "
            "if it reports a stale lock and no git process is running, "
            "remove it with `rm .git/index.lock` and retry"
        )
    dirty: list[str] = []
    for line in result.stdout.splitlines():
        if len(line) < 4:
            continue
        status, path = line[:2], line[3:]
        if status.strip() == "??" or not path.endswith(".py"):
            continue
        dirty.append(path)
    return dirty, None


def resume_cosmic_ray(
    session_path: Path,
    resume_toml: Path,
    exec_timeout: int | None = None,
    project_root: Path | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Resume an interrupted cosmic-ray session (``--resume`` mode).

    The session sqlite already holds the completed work items;
    ``cosmic-ray exec`` only runs the remaining ones. Before exec,
    the target modules must be clean — a leftover mutant from the
    killed run shows up as a modified file and the resume refuses
    (exit 1) with the exact restore command, instead of running
    against contaminated source. When nothing is pending, exec is
    skipped and the session is dumped and gated as-is. Returns
    ``(exit_code, dump_records)`` with the same meaning as
    :func:`run_cosmic_ray`.
    """
    root = project_root or Path.cwd()
    session_path = session_path.resolve()
    dump_path = root / f"{session_path.stem}.json"
    if not session_path.is_file():
        print(f"Resume session not found: {session_path}", file=sys.stderr)
        return 1, [{"error": "resume_session_not_found"}]
    if not resume_toml.is_file():
        print(f"Resume config not found: {resume_toml}", file=sys.stderr)
        return 1, [{"error": "resume_config_not_found"}]
    dirty, error = _dirty_target_modules(root)
    if error is not None:
        print(error, file=sys.stderr)
        return 1, [{"error": "resume_git_status_failed", "detail": error}]
    if dirty:
        print(
            "Refusing to resume: target module(s) modified in the worktree "
            "— a killed exec leaves its mutant baked into the source, and "
            "resuming against it shifts occurrence numbering and produces "
            "bogus kills / no-test records. Restore the source first:",
            file=sys.stderr,
        )
        for path in dirty:
            print(f"  git checkout -- {path}", file=sys.stderr)
        print("Then re-run the resume.", file=sys.stderr)
        return 1, [{"error": "resume_dirty_source", "files": dirty}]
    records, dump_error = _dump_session(session_path, dump_path)
    if dump_error is not None:
        print(dump_error, file=sys.stderr)
        return 1, [{"error": "dump_failed", "stderr": dump_error}]
    pending = sum(1 for record in records if record.get("result") is None)
    completed = len(records) - pending
    print(f"Resume session: {completed} completed, {pending} pending work item(s).")
    if pending == 0:
        print("Nothing pending — dumping and gating the finished session.")
        return 0, records
    return _exec_session(
        resume_toml,
        session_path,
        dump_path,
        exec_timeout,
        session_path.stem,
        resume_toml,
    )


def module_path(module: str, project_root: Path) -> Path:
    """Convert a dotted module name to its source file path."""
    relative = Path(*module.split(".")).with_suffix(".py")
    return project_root / "src" / relative


def test_command_for(modules: list[str], project_root: Path) -> str:
    """Build the per-mutant test command for the given modules.

    Scoped to each module's dedicated test file when every module has one;
    otherwise the full suite (slow but correct — a module without a dedicated
    test file must not silently lose coverage).

    Most modules follow the ``tests/test_<stem>.py`` convention; modules
    whose tests live elsewhere are listed explicitly in
    :data:`_MODULE_TEST_FILES`. Without the override, ``textforensics.policy``
    fell back to the full suite, whose ~3-minute runtime exceeds the
    per-test-run timeout and fails the cosmic-ray baseline before any
    mutant runs (PR #55).
    """
    test_files: list[str] = []
    for module in modules:
        override = _MODULE_TEST_FILES.get(module)
        if override is not None:
            test_files.extend(override)
            continue
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


# Modules whose tests do not follow the ``tests/test_<stem>.py`` convention.
# W1 regression tests live in shared files: the expiry/consent/stop tests
# for policy + execution_policy are in tests/test_execution_policy.py and
# tests/test_w1_consent_stop.py; the detector-gating tests are in
# tests/test_w1_consent_stop.py; the trust/casefile W1 tests (CORE-07,
# C03/C06/C12, replay) are in tests/test_w1_worker_d.py. A mutant in one
# of these modules is only killable by the tests that cover its new
# behaviour, so the per-mutant command must include those files — the
# dedicated file alone would report live kills as unexplained survivors.
# The W2 kill-test files (tests/test_audit_w2_worker_f_<stem>.py) are
# likewise listed for their modules (audit-w2 decision (c.1)): a
# diff-mode run that scoped to the mapped files without them would
# report the W2 mutants they kill as unexplained survivors.
# Two modules have NO entry on purpose and still fall back to the full
# suite, which collects their kill-test files anyway: evidence and
# observatory. Evidence has no dedicated test file (its proof-driver
# command was test_audit_w2_worker_a.py + test_evidence_manifest.py +
# test_seed_evidence.py); observatory is imported by eight test files,
# so a bare override would narrow coverage (see test_test_command_scoping).
_MODULE_TEST_FILES: dict[str, list[str]] = {
    # W2 kill tests live in test_audit_w2_worker_f_calibration.py
    # alongside the dedicated file.
    "textforensics.calibration": [
        "tests/test_calibration.py",
        "tests/test_audit_w2_worker_f_calibration.py",
    ],
    # W2 kill tests live in test_audit_w2_worker_f_benchmark.py
    # alongside the dedicated file.
    "textforensics.benchmark": [
        "tests/test_benchmark.py",
        "tests/test_audit_w2_worker_f_benchmark.py",
    ],
    # W2 kill tests live in test_audit_w2_worker_f_validation.py
    # alongside the dedicated file.
    "textforensics.validation": [
        "tests/test_validation.py",
        "tests/test_audit_w2_worker_f_validation.py",
    ],
    # W2 kill tests live in test_audit_w2_worker_f_report.py
    # alongside the dedicated file.
    "textforensics.report": [
        "tests/test_report.py",
        "tests/test_audit_w2_worker_f_report.py",
    ],
    # W2 kill tests live in test_audit_w2_worker_f_mixed_origin.py
    # alongside the dedicated file.
    "textforensics.mixed_origin": [
        "tests/test_mixed_origin.py",
        "tests/test_audit_w2_worker_f_mixed_origin.py",
    ],
    # W2 kill tests live in test_audit_w2_worker_f_schema.py
    # alongside the dedicated file.
    "textforensics.schema": [
        "tests/test_schema.py",
        "tests/test_audit_w2_worker_f_schema.py",
    ],
    # The dedicated file is tests/test_standalone_verify.py (no
    # test__standalone_verify.py: the stem has a leading underscore),
    # plus the W2 kill tests in
    # tests/test_audit_w2_worker_f__standalone_verify.py.
    "textforensics._standalone_verify": [
        "tests/test_standalone_verify.py",
        "tests/test_audit_w2_worker_f__standalone_verify.py",
    ],
    # Policy tests live in test_enterprise_policy.py, not test_policy.py;
    # the capability-expiry tests live in test_execution_policy.py; the
    # W2 Worker A trust/policy tests live in test_audit_w2_worker_a.py;
    # the W2 kill tests live in test_audit_w2_worker_f_policy.py.
    "textforensics.policy": [
        "tests/test_enterprise_policy.py",
        "tests/test_execution_policy.py",
        "tests/test_audit_w2_worker_a.py",
        "tests/test_audit_w2_worker_f_policy.py",
    ],
    # Execution-policy tests are split across test_execution_policy.py
    # (contract) and test_w1_consent_stop.py (consent/stop behaviour).
    "textforensics.execution_policy": [
        "tests/test_execution_policy.py",
        "tests/test_w1_consent_stop.py",
    ],
    # Detector-gating (execute_detector / run_all_detectors policy + stop)
    # is covered by test_w1_consent_stop.py.
    "textforensics.detectors": [
        "tests/test_detectors.py",
        "tests/test_w1_consent_stop.py",
    ],
    # CORE-07 trust-gate tests live in test_w1_worker_d.py; the W2
    # Worker A trust tests live in test_audit_w2_worker_a.py; the W2
    # kill tests live in test_audit_w2_worker_f_trust.py.
    "textforensics.trust": [
        "tests/test_trust.py",
        "tests/test_w1_worker_d.py",
        "tests/test_audit_w2_worker_a.py",
        "tests/test_audit_w2_worker_f_trust.py",
    ],
    # C03/C06/C12 + replay tests live in test_w1_worker_d.py; the v3
    # case-file tests live in test_casefile_v3.py; the W2 kill tests
    # live in test_audit_w2_worker_f_casefile.py. (test_audit_w2_worker_a
    # is NOT listed: it contains zero casefile references — Worker A
    # tested trust/policy, not casefile.)
    "textforensics.casefile": [
        "tests/test_casefile.py",
        "tests/test_w1_worker_d.py",
        "tests/test_casefile_v3.py",
        "tests/test_audit_w2_worker_f_casefile.py",
    ],
    # W2 Worker D tests (probe_runs / probe_metrics / model_card /
    # result_codec) live in test_w2_worker_d.py alongside the dedicated
    # files. Observatory is DELIBERATELY not listed: eight test files
    # import it (test_drift*.py, test_detector_health.py,
    # test_w1_worker_d.py, ...), so a bare [test_w2_worker_d.py] override
    # would narrow coverage; it still falls back to the full suite until
    # the coordinator decides the file list.
    "textforensics.probe_runs": [
        "tests/test_probe_runs.py",
        "tests/test_w2_worker_d.py",
        "tests/test_audit_w2_worker_f_probe_runs.py",
    ],
    "textforensics.probe_metrics": [
        "tests/test_probe_metrics.py",
        "tests/test_w2_worker_d.py",
        "tests/test_audit_w2_worker_f_probe_metrics.py",
    ],
    "textforensics.model_card": [
        "tests/test_model_card.py",
        "tests/test_w2_worker_d.py",
        "tests/test_audit_w2_worker_f_model_card.py",
    ],
    "textforensics.result_codec": [
        "tests/test_result_codec.py",
        "tests/test_w2_worker_d.py",
        "tests/test_audit_w2_worker_f_result_codec.py",
    ],
    # W2 Worker E tests: adversarial + semantic in test_w2_worker_e_if12.py
    # (IF-12), explain in test_w2_worker_e_if19.py (IF-19); the W2 kill
    # tests live in the matching test_audit_w2_worker_f_<stem>.py files.
    "textforensics.adversarial": [
        "tests/test_adversarial.py",
        "tests/test_w2_worker_e_if12.py",
        "tests/test_audit_w2_worker_f_adversarial.py",
    ],
    "textforensics.semantic": [
        "tests/test_semantic.py",
        "tests/test_w2_worker_e_if12.py",
        "tests/test_audit_w2_worker_f_semantic.py",
    ],
    "textforensics.explain": [
        "tests/test_explain.py",
        "tests/test_w2_worker_e_if19.py",
        "tests/test_audit_w2_worker_f_explain.py",
    ],
    # The v3 case-file/verify tests live in test_casefile_v3.py; the W2
    # kill tests live in test_audit_w2_worker_f_verify.py.
    "textforensics.verify": [
        "tests/test_verify.py",
        "tests/test_casefile_v3.py",
        "tests/test_audit_w2_worker_f_verify.py",
    ],
}


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


def _dotted_module(module_path: str) -> str:
    """Normalise a cosmic-ray ``module_path`` (absolute filesystem path) to a
    dotted module name (``textforensics.trust``).

    CI and local checkouts differ in their absolute prefix, so the match key
    uses the path below the ``src/`` directory, never the full path.
    """
    path = module_path.replace("\\", "/")
    if "/src/" in path:
        path = path.split("/src/", 1)[1]
    elif path.startswith("src/"):
        path = path[4:]
    if path.endswith(".py"):
        path = path[:-3]
    return path.replace("/", ".")


def _annotation_spans(tree: ast.AST, source: str) -> list[dict[str, Any]]:
    """Collect every annotation in a module as a span dict.

    Covers function argument annotations, return annotations and ``AnnAssign``
    (variable / dataclass-field) annotations, with the qualified owner name
    (``TrustMap.dimension``, ``assess_trust_map``) and the annotation source
    text. Positions are 1-based lines / 0-based columns, end exclusive —
    the same convention cosmic-ray uses for ``start_pos`` / ``end_pos``.
    """
    spans: list[dict[str, Any]] = []

    def add(node: ast.AST, kind: str, owner: str) -> None:
        spans.append(
            {
                "start_line": node.lineno,
                "start_col": node.col_offset,
                "end_line": node.end_lineno,
                "end_col": node.end_col_offset,
                "kind": kind,
                "owner": owner,
                "text": ast.get_source_segment(source, node),
            }
        )

    def walk(node: ast.AST, owner: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_owner = f"{owner}.{child.name}" if owner else child.name
                for arg in (
                    list(child.args.posonlyargs)
                    + list(child.args.args)
                    + list(child.args.kwonlyargs)
                ):
                    if arg.annotation is not None:
                        add(arg.annotation, "arg", child_owner)
                for extra in (child.args.vararg, child.args.kwarg):
                    if extra is not None and extra.annotation is not None:
                        add(extra.annotation, "arg", child_owner)
                if child.returns is not None:
                    add(child.returns, "return", child_owner)
                walk(child, child_owner)
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{owner}.{child.name}" if owner else child.name)
            elif isinstance(child, ast.AnnAssign):
                add(child.annotation, "annassign", owner or "?")
            else:
                walk(child, owner)

    walk(tree, "")
    return spans


def _has_postponed_evaluation(tree: ast.AST) -> bool:
    """True when the module uses ``from __future__ import annotations``
    (PEP 563: annotations are strings, never evaluated at runtime)."""
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module == "__future__"
        and any(alias.name == "annotations" for alias in node.names)
        for node in ast.walk(tree)
    )


def _entry_key(
    entry: dict[str, Any],
) -> tuple[str, str, tuple[int, int], tuple[int, int], int]:
    """Match key of a baseline entry: (module, operator, start_pos, end_pos, occurrence).

    ``occurrence`` is part of the key, not provenance only: one operator
    generates several distinct mutants at one position (NumberReplacer
    replaces a literal with several values), and those mutants need not
    share equivalence — at ``trust_map_from_capability_ledger`` L628:54,
    ``max(1, ...)`` -> ``max(2, ...)`` is equivalent while ``max(1, ...)``
    -> ``max(0, ...)`` is killable. Position-only matching would conflate
    them. A renumbering (a new mutation point earlier in the file) makes
    the entry dormant and the survivor unexplained, so the gate fails
    loudly (exit 2) rather than passing silently. The annotation text,
    source text and owner are re-validated separately by
    :func:`validate_baseline_entry`.
    """
    return (
        entry["module"],
        entry["operator"],
        tuple(entry["start_pos"]),
        tuple(entry["end_pos"]),
        int(entry["occurrence"]),
    )


def load_baseline(baseline_path: Path) -> dict[str, Any]:
    """Load and structurally validate ``mutation-baseline.toml``.

    Raises ``FileNotFoundError`` when the file is missing and ``ValueError``
    on any malformed content (wrong version, missing field, duplicate id or
    duplicate match key, unknown kind, malformed position). Structural
    problems fail loudly at load time; staleness against the current source
    is checked per entry by :func:`validate_baseline_entry`.
    """
    with open(baseline_path, "rb") as f:
        data = tomllib.load(f)
    if data.get("version") != 1:
        raise ValueError(f"Unsupported baseline version (expected 1): {data.get('version')!r}")
    entries = data.get("equivalent", [])
    if not isinstance(entries, list):
        raise ValueError("Baseline 'equivalent' must be a list of entries")
    seen_keys: set[tuple[str, str, tuple[int, int], tuple[int, int], int]] = set()
    seen_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"Baseline entry is not a table: {entry!r}")
        missing = BASELINE_COMMON_FIELDS - set(entry)
        if missing:
            raise ValueError(
                f"Baseline entry {entry.get('id', '?')!r} is missing field(s): "
                + ", ".join(sorted(missing))
            )
        if entry["kind"] not in BASELINE_KINDS:
            raise ValueError(
                f"Baseline entry {entry['id']!r} has unknown kind "
                f"{entry['kind']!r} (supported: {sorted(BASELINE_KINDS)})"
            )
        if entry["kind"] in BASELINE_ANNOTATION_KINDS:
            kind_fields = BASELINE_ANNOTATION_FIELDS
        elif entry["kind"] == "ulp-equivalent":
            # An ulp-equivalent entry needs the runtime fields plus the
            # recorded sweep bound and domain (see BASELINE_ULP_FIELDS).
            kind_fields = BASELINE_RUNTIME_FIELDS | BASELINE_ULP_FIELDS
        else:
            kind_fields = BASELINE_RUNTIME_FIELDS
        missing_kind = kind_fields - set(entry)
        if missing_kind:
            raise ValueError(
                f"Baseline entry {entry['id']!r} (kind {entry['kind']!r}) is "
                "missing field(s): " + ", ".join(sorted(missing_kind))
            )
        if entry["kind"] == "ulp-equivalent":
            ok, reason = _validate_ulp_fields(entry)
            if not ok:
                raise ValueError(f"Baseline entry {entry['id']!r} is invalid: {reason}")
        for field in ("start_pos", "end_pos"):
            pos = entry[field]
            if (
                not isinstance(pos, list)
                or len(pos) != 2
                or not all(isinstance(v, int) for v in pos)
            ):
                raise ValueError(f"Baseline entry {entry['id']!r} has malformed {field}: {pos!r}")
        if entry["id"] in seen_ids:
            raise ValueError(f"Duplicate baseline entry id: {entry['id']!r}")
        key = _entry_key(entry)
        if key in seen_keys:
            raise ValueError(f"Duplicate baseline match key: {key!r}")
        seen_ids.add(entry["id"])
        seen_keys.add(key)
    return {
        "version": 1,
        "entries": entries,
        "source_run": data.get("source_run"),
        "source_commit": data.get("source_commit"),
        "source_tool": data.get("source_tool"),
        "source_budget": data.get("source_budget"),
    }


def _enclosing_function(tree: ast.AST, line: int, col: int) -> tuple[str | None, ast.AST | None]:
    """Innermost function containing ``(line, col)``: (qualified name, node).

    Qualified names follow the :func:`_annotation_spans` convention
    (``TrustMap.dimension``, ``assess_trust_map``). Returns ``(None, None)``
    when the position is not inside any function. The walk visits parents
    before children, so the last containing function found is the
    innermost one. A decorated function's span starts at its first
    decorator line, not at the ``def`` line: a mutant in a decorator
    argument (e.g. ``@lru_cache(maxsize=4)``) is inside the function
    it decorates.
    """
    found: tuple[str, ast.AST] | None = None

    def walk(node: ast.AST, owner: str) -> None:
        nonlocal found
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_owner = f"{owner}.{child.name}" if owner else child.name
                if child.decorator_list:
                    first = child.decorator_list[0]
                    start = (first.lineno, 0)
                else:
                    start = (child.lineno, child.col_offset)
                end = (child.end_lineno or child.lineno, child.end_col_offset or 0)
                if start <= (line, col) < end:
                    found = (child_owner, child)
                walk(child, child_owner)
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{owner}.{child.name}" if owner else child.name)
            else:
                walk(child, owner)

    walk(tree, "")
    if found is None:
        return None, None
    return found


def _function_fingerprint(source: str, node: ast.AST) -> str:
    """SHA-256 of the whitespace-normalised source of a function node.

    Pure-text normalisation (``" ".join(segment.split())``) makes the
    fingerprint independent of formatting and of the Python version that
    parses the tree (unlike ``ast.dump``, whose output gained
    ``type_params`` in 3.12). Any token change in the function changes
    the fingerprint, so the entry goes stale and must be re-verified.
    The hashed source starts at the first decorator line when the
    function is decorated (``ast.get_source_segment`` starts at the
    ``def`` line, so decorator lines are prepended explicitly): the
    fingerprint pins the WHOLE decorated function, including the
    decorator arguments a runtime entry may record. Undecorated
    functions hash exactly as before.
    """
    segment = ast.get_source_segment(source, node) or ""
    decorators = getattr(node, "decorator_list", None) or []
    if decorators:
        lines = source.splitlines()
        first = decorators[0]
        deco_lines = lines[first.lineno - 1 : node.lineno - 1]
        segment = "\n".join([*deco_lines, segment])
    return hashlib.sha256(" ".join(segment.split()).encode()).hexdigest()


def _validate_ulp_fields(entry: dict[str, Any]) -> tuple[bool, str]:
    """Validate the extra fields of an ``"ulp-equivalent"`` entry.

    Returns ``(True, "ok")`` only when ``ulp_bound_ulps`` is a non-negative
    integer (``bool`` is not accepted — it is an ``int`` subclass but
    not a ULP count) and ``swept_domain`` is a non-empty string. A bound
    of 0 is a measured value — no observed difference over the swept
    domain — not a missing bound. Any
    failure means the entry cannot support its equivalence claim, so
    the entry is stale/invalid and the run must fail loudly (exit 1).
    Other kinds never carry these fields and are never checked here.
    """
    bound = entry.get("ulp_bound_ulps")
    if isinstance(bound, bool) or not isinstance(bound, int):
        return False, f"ulp_bound_ulps must be a non-negative integer (got {bound!r})"
    if bound < 0:
        return False, f"ulp_bound_ulps must be a non-negative integer (got {bound!r})"
    domain = entry.get("swept_domain")
    if not isinstance(domain, str) or not domain.strip():
        return False, f"swept_domain must be a non-empty string (got {domain!r})"
    return True, "ok"


class _ModuleContext:
    """Parsed source + derived tables for one module file.

    Built once per (path, mtime, size) and reused across every baseline
    entry of that module, so :func:`classify_baseline` no longer re-reads,
    re-parses and re-walks the same module once per entry (887 entries
    over 5 modules). The annotation-span walk is the expensive part:
    :func:`_annotation_spans` calls ``ast.get_source_segment`` for every
    annotation, and each call re-splits the whole source — on CPython
    3.11 a single ``parse_results`` over the full baseline exceeds 10
    minutes without this cache (test 2562, measured 2026-11-08).
    """

    __slots__ = (
        "source",
        "lines",
        "tree",
        "spans",
        "postponed",
        "functions",
        "fingerprints",
    )

    def __init__(self, source: str, tree: ast.AST) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.tree = tree
        self.spans = _annotation_spans(tree, source)
        self.postponed = _has_postponed_evaluation(tree)
        self.functions = _function_table(tree)
        self.fingerprints: dict[tuple[int, int], str] = {}

    def enclosing_function(self, line: int, col: int) -> tuple[str | None, ast.AST | None]:
        """Innermost function containing ``(line, col)``.

        Same semantics as :func:`_enclosing_function`: the table is in
        its walk order (parents before children), so the last containing
        function is the innermost one.
        """
        found: tuple[str, ast.AST] | None = None
        for name, node, start, end in self.functions:
            if start <= (line, col) < end:
                found = (name, node)
        return found if found is not None else (None, None)

    def fingerprint(self, node: ast.AST) -> str:
        """Cached :func:`_function_fingerprint` for one function node.

        Keyed by the node's start position, which is unique within the
        module; the source is fixed for the life of this context, so the
        fingerprint cannot change underneath it.
        """
        key = (node.lineno, node.col_offset)
        fp = self.fingerprints.get(key)
        if fp is None:
            fp = _function_fingerprint(self.source, node)
            self.fingerprints[key] = fp
        return fp


def _function_table(tree: ast.AST) -> list[tuple[str, ast.AST, tuple[int, int], tuple[int, int]]]:
    """``(name, node, start, end)`` for every function in ``tree``.

    Same walk as :func:`_enclosing_function` (parents before children,
    classes contribute their name to the owner, a decorated function's
    span starts at its first decorator line), so
    :meth:`_ModuleContext.enclosing_function` matches it exactly.
    """
    table: list[tuple[str, ast.AST, tuple[int, int], tuple[int, int]]] = []

    def walk(node: ast.AST, owner: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child_owner = f"{owner}.{child.name}" if owner else child.name
                if child.decorator_list:
                    first = child.decorator_list[0]
                    start = (first.lineno, 0)
                else:
                    start = (child.lineno, child.col_offset)
                end = (child.end_lineno or child.lineno, child.end_col_offset or 0)
                table.append((child_owner, child, start, end))
                walk(child, child_owner)
            elif isinstance(child, ast.ClassDef):
                walk(child, f"{owner}.{child.name}" if owner else child.name)
            else:
                walk(child, owner)

    walk(tree, "")
    return table


#: Cached module contexts, keyed by (path, mtime_ns, size). The suite
#: touches 5 modules; the cap is generous and only bounds a long-lived
#: process that validates many different files.
_MODULE_CONTEXT_CACHE: dict[tuple[str, int, int], _ModuleContext] = {}
_MODULE_CONTEXT_CACHE_MAX = 32


def _load_module_context(source_path: Path) -> tuple[_ModuleContext | None, str | None]:
    """``(context, error)`` for a module file, cached by (path, mtime, size).

    An edited file is re-parsed on the next call instead of serving a
    stale tree — the baseline is position-keyed, so a changed source
    makes its entries stale anyway; the cache only avoids re-doing the
    same work for an unchanged file. ``error`` is the same reason string
    :func:`validate_baseline_entry` used to produce inline, so behaviour
    (including the exact messages) is unchanged.
    """
    try:
        stat = source_path.stat()
    except OSError as exc:
        return None, f"module source unreadable: {exc}"
    key = (str(source_path), stat.st_mtime_ns, stat.st_size)
    context = _MODULE_CONTEXT_CACHE.get(key)
    if context is not None:
        return context, None
    try:
        source = source_path.read_text()
    except OSError as exc:
        return None, f"module source unreadable: {exc}"
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return None, f"module does not parse: {exc}"
    context = _ModuleContext(source, tree)
    if len(_MODULE_CONTEXT_CACHE) >= _MODULE_CONTEXT_CACHE_MAX:
        _MODULE_CONTEXT_CACHE.pop(next(iter(_MODULE_CONTEXT_CACHE)))
    _MODULE_CONTEXT_CACHE[key] = context
    return context, None


def _clear_module_context_cache() -> None:
    """Drop all cached module contexts (tests; long-lived processes)."""
    _MODULE_CONTEXT_CACHE.clear()


def validate_baseline_entry(entry: dict[str, Any], project_root: Path) -> tuple[bool, str]:
    """Re-validate one baseline entry against the CURRENT source.

    Dispatches on kind: annotation kinds go through
    :func:`_validate_annotation_entry`, runtime kinds (``"unreachable-
    condition"``, ``"unobservable-value"``, ``"domain-equivalent"`` and
    ``"ulp-equivalent"``) through :func:`_validate_runtime_entry`.
    ``"ulp-equivalent"`` entries are additionally checked by
    :func:`_validate_ulp_fields` first: a missing bound or domain, or a
    non-integer/negative bound, makes the entry stale. Any failure
    returns ``(False, reason)`` — the entry is STALE and the run must
    fail loudly (exit 1), never pass silently.

    The module's parse + annotation spans + function table are loaded
    once per (path, mtime, size) via :func:`_load_module_context` and
    shared across entries; see :class:`_ModuleContext`.
    """
    source_path = module_path(entry["module"], project_root)
    if not source_path.is_file():
        return False, f"module source not found: {source_path}"
    context, error = _load_module_context(source_path)
    if error is not None:
        return False, error
    if entry["kind"] in BASELINE_ANNOTATION_KINDS:
        return _validate_annotation_entry(entry, context)
    if entry["kind"] in BASELINE_RUNTIME_KINDS:
        if entry["kind"] == "ulp-equivalent":
            ok, reason = _validate_ulp_fields(entry)
            if not ok:
                return False, reason
        return _validate_runtime_entry(entry, context)
    return False, f"unknown baseline kind {entry['kind']!r}"


def _validate_annotation_entry(entry: dict[str, Any], context: _ModuleContext) -> tuple[bool, str]:
    """Re-validate an annotation-kind entry against the current source.

    Returns ``(True, "ok")`` only when every check holds: the module
    still uses postponed evaluation, the recorded position still holds
    the recorded operator inside an annotation, the enclosing function
    still matches, and the annotation text is unchanged. The annotation
    spans and the postponed-evaluation flag come from the cached
    :class:`_ModuleContext` — re-walking the module per entry is what
    made ``classify_baseline`` minutes-slow.
    """
    if not context.postponed:
        return (
            False,
            "module no longer uses postponed evaluation "
            "(`from __future__ import annotations` missing) — the annotation "
            "may now be evaluated at runtime, so the equivalence proof no "
            "longer holds",
        )
    start_line, start_col = entry["start_pos"]
    end_line, end_col = entry["end_pos"]
    if not (1 <= start_line <= len(context.lines)) or start_line != end_line:
        return False, f"position {entry['start_pos']} is outside the current source"
    line = context.lines[start_line - 1]
    if not (0 <= start_col < end_col <= len(line)):
        return (
            False,
            f"position {entry['start_pos']}-{entry['end_pos']} is outside line {start_line}",
        )
    segment = line[start_col:end_col]
    if "BitOr" in entry["operator"]:
        if segment != "|":
            return (
                False,
                f"position L{start_line}:{start_col} no longer holds `|` "
                f"(found {segment!r}) — the annotated code moved or changed",
            )
    elif not segment or any(ch.isspace() or ch.isalnum() or ch == "_" for ch in segment):
        return (
            False,
            f"position L{start_line}:{start_col} no longer holds an operator (found {segment!r})",
        )
    span = None
    for candidate in context.spans:
        sl, sc, el, ec = (
            candidate["start_line"],
            candidate["start_col"],
            candidate["end_line"],
            candidate["end_col"],
        )
        if (
            (sl == el == start_line and sc <= start_col < ec)
            or (sl < start_line < el)
            or (sl == start_line < el and start_col >= sc)
            or (sl < start_line == el and start_col < ec)
        ):
            span = candidate
            break
    if span is None:
        return (
            False,
            f"position L{start_line}:{start_col} is no longer inside an "
            "annotation — the mutant is now in runtime code",
        )
    if span["kind"] != entry["kind"]:
        return (
            False,
            f"annotation kind changed ({entry['kind']!r} -> {span['kind']!r})",
        )
    if span["owner"] != entry["function"]:
        return (
            False,
            f"enclosing function changed ({entry['function']!r} -> "
            f"{span['owner']!r}) — re-verify the mutant",
        )
    current_text = " ".join((span["text"] or "").split())
    recorded_text = " ".join(str(entry["annotation"]).split())
    if current_text != recorded_text:
        return (
            False,
            f"annotation text changed ({recorded_text!r} -> {current_text!r}) "
            "— re-verify the mutant",
        )
    return True, "ok"


def _validate_runtime_entry(entry: dict[str, Any], context: _ModuleContext) -> tuple[bool, str]:
    """Re-validate a runtime-kind entry against current source.

    Covers all four runtime kinds — ``"unreachable-condition"``,
    ``"unobservable-value"``, ``"domain-equivalent"`` and
    ``"ulp-equivalent"``: the kinds differ only in their proof (a
    provably dead branch condition vs a provably unobservable
    replacement value vs a replacement that coincides with the original
    on every value in the enclosing function vs a replacement that
    differs only by a few ULPs), and all four proofs depend on the
    enclosing function's behaviour as a whole.

    Returns ``(True, "ok")`` only when every check holds: the recorded
    position still holds the recorded source text, it sits inside the
    recorded (innermost) function, and that function's
    whitespace-normalised source still hashes to the recorded
    fingerprint. The fingerprint pins the WHOLE function because the
    equivalence proof depends on its behaviour as a whole (which states
    are ever assigned, which branches are reachable, which values are
    ever compared); any edit to the function — even far from the mutant
    — makes the entry stale so a human re-verifies the proof.

    The enclosing-function lookup and the function fingerprint come
    from the cached :class:`_ModuleContext`, so a full-baseline
    re-validation no longer walks the module tree per entry.
    """
    start_line, start_col = entry["start_pos"]
    end_line, end_col = entry["end_pos"]
    if not (1 <= start_line <= len(context.lines)) or start_line != end_line:
        return False, f"position {entry['start_pos']} is outside the current source"
    line = context.lines[start_line - 1]
    if not (0 <= start_col < end_col <= len(line)):
        return (
            False,
            f"position {entry['start_pos']}-{entry['end_pos']} is outside line {start_line}",
        )
    segment = line[start_col:end_col]
    if segment != entry["source_text"]:
        return (
            False,
            f"position L{start_line}:{start_col} no longer holds "
            f"{entry['source_text']!r} (found {segment!r}) — the code moved "
            "or changed",
        )
    name, node = context.enclosing_function(start_line, start_col)
    if node is None:
        return (
            False,
            f"position L{start_line}:{start_col} is no longer inside a function",
        )
    if name != entry["function"]:
        return (
            False,
            f"enclosing function changed ({entry['function']!r} -> {name!r}) "
            "— re-verify the mutant",
        )
    current = context.fingerprint(node)
    if current != entry["source_fingerprint"]:
        return (
            False,
            f"enclosing function {name!r} changed (fingerprint mismatch) "
            "— the equivalence proof no longer holds against the current "
            "source; re-verify the mutant",
        )
    return True, "ok"


def _record_mutant_key(
    record: dict[str, Any],
) -> tuple[str, str, tuple[int, int], tuple[int, int], int] | None:
    """Match key of one cosmic-ray dump record, or None when malformed.

    Mirrors :func:`_entry_key`: (module, operator, start_pos, end_pos,
    occurrence). ``occurrence`` disambiguates the several mutants one
    operator generates at one position (see :func:`_entry_key`).
    """
    try:
        mutation = record["work_item"]["mutations"][0]
        return (
            _dotted_module(mutation["module_path"]),
            mutation["operator_name"],
            tuple(mutation["start_pos"]),
            tuple(mutation["end_pos"]),
            int(mutation["occurrence"]),
        )
    except (KeyError, IndexError, TypeError, AttributeError, ValueError):
        return None


def classify_baseline(
    records: list[dict[str, Any]],
    baseline: dict[str, Any] | None,
    project_root: Path,
) -> dict[str, Any]:
    """Classify surviving mutants against the equivalent-mutant baseline.

    Returns the baseline portion of the summary: how many survivors were
    accepted as equivalent (each matched to a re-validated entry), how many
    remain unexplained, which entries are stale (failed re-validation),
    dormant (valid but no live survivor in this run) or superseded (valid
    but the mutant was executed and killed — the entry is now unnecessary).
    A stale entry never excuses a survivor: a survivor matching a stale
    entry counts as unexplained as well.
    """
    entries = list(baseline.get("entries", [])) if baseline else []
    result: dict[str, Any] = {
        "equivalent": 0,
        "equivalent_mutants": [],
        "equivalent_dormant": 0,
        "equivalent_dormant_ids": [],
        "equivalent_superseded": 0,
        "equivalent_superseded_ids": [],
        "unexplained_surviving": 0,
        "stale_baseline_entries": [],
        "baseline_entries": len(entries),
    }
    validation = {entry["id"]: validate_baseline_entry(entry, project_root) for entry in entries}
    result["stale_baseline_entries"] = [
        {"id": entry["id"], "reason": validation[entry["id"]][1]}
        for entry in entries
        if not validation[entry["id"]][0]
    ]
    by_key = {_entry_key(entry): entry for entry in entries}
    executed: dict[tuple[str, str, tuple[int, int], tuple[int, int], int], str] = {}
    survivors: list[tuple[str, str, tuple[int, int], tuple[int, int], int]] = []
    for record in records:
        if "error" in record:
            continue
        outcome = record.get("result")
        if outcome is None:
            continue
        key = _record_mutant_key(record)
        if key is None:
            continue
        test_outcome = str(outcome.get("test_outcome") or "").lower()
        executed[key] = test_outcome
        if test_outcome == "survived":
            survivors.append(key)
    matched_valid: set[str] = set()
    for key in survivors:
        entry = by_key.get(key)
        if entry is not None and validation[entry["id"]][0]:
            result["equivalent_mutants"].append(entry["id"])
            matched_valid.add(entry["id"])
        else:
            result["unexplained_surviving"] += 1
    result["equivalent"] = len(result["equivalent_mutants"])
    for entry in entries:
        if not validation[entry["id"]][0] or entry["id"] in matched_valid:
            continue
        if executed.get(_entry_key(entry)) == "killed":
            result["equivalent_superseded_ids"].append(entry["id"])
        else:
            result["equivalent_dormant_ids"].append(entry["id"])
    result["equivalent_dormant"] = len(result["equivalent_dormant_ids"])
    result["equivalent_superseded"] = len(result["equivalent_superseded_ids"])
    return result


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
    exec_timeout: int | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    """Run cosmic-ray 8.x (baseline → init → exec → dump).

    Returns ``(exit_code, dump_records)`` where each dump record is a
    ``{"work_item": ..., "result": ... | None}`` dict parsed from
    ``cosmic-ray dump`` JSONL output. ``result`` is ``None`` for pending
    (unexecuted) work items.

    The generated per-run config is persisted before exec as the resume
    TOML, ``mutation-results/<session_name>.toml`` (next to
    ``<session_name>.sqlite``), so an interrupted run can be resumed
    with ``--resume`` or directly with ``cosmic-ray exec``. The exec
    wall-clock cap comes from :func:`exec_timeout_for`: a budget-0
    (full) session has no cap unless an explicit ``--exec-timeout`` is
    given; a budgeted run keeps the scaled cap, floored at 600 s.
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
        toml_text = build_toml_config(modules, root, effective_timeout, excluded)
        run_config.write_text(toml_text)
        session_path = (root / f"{session_name}.sqlite").resolve()
        baseline_session = tmp / "baseline.sqlite"
        dump_path = root / f"{session_name}.json"
        # Persist the exact per-run config before exec starts: the
        # tempdir config is deleted on exit, and a resume needs the
        # same test-command / timeout the session was started with.
        resume_toml = root / "mutation-results" / f"{session_name}.toml"
        resume_toml.parent.mkdir(parents=True, exist_ok=True)
        resume_toml.write_text(toml_text)
        print(f"Resume config written to {resume_toml}")

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
        # Wall-clock bound from exec_timeout_for: a budget-0 (full)
        # session has NO cap (a full session takes ~20 h — the old 3600 s
        # kill died mid-mutant and lost the dump); a budgeted run scales
        # with the budget, floored at 600 s. An explicit --exec-timeout
        # overrides both and is honoured exactly (no floor): it is the
        # operator's deliberate chunk size for a resumable run, and
        # _exec_session dumps the partial session and prints the resume
        # procedure instead of dying with a traceback. The CI job
        # timeout is the outer bound.
        try:
            exec_timeout_s = exec_timeout_for(budget, effective_timeout, exec_timeout)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1, [{"error": "invalid_exec_timeout", "detail": str(exc)}]
        if exec_timeout is None and exec_timeout_s is not None:
            exec_timeout_s = max(exec_timeout_s, 600)
        return _exec_session(
            run_config, session_path, dump_path, exec_timeout_s, session_name, resume_toml
        )


def parse_results(
    records: list[dict[str, Any]] | dict[str, Any],
    baseline: dict[str, Any] | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Parse cosmic-ray 8.x ``dump`` records into summary statistics.

    Accepts the list returned by :func:`run_cosmic_ray`. A record carrying an
    ``"error"`` key (baseline/init/exec/dump failure) sets ``error`` to 1.
    ``total`` counts completed work items only; unexecuted items are reported
    separately as ``pending``.

    ``total`` / ``killed`` / ``surviving`` keep their measured meanings.
    When a baseline is given, surviving mutants are additionally classified
    by :func:`classify_baseline` into ``equivalent`` (accepted, each matched
    to a re-validated entry), ``unexplained_surviving`` (the count the gate
    fails on), ``equivalent_dormant`` / ``equivalent_superseded`` and
    ``stale_baseline_entries``. Equivalent mutants are never counted as
    killed and never removed from ``total`` or ``surviving``.
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
        "equivalent": 0,
        "equivalent_mutants": [],
        "equivalent_dormant": 0,
        "equivalent_dormant_ids": [],
        "equivalent_superseded": 0,
        "equivalent_superseded_ids": [],
        "unexplained_surviving": 0,
        "stale_baseline_entries": [],
        "baseline_entries": 0,
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

        if test_outcome == "incompetent":
            # Mutant could not be applied / did not compile: no test
            # signal, neither a kill nor a survival. Checked FIRST,
            # before worker_outcome: a cosmic-ray operator crash (e.g.
            # ExceptionReplacer dying inside the operator, before any
            # mutant code exists) arrives as worker_outcome="exception"
            # with test_outcome="incompetent", and there is no behaviour
            # to kill or baseline — it must not count as an error. A
            # worker exception with any other test_outcome stays an
            # error (see the branch below).
            summary["incompetent"] += 1
        elif worker_outcome in ("exception", "abnormal", "no-test"):
            summary["error"] += 1
        elif worker_outcome == "skipped":
            summary["skipped"] += 1
        elif test_outcome == "killed":
            summary["killed"] += 1
        elif test_outcome == "survived":
            summary["surviving"] += 1
        else:
            summary["error"] += 1

    classification = classify_baseline(records, baseline, project_root or Path.cwd())
    summary.update(classification)
    return summary


def write_summary(summary: dict[str, Any], output_dir: Path) -> None:
    """Write mutation summary to JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary written to {summary_path}")


def check_results(summary_path: Path) -> int:
    """Check mutation results and return appropriate exit code.

    Exit 1 on stale baseline entries (a baseline entry that no longer
    matches the current source must fail loudly, never pass silently).
    Exit 2 only on UNEXPLAINED survivors — survivors accepted as equivalent
    per a re-validated baseline entry do not fail the gate. Summaries
    written before the baseline mechanism existed carry no
    ``unexplained_surviving`` field and fall back to the raw ``surviving``
    count, so old summaries keep their old verdict.
    """
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

    stale = summary.get("stale_baseline_entries") or []
    if stale:
        print(
            f"[ERROR] {len(stale)} stale baseline entr(y/ies) — the baseline no "
            "longer matches the current source; re-verify and update it, "
            "do not delete the entries to make the run pass:"
        )
        for entry in stale:
            print(f"  - {entry.get('id', '?')}: {entry.get('reason', '?')}")
        return 1

    # A partial run must never pass: unexecuted work items are not
    # kills, and an interrupted exec's summary would otherwise read as
    # a clean pass when every completed mutant happened to be killed.
    # Resume the session (see the runner docstring / CONTRIBUTING.md
    # §2.3) and gate on the finished run instead.
    pending = summary.get("pending", 0) or 0
    if pending > 0:
        print(
            f"[ERROR] {pending} work item(s) never executed — this is a "
            "partial run, not a pass. Resume the session and gate on the "
            "finished run."
        )
        return 1

    unexplained = summary.get("unexplained_surviving", summary.get("surviving", 0))
    if unexplained > 0:
        print(
            f"[WARNING] {summary.get('surviving', 0)} surviving mutant(s) detected "
            f"({summary.get('equivalent', 0)} accepted as equivalent per "
            f"mutation-baseline.toml, {unexplained} unexplained)!"
        )
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

    if summary.get("equivalent", 0):
        print(
            f"[OK] All mutations caught! ({summary['equivalent']} surviving "
            "mutant(s) accepted as equivalent per mutation-baseline.toml; "
            f"{summary.get('equivalent_dormant', 0)} baseline entr(y/ies) "
            f"dormant, {summary.get('equivalent_superseded', 0)} superseded.)"
        )
    else:
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
        "equivalent": 0,
        "equivalent_mutants": [],
        "equivalent_dormant": 0,
        "equivalent_dormant_ids": [],
        "equivalent_superseded": 0,
        "equivalent_superseded_ids": [],
        "unexplained_surviving": 0,
        "stale_baseline_entries": [],
        "baseline_entries": 0,
        "skipped_reason": SKIPPED_REASON_NO_CHANGES,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run mutation testing for TextForensics",
        epilog=(
            "Exec timeout and resume: a budget-0 (full) session has NO wall-clock "
            "cap — a full session takes ~20 h and the old 3600 s kill died "
            "mid-mutant. Pass --exec-timeout SECONDS only to chunk a run "
            "deliberately (0 = no cap); on expiry the partial session is dumped "
            "and the run exits 1 with resume instructions. Resume with "
            "--resume <session>.sqlite (the runner refuses to exec against a "
            "modified target module — restore it first with "
            "`git checkout -- <module file>` — and removes nothing itself). "
            "Sessions started before the resume TOML existed use "
            "--resume-toml .cosmic-ray.toml. Manual fallback, from the repo root "
            "after restoring the source: "
            "`cosmic-ray exec mutation-results/<session>.toml <session>.sqlite`. "
            "If git reports a stale lock and no git process is running: "
            "`rm .git/index.lock`. Full procedure: CONTRIBUTING.md §2.3."
        ),
    )
    parser.add_argument(
        "--mode", choices=["diff", "full", "safety-critical"], default="diff", help="Mutation mode"
    )
    parser.add_argument("--base-sha", default="origin/main", help="Base SHA for diff mode")
    parser.add_argument(
        "--config", default=".cosmic-ray.toml", help="Path to cosmic-ray TOML config"
    )
    parser.add_argument("--check-results", help="Check results from summary.json file")
    parser.add_argument(
        "--resume",
        default=None,
        metavar="SESSION.sqlite",
        help="Resume an interrupted session instead of starting a new one: "
        "runs only the session's remaining work items, dumps, and gates on "
        "the result exactly like a fresh run. Refuses when a target module "
        "is modified (leftover mutant — restore with "
        "`git checkout -- <module file>` first). The resume config defaults "
        "to mutation-results/<session>.toml written by the run that created "
        "the session; override with --resume-toml.",
    )
    parser.add_argument(
        "--resume-toml",
        default=None,
        metavar="CONFIG.toml",
        help="Config for --resume (default: mutation-results/<session>.toml; "
        "use .cosmic-ray.toml for sessions started before the resume TOML "
        "was persisted).",
    )
    parser.add_argument(
        "--exec-timeout",
        type=int,
        default=None,
        metavar="SECONDS",
        help="Wall-clock cap for the cosmic-ray exec step. Default: a budgeted "
        "run scales with the budget (budget * (per-test timeout + 15), "
        "floored at 600 s); a budget-0 (full) session has NO cap. 0 = no cap. "
        "On expiry the partial session is dumped, the run exits 1, and the "
        "resume procedure is printed — the session is resumed with --resume.",
    )
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
        "--baseline",
        default=None,
        help="Path to the equivalent-mutant baseline TOML "
        f"(default: {DEFAULT_BASELINE} in the project root when present; "
        "an explicitly given file that is missing or malformed fails loudly)",
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

    if args.exec_timeout is not None and args.exec_timeout < 0:
        print(f"--exec-timeout must be >= 0 (got {args.exec_timeout})", file=sys.stderr)
        return 1

    config_path = Path(args.config)
    project_root = Path.cwd()

    # Equivalent-mutant baseline: the default file is used when present;
    # an explicitly given file must exist and parse, or the run fails.
    if args.baseline:
        baseline_path = Path(args.baseline)
        if not baseline_path.is_file():
            print(f"Baseline file not found: {baseline_path}", file=sys.stderr)
            return 1
        try:
            baseline = load_baseline(baseline_path)
        except ValueError as exc:
            print(f"Invalid baseline file {baseline_path}: {exc}", file=sys.stderr)
            return 1
    else:
        default_baseline = project_root / DEFAULT_BASELINE
        if default_baseline.is_file():
            try:
                baseline = load_baseline(default_baseline)
            except ValueError as exc:
                print(f"Invalid baseline file {default_baseline}: {exc}", file=sys.stderr)
                return 1
        else:
            baseline = {"version": 1, "entries": []}
    if baseline["entries"]:
        print(
            f"Loaded equivalent-mutant baseline: {len(baseline['entries'])} "
            f"entr(y/ies) (source run {baseline.get('source_run')}, "
            f"commit {baseline.get('source_commit')})"
        )

    # Handle resume mode: run only the session's remaining work items.
    # --mode / --modules do not apply — the session already fixes them.
    if args.resume:
        session_path = Path(args.resume)
        if args.resume_toml:
            resume_toml = Path(args.resume_toml)
        else:
            resume_toml = project_root / "mutation-results" / f"{session_path.stem}.toml"
            if not resume_toml.is_file() and (project_root / ".cosmic-ray.toml").is_file():
                print(
                    "No persisted resume TOML for this session (it was started "
                    "before the runner wrote one); falling back to the checked-in "
                    ".cosmic-ray.toml — same per-mutant timeout, full-suite test "
                    "command, so the resume is correct but slower."
                )
                resume_toml = project_root / ".cosmic-ray.toml"
        exit_code, records = resume_cosmic_ray(
            session_path=session_path,
            resume_toml=resume_toml,
            exec_timeout=args.exec_timeout,
            project_root=project_root,
        )
        summary = parse_results(records, baseline=baseline, project_root=project_root)
        write_summary(summary, Path("mutation-results"))
        if exit_code == 0:
            return check_results(Path("mutation-results/summary.json"))
        return 1

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
        exec_timeout=args.exec_timeout,
    )

    # Parse and write results
    summary = parse_results(records, baseline=baseline, project_root=project_root)
    write_summary(summary, Path("mutation-results"))

    # Return appropriate exit code based on results
    if exit_code == 0:
        return check_results(Path("mutation-results/summary.json"))
    else:
        # Cosmic-ray itself failed
        return 1


if __name__ == "__main__":
    sys.exit(main())
