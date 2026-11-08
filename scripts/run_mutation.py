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
position: ``trust_map_from_capability_ledger`` L542:54 proves it, with
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
_MODULE_TEST_FILES: dict[str, list[str]] = {
    # Policy tests live in test_enterprise_policy.py, not test_policy.py.
    "textforensics.policy": ["tests/test_enterprise_policy.py"],
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
    share equivalence — at ``trust_map_from_capability_ledger`` L542:54,
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
    """
    source_path = module_path(entry["module"], project_root)
    if not source_path.is_file():
        return False, f"module source not found: {source_path}"
    try:
        source = source_path.read_text()
    except OSError as exc:
        return False, f"module source unreadable: {exc}"
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return False, f"module does not parse: {exc}"
    lines = source.splitlines()
    if entry["kind"] in BASELINE_ANNOTATION_KINDS:
        return _validate_annotation_entry(entry, tree, source, lines)
    if entry["kind"] in BASELINE_RUNTIME_KINDS:
        if entry["kind"] == "ulp-equivalent":
            ok, reason = _validate_ulp_fields(entry)
            if not ok:
                return False, reason
        return _validate_runtime_entry(entry, tree, source, lines)
    return False, f"unknown baseline kind {entry['kind']!r}"


def _validate_annotation_entry(
    entry: dict[str, Any], tree: ast.AST, source: str, lines: list[str]
) -> tuple[bool, str]:
    """Re-validate an annotation-kind entry against the current source.

    Returns ``(True, "ok")`` only when every check holds: the module
    still uses postponed evaluation, the recorded position still holds
    the recorded operator inside an annotation, the enclosing function
    still matches, and the annotation text is unchanged.
    """
    if not _has_postponed_evaluation(tree):
        return (
            False,
            "module no longer uses postponed evaluation "
            "(`from __future__ import annotations` missing) — the annotation "
            "may now be evaluated at runtime, so the equivalence proof no "
            "longer holds",
        )
    start_line, start_col = entry["start_pos"]
    end_line, end_col = entry["end_pos"]
    if not (1 <= start_line <= len(lines)) or start_line != end_line:
        return False, f"position {entry['start_pos']} is outside the current source"
    line = lines[start_line - 1]
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
    for candidate in _annotation_spans(tree, source):
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


def _validate_runtime_entry(
    entry: dict[str, Any], tree: ast.AST, source: str, lines: list[str]
) -> tuple[bool, str]:
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
    """
    start_line, start_col = entry["start_pos"]
    end_line, end_col = entry["end_pos"]
    if not (1 <= start_line <= len(lines)) or start_line != end_line:
        return False, f"position {entry['start_pos']} is outside the current source"
    line = lines[start_line - 1]
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
    name, node = _enclosing_function(tree, start_line, start_col)
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
    current = _function_fingerprint(source, node)
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
