"""Canonical local verification command for TextForensics (W0).

Mirrors the complete CI surface (every job in ``.github/workflows/*.yml``)
as locally executable subprocess gates, or as explicitly ``unavailable`` /
``not_applicable`` gates with a reason. Never reports an unexecuted gate
as ``pass``.

Usage:
    python scripts/verify_release.py [--json PATH] [--gate NAME ...]
                                     [--candidate-sha SHA]

Exit codes (frozen W0 contract):
    0  every required gate passed;
    1  a required gate failed (and no exit-2 condition applies);
    2  incomplete: a required gate is skipped / unavailable / zero_work /
       not_applicable, the candidate SHA is stale, the working tree is
       dirty, or a required tool / artifact / baseline is missing.

A child process exit 2 is a FAILURE of its gate (status ``fail``), never a
pass. A dirty tree is not a verifiable candidate: gates are not executed
at all and every gate is reported ``not_applicable`` (same treatment as a
stale ``--candidate-sha``). The command never requires network access, the
GitHub API, or any remote service, and never dispatches a release, creates
a tag, contacts an upload endpoint, or pushes an image. It writes nothing
inside the repository except through ``--json PATH`` when the caller points
it there; all per-gate working files live in a retained temporary work
directory whose path is recorded in the report.

Status vocabulary (exact strings, no others): ``pass``, ``fail``,
``skipped``, ``unavailable``, ``not_applicable``, ``zero_work``.
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

VERSION = "1.0.0"

STATUSES = (
    "pass",
    "fail",
    "skipped",
    "unavailable",
    "not_applicable",
    "zero_work",
)

# Statuses that make a required gate incomplete (exit 2). A required gate
# that is ``not_applicable`` is also incomplete: required gates accept
# ONLY ``pass`` (a required gate that does not apply to this candidate
# cannot yield a passing verdict).
INCOMPLETE_STATUSES = ("skipped", "unavailable", "zero_work", "not_applicable")

PYTEST_WORK = {
    "type": "regex_sum",
    "patterns": [
        r"(\d+) passed",
        r"(\d+) failed",
        r"(\d+) skipped",
        r"(\d+) deselected",
        r"(\d+) errors?",
    ],
}

JQ_FILTER = (
    'walk(if type == "object" then del(.runtime_ms, .generated_at_utc, '
    ".timestamp, .created_at, .generated_at) else . end)"
)

SAMPLE_TEXT_CLI = (
    "This is a sample text for reproducibility testing.\n"
    "It contains multiple sentences to ensure meaningful analysis.\n"
    "The text should produce identical results across multiple runs.\n"
    "We will verify that the CLI outputs are deterministic.\n"
    "This helps ensure the reliability of the detection system.\n"
)

SAMPLE_TEXT_CASE = (
    "This is a sample text for case-file reproducibility testing.\n"
    "It contains multiple sentences to ensure meaningful analysis.\n"
)

SAMPLE_TEXT_REPORT = (
    "This is a sample text for detector determinism testing.\n"
    "It contains multiple sentences to ensure meaningful analysis.\n"
    "The text should produce identical results across multiple runs.\n"
)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _git(args, cwd):
    """Run git and return stripped stdout, or None on any failure."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def sha256_file(path):
    """SHA-256 hex digest of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_tool_binary(name):
    """Resolve a tool binary: the venv bin dir first, then PATH."""
    venv_bin = Path(sys.executable).parent / name
    if venv_bin.exists():
        return str(venv_bin)
    found = shutil.which(name)
    return found


def check_missing(spec):
    """Return a detail string naming the missing tool, or None if present."""
    kind = spec["kind"]
    name = spec["name"]
    if kind == "binary":
        if find_tool_binary(name) is None:
            return f"missing required tool: {name} binary not found"
        return None
    if kind == "module":
        try:
            found = importlib.util.find_spec(name)
        except (ImportError, ValueError):
            found = None
        if found is None:
            return f"missing required tool: Python module {name} not installed"
        return None
    raise ValueError(f"unknown missing-tool kind: {kind}")


def expand(template, ctx):
    """Expand {python} / {repo} / {workdir} / {venvbin} placeholders."""
    subs = {
        "{python}": ctx["python"],
        "{repo}": str(ctx["repo_root"]),
        "{workdir}": str(ctx["work_dir"]),
        "{venvbin}": str(Path(ctx["python"]).parent),
    }
    result = template
    for key, value in subs.items():
        result = result.replace(key, value)
    return result


def resolve_argv(argv, ctx):
    """Expand placeholders in every argv element."""
    return [expand(arg, ctx) for arg in argv]


def display_command(argv):
    """Shell-quoted display form of an argv list."""
    return " ".join(shlex.quote(arg) for arg in argv)


def one_line(text, limit=200):
    """Last informative line of output, flattened and truncated.

    Separator-only lines (runs of dashes / equals / stars) are skipped:
    they carry no information and otherwise become useless fail details.
    """
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    informative = [line for line in lines if not re.fullmatch(r"[-=~_*#\s]+", line)]
    picked = informative[-1] if informative else (lines[-1] if lines else "")
    return picked.replace("\n", " ")[:limit]


def parse_work(spec, output, ctx):
    """Count the positive work a gate executed, per its parser spec."""
    kind = spec["type"]
    if kind == "fixed":
        return int(spec["value"])
    if kind == "regex_sum":
        total = 0
        for pattern in spec["patterns"]:
            for match in re.finditer(pattern, output or ""):
                groups = [g for g in match.groups() if g is not None]
                if groups:
                    total += sum(int(g) for g in groups)
                else:
                    total += 1
        return total
    if kind == "line_count":
        return len(re.findall(spec["pattern"], output or "", re.MULTILINE))
    if kind == "py_files":
        total = 0
        for dirname in spec["dirs"]:
            root = ctx["repo_root"] / dirname
            if root.exists():
                total += sum(1 for _ in root.rglob("*.py"))
        return total
    if kind == "installed_dists":
        return len(list(importlib.metadata.distributions()))
    if kind == "sbom_components":
        path = ctx["repo_root"] / "sbom" / "textforensics.cdx.json"
        try:
            return len(json.loads(path.read_text(encoding="utf-8"))["components"])
        except (OSError, ValueError, KeyError, TypeError):
            return 0
    if kind == "json_key_count":
        path = Path(expand(spec["file"], ctx))
        try:
            return len(json.loads(path.read_text(encoding="utf-8"))[spec["key"]])
        except (OSError, ValueError, KeyError, TypeError):
            return 0
    if kind == "coverage_total":
        match = re.search(r"^TOTAL\s+(\d+)", output or "", re.MULTILINE)
        return int(match.group(1)) if match else 0
    if kind == "dist_files":
        directory = Path(expand(spec["dir"], ctx))
        if directory.exists():
            return len(list(directory.iterdir()))
        return 0
    raise ValueError(f"unknown work parser type: {kind}")


def parse_work_safe(spec, output, ctx):
    """parse_work, returning 0 instead of raising on bad input."""
    try:
        return parse_work(spec, output, ctx)
    except (ValueError, TypeError, KeyError):
        return 0


# ---------------------------------------------------------------------------
# Gate definition factories
# ---------------------------------------------------------------------------


def subprocess_gate(
    name,
    ci_workflow,
    ci_job,
    argv,
    work,
    required=True,
    timeout_s=300,
    missing=None,
    stdin=None,
    cwd="repo",
    env_extra=None,
    coverage_file=None,
    artifacts=None,
):
    """Build a gate definition for one subprocess invocation."""
    return {
        "name": name,
        "ci_workflow": ci_workflow,
        "ci_job": ci_job,
        "required": required,
        "kind": "subprocess",
        "argv": list(argv),
        "work": work,
        "timeout_s": timeout_s,
        "missing": missing,
        "stdin": stdin,
        "cwd": cwd,
        "env_extra": env_extra or {},
        "coverage_file": coverage_file,
        "artifacts": artifacts or [],
    }


def static_gate(name, ci_workflow, ci_job, kind, reason, required=True):
    """Build a gate that never executes: unavailable / not_applicable."""
    assert kind in ("unavailable", "not_applicable")
    return {
        "name": name,
        "ci_workflow": ci_workflow,
        "ci_job": ci_job,
        "required": required,
        "kind": kind,
        "reason": reason,
    }


def special_gate(name, ci_workflow, ci_job, special, required=True, timeout_s=300):
    """Build a gate implemented by a named special handler."""
    return {
        "name": name,
        "ci_workflow": ci_workflow,
        "ci_job": ci_job,
        "required": required,
        "kind": "special",
        "special": special,
        "timeout_s": timeout_s,
    }


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


def build_context(repo_root, work_dir, candidate_sha=None, head_sha=None, dirty=None):
    """Build the run context. ``head_sha`` / ``dirty`` may be injected by
    tests; when omitted they are read from git (dirty defaults to True --
    fail closed -- if git cannot answer)."""
    repo_root = Path(repo_root)
    work_dir = Path(work_dir)
    if head_sha is None:
        head_sha = _git(["rev-parse", "HEAD"], repo_root) or "unknown"
    if dirty is None:
        status = _git(["status", "--porcelain"], repo_root)
        dirty = bool(status) if status is not None else True
    stale_sha = candidate_sha is not None and candidate_sha != head_sha
    env = dict(os.environ)
    src = str(repo_root / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = src + (os.pathsep + existing if existing else "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # The command is specified to run under the canonical venv, so its
    # children must see that venv's binaries: pre-commit's local hooks
    # invoke bare `python`, and tests invoke the bare `textforensics`
    # console script. Without this, both fail with FileNotFoundError
    # whenever the caller's PATH lacks the venv bin dir.
    venv_bin = str(Path(sys.executable).parent)
    path_entries = env.get("PATH", "").split(os.pathsep) if env.get("PATH") else []
    if venv_bin not in path_entries:
        env["PATH"] = venv_bin + (os.pathsep + env["PATH"] if env.get("PATH") else "")
    return {
        "repo_root": repo_root,
        "work_dir": work_dir,
        "head_sha": head_sha,
        "dirty": dirty,
        "candidate_sha": candidate_sha,
        "stale_sha": stale_sha,
        "python": sys.executable,
        "env": env,
        "coverage_file": None,
        "snapshot_dir": None,
        "snapshot_dist_dir": None,
    }


def child_env(ctx, gate):
    """Environment for a child process: base env plus gate extras."""
    env = dict(ctx["env"])
    for key, value in (gate.get("env_extra") or {}).items():
        env[key] = expand(value, ctx)
    return env


def make_record(gate, status, executed_work, command, duration_s, detail, artifacts=None):
    """One per-gate result record (frozen shape)."""
    assert status in STATUSES
    return {
        "name": gate["name"],
        "ci_workflow": gate["ci_workflow"],
        "ci_job": gate["ci_job"],
        "required": gate["required"],
        "status": status,
        "executed_work": int(executed_work),
        "command": command,
        "duration_s": round(float(duration_s), 3),
        "detail": detail,
        "artifacts": artifacts or [],
    }


def collect_artifacts(gate, ctx):
    """SHA-256 records for gate output files that still exist."""
    collected = []
    for template in gate.get("artifacts") or []:
        path = Path(expand(template, ctx))
        if path.exists() and path.is_file():
            collected.append({"path": str(path), "sha256": sha256_file(path)})
    return collected


# ---------------------------------------------------------------------------
# Subprocess gates
# ---------------------------------------------------------------------------


def run_subprocess(argv, ctx, gate, stdin=None):
    """Run one child process; return (returncode, combined output, detail).

    returncode is None on timeout / spawn failure (detail explains why).
    """
    timeout_s = gate.get("timeout_s", 300)
    cwd = str(ctx["repo_root"]) if gate.get("cwd", "repo") == "repo" else str(ctx["work_dir"])
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=cwd,
            env=child_env(ctx, gate),
            input=stdin,
        )
    except subprocess.TimeoutExpired:
        return None, "", f"timed out after {timeout_s}s"
    except OSError as exc:
        return None, "", f"could not start child process: {exc}"
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output, one_line(output)


def run_subprocess_gate(gate, ctx):
    """Execute a plain subprocess gate and classify its result."""
    started = time.monotonic()
    argv = resolve_argv(gate["argv"], ctx)
    command = display_command(argv)
    missing = gate.get("missing")
    if missing:
        problem = check_missing(missing)
        if problem is not None:
            return make_record(gate, "unavailable", 0, command, 0.0, problem)
    returncode, output, last_line = run_subprocess(argv, ctx, gate, stdin=gate.get("stdin"))
    duration = time.monotonic() - started
    work = parse_work_safe(gate.get("work", {"type": "fixed", "value": 0}), output, ctx)
    artifacts = collect_artifacts(gate, ctx)
    if gate.get("coverage_file"):
        candidate = Path(expand(gate["coverage_file"], ctx))
        if candidate.exists():
            ctx["coverage_file"] = candidate
    if returncode is None:
        # Timeout or spawn failure: the gate did not complete.
        return make_record(gate, "fail", work, command, duration, last_line, artifacts)
    if returncode != 0:
        # Any nonzero child exit is a gate failure, including exit 2.
        detail = f"child exit {returncode}"
        if last_line:
            detail += f": {last_line}"
        return make_record(gate, "fail", work, command, duration, detail, artifacts)
    if work == 0:
        detail = "gate ran but executed zero work"
        if last_line:
            detail += f": {last_line}"
        return make_record(gate, "zero_work", 0, command, duration, detail, artifacts)
    detail = last_line or "ok"
    return make_record(gate, "pass", work, command, duration, detail, artifacts)


# ---------------------------------------------------------------------------
# Shared helpers for special gates
# ---------------------------------------------------------------------------


def git_archive_snapshot(repo_root, dest_dir):
    """Extract HEAD into dest_dir via `git archive`; return True on success."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "archive", "HEAD"],
        cwd=str(repo_root),
        capture_output=True,
        timeout=300,
    )
    if proc.returncode != 0 or not proc.stdout:
        return False
    archive_path = dest_dir.parent / (dest_dir.name + ".tar")
    archive_path.write_bytes(proc.stdout)
    try:
        with tarfile.open(archive_path, "r") as archive:
            archive.extractall(dest_dir, filter="data")
    except (tarfile.TarError, OSError):
        return False
    return True


def snapshot_dist_dir(ctx):
    """The dist dir produced by the package-build gate, or None."""
    dist_dir = ctx.get("snapshot_dist_dir")
    if dist_dir is not None and Path(dist_dir).exists():
        return Path(dist_dir)
    return None


def run_checked(argv, ctx, gate, cwd=None, env=None, stdin=None):
    """Run a child for a special gate; return (returncode, output)."""
    timeout_s = gate.get("timeout_s", 300)
    run_env = dict(ctx["env"]) if env is None else env
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=str(cwd or ctx["repo_root"]),
            env=run_env,
            input=stdin,
        )
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout_s}s"
    except OSError as exc:
        return None, f"could not start child process: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def special_result(gate, status, work, command, detail, artifacts=None):
    """Result dict from a special handler (duration added by run_gate)."""
    return {
        "status": status,
        "executed_work": int(work),
        "command": command,
        "detail": detail,
        "artifacts": artifacts or [],
    }


def file_artifacts(paths):
    """SHA-256 records for files that exist."""
    collected = []
    for path in paths:
        path = Path(path)
        if path.exists() and path.is_file():
            collected.append({"path": str(path), "sha256": sha256_file(path)})
    return collected


# ---------------------------------------------------------------------------
# Special gates
# ---------------------------------------------------------------------------


def special_report_card_fresh(gate, ctx):
    """Reproduce the CI report-card freshness check without mutating the
    repo: regenerate the card into the work dir and byte-compare it with
    the committed card."""
    tmp_card = ctx["work_dir"] / "report-card.md"
    argv = [
        ctx["python"],
        "scripts/check_claims.py",
        "--report-card",
        str(tmp_card),
    ]
    command = display_command(argv)
    returncode, output = run_checked(argv, ctx, gate)
    if returncode is None:
        return special_result(gate, "fail", 0, command, output)
    if returncode != 0:
        return special_result(
            gate, "fail", 0, command, f"child exit {returncode}: {one_line(output)}"
        )
    committed = ctx["repo_root"] / "docs" / "evidence" / "report-card.md"
    if not tmp_card.exists():
        return special_result(gate, "fail", 0, command, "report card was not generated")
    if not committed.exists():
        return special_result(
            gate, "fail", 0, command, "committed docs/evidence/report-card.md is missing"
        )
    artifacts = file_artifacts([tmp_card])
    if tmp_card.read_bytes() != committed.read_bytes():
        return special_result(
            gate,
            "fail",
            1,
            command,
            "report card is stale: generated card differs from committed "
            "docs/evidence/report-card.md",
            artifacts,
        )
    return special_result(
        gate, "pass", 1, command, "generated report card matches the committed card", artifacts
    )


def special_coverage(gate, ctx):
    """coverage report --fail-under=75 on the pytest-core gate's data."""
    data = ctx.get("coverage_file")
    if data is None or not Path(data).exists():
        return special_result(
            gate,
            "unavailable",
            0,
            None,
            "no coverage data in this invocation: the pytest-core gate did "
            "not run or produced no coverage data",
        )
    missing = check_missing({"kind": "module", "name": "coverage"})
    if missing is not None:
        return special_result(gate, "unavailable", 0, None, missing)
    argv = [
        ctx["python"],
        "-m",
        "coverage",
        "report",
        f"--data-file={data}",
        "--fail-under=75",
    ]
    command = display_command(argv)
    returncode, output = run_checked(argv, ctx, gate)
    if returncode is None:
        return special_result(gate, "fail", 0, command, output)
    work = parse_work_safe({"type": "coverage_total"}, output, ctx)
    if returncode != 0:
        return special_result(
            gate, "fail", work, command, f"child exit {returncode}: {one_line(output)}"
        )
    if work == 0:
        return special_result(
            gate, "zero_work", 0, command, "coverage report measured zero statements"
        )
    return special_result(gate, "pass", work, command, one_line(output) or "coverage gate passed")


def special_mutation_diff(gate, ctx):
    """Diff-mutation evidence presence only: validate an existing
    summary for this checkout; never launch a mutation campaign."""
    summary_path = ctx["repo_root"] / "mutation-results" / "summary.json"
    if not summary_path.exists():
        return special_result(
            gate,
            "unavailable",
            0,
            None,
            "no completed diff-mutation run artifact for this HEAD "
            "(mutation-results/summary.json is absent); verify_release "
            "does not launch mutation campaigns",
        )
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return special_result(gate, "fail", 0, None, "mutation summary is not valid JSON")
    total = int(summary.get("total", 0) or 0)
    argv = [ctx["python"], "scripts/run_mutation.py", "--check-results", str(summary_path)]
    command = display_command(argv)
    artifacts = file_artifacts([summary_path])
    returncode, output = run_checked(argv, ctx, gate)
    if returncode is None:
        return special_result(gate, "fail", total, command, output, artifacts)
    if returncode != 0:
        return special_result(
            gate, "fail", total, command, f"child exit {returncode}: {one_line(output)}", artifacts
        )
    detail = (
        "mutation summary accepted; note: the summary carries no source-SHA "
        "binding, so HEAD binding is not established by this gate"
    )
    if total == 0:
        reason = summary.get("skipped_reason", "")
        detail = "check passed but the summary records zero mutants"
        if reason:
            detail += f" (skipped_reason={reason})"
        return special_result(gate, "zero_work", 0, command, detail, artifacts)
    return special_result(gate, "pass", total, command, detail, artifacts)


def special_package_build(gate, ctx):
    """Build wheel + sdist from a `git archive HEAD` snapshot (outputs
    outside the source tree), exactly as the reproducibility fix
    direction requires. Uses --no-isolation: local verification has no
    network access, unlike CI's isolated build."""
    for module in ("build", "wheel"):
        missing = check_missing({"kind": "module", "name": module})
        if missing is not None:
            return special_result(gate, "unavailable", 0, None, missing)
    snapshot = ctx["work_dir"] / "snapshot"
    if not git_archive_snapshot(ctx["repo_root"], snapshot):
        return special_result(gate, "fail", 0, None, "git archive HEAD failed")
    dist_dir = snapshot / "dist"
    argv = [
        ctx["python"],
        "-m",
        "build",
        "--no-isolation",
        "--wheel",
        "--sdist",
        "--outdir",
        str(dist_dir),
    ]
    command = display_command(argv)
    returncode, output = run_checked(argv, ctx, gate, cwd=snapshot)
    if returncode is None:
        return special_result(gate, "fail", 0, command, output)
    if returncode != 0:
        return special_result(
            gate, "fail", 0, command, f"child exit {returncode}: {one_line(output)}"
        )
    dists = sorted(dist_dir.iterdir()) if dist_dir.exists() else []
    if not dists:
        return special_result(gate, "zero_work", 0, command, "build produced no distributions")
    ctx["snapshot_dir"] = snapshot
    ctx["snapshot_dist_dir"] = dist_dir
    names = ", ".join(p.name for p in dists)
    return special_result(
        gate,
        "pass",
        len(dists),
        command,
        f"built {len(dists)} distributions: {names}",
        file_artifacts(dists),
    )


def special_package_twine(gate, ctx):
    """twine check on the distributions built by the package-build gate."""
    dist_dir = snapshot_dist_dir(ctx)
    if dist_dir is None:
        return special_result(
            gate,
            "unavailable",
            0,
            None,
            "no built distributions in this invocation: the package-build gate did not run",
        )
    missing = check_missing({"kind": "module", "name": "twine"})
    if missing is not None:
        return special_result(gate, "unavailable", 0, None, missing)
    files = sorted(dist_dir.iterdir())
    argv = [ctx["python"], "-m", "twine", "check", *[str(p) for p in files]]
    command = display_command(argv)
    returncode, output = run_checked(argv, ctx, gate)
    if returncode is None:
        return special_result(gate, "fail", 0, command, output)
    work = parse_work_safe({"type": "regex_sum", "patterns": ["PASSED"]}, output, ctx)
    if returncode != 0:
        return special_result(
            gate, "fail", work, command, f"child exit {returncode}: {one_line(output)}"
        )
    if work == 0:
        return special_result(gate, "zero_work", 0, command, "twine checked zero distributions")
    return special_result(gate, "pass", work, command, one_line(output) or "twine check passed")


def special_package_wheel_contents(gate, ctx):
    """Replicate the CI wheel-contents assertions on the built wheel."""
    dist_dir = snapshot_dist_dir(ctx)
    if dist_dir is None:
        return special_result(
            gate,
            "unavailable",
            0,
            None,
            "no built distributions in this invocation: the package-build gate did not run",
        )
    program = "\n".join(
        [
            "import glob, zipfile",
            f"wheel = glob.glob({str(dist_dir / '*.whl')!r})",
            "assert len(wheel) == 1, wheel",
            "names = zipfile.ZipFile(wheel[0]).namelist()",
            "for suffix in ('schemas/case-file.schema.json',",
            "               'schemas/detector-result.schema.json',",
            "               'schemas/forensic-bundle.schema.json'):",
            "    assert any(n.endswith(suffix) for n in names), suffix",
            "assert any('/licenses/LICENSE' in n for n in names), names",
            "print('WHEEL CONTENTS OK')",
        ]
    )
    argv = [ctx["python"], "-c", program]
    command = display_command(argv)
    returncode, output = run_checked(argv, ctx, gate)
    if returncode is None:
        return special_result(gate, "fail", 0, command, output)
    if returncode != 0:
        return special_result(
            gate, "fail", 0, command, f"child exit {returncode}: {one_line(output)}"
        )
    return special_result(gate, "pass", 4, command, "wheel contains 3 schemas and LICENSE")


def special_wheel_install_smoke(gate, ctx):
    """Install the built wheel --no-deps into a throwaway venv (with
    system site packages, so the wheel's runtime deps resolve without
    network) and smoke-test it from outside the repository, with
    PYTHONPATH removed so the wheel -- not the worktree -- is imported."""
    dist_dir = snapshot_dist_dir(ctx)
    if dist_dir is None:
        return special_result(
            gate,
            "unavailable",
            0,
            None,
            "no built distributions in this invocation: the package-build gate did not run",
        )
    wheels = sorted(dist_dir.glob("*.whl"))
    if not wheels:
        return special_result(gate, "fail", 0, None, "no wheel was built")
    venv_dir = ctx["work_dir"] / "install-venv"
    venv_python = venv_dir / "bin" / "python"
    steps = []
    argv_venv = [ctx["python"], "-m", "venv", "--system-site-packages", str(venv_dir)]
    steps.append(display_command(argv_venv))
    returncode, output = run_checked(argv_venv, ctx, gate)
    if returncode is None or returncode != 0:
        detail = output if returncode is None else f"child exit {returncode}: {one_line(output)}"
        return special_result(
            gate, "fail", 0, " && ".join(steps), f"venv creation failed: {detail}"
        )
    argv_install = [
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--no-deps",
        "--disable-pip-version-check",
        str(wheels[0]),
    ]
    steps.append(display_command(argv_install))
    returncode, output = run_checked(argv_install, ctx, gate)
    if returncode is None or returncode != 0:
        detail = output if returncode is None else f"child exit {returncode}: {one_line(output)}"
        return special_result(
            gate, "fail", 0, " && ".join(steps), f"wheel install failed: {detail}"
        )
    smoke_env = dict(ctx["env"])
    smoke_env.pop("PYTHONPATH", None)
    checks = [
        ([str(venv_python), "-m", "textforensics.cli", "--version"], "version smoke"),
        (
            [
                str(venv_python),
                "-c",
                "from textforensics.schema import load_schema; "
                "assert load_schema('case-file')['type'] == 'object'; "
                "print('SCHEMA OK')",
            ],
            "schema smoke",
        ),
    ]
    for argv_check, _label in checks:
        steps.append(display_command(argv_check))
        returncode, output = run_checked(argv_check, ctx, gate, cwd=ctx["work_dir"], env=smoke_env)
        if returncode is None or returncode != 0:
            detail = (
                output if returncode is None else f"child exit {returncode}: {one_line(output)}"
            )
            return special_result(
                gate, "fail", 0, " && ".join(steps), f"smoke check failed: {detail}"
            )
    return special_result(
        gate, "pass", 2, " && ".join(steps), "installed wheel: --version and schema load ok"
    )


def special_cli_scan_smoke(gate, ctx):
    """The CI OS-smoke JSON scan: pipe one sample sentence through
    `textforensics scan --json` and require valid JSON output."""
    argv = [ctx["python"], "-m", "textforensics.cli", "scan", "--json"]
    command = display_command(argv)
    returncode, output = run_checked(
        argv, ctx, gate, stdin="I tested this yesterday and wrote down what happened."
    )
    if returncode is None:
        return special_result(gate, "fail", 0, command, output)
    if returncode != 0:
        return special_result(
            gate, "fail", 0, command, f"child exit {returncode}: {one_line(output)}"
        )
    try:
        json.loads(output)
    except ValueError:
        return special_result(gate, "fail", 0, command, "scan output is not valid JSON")
    return special_result(gate, "pass", 1, command, "scan returned valid JSON")


def _jq_filtered_runs(gate, ctx, cli_argv, sample_text, sample_name, evidence_prefix, runs=5):
    """Run a CLI command N times, jq-filter non-deterministic fields, and
    require byte-identical filtered output (the reproducibility jobs)."""
    jq = find_tool_binary("jq")
    if jq is None:
        return special_result(
            gate, "unavailable", 0, None, "missing required tool: jq binary not found"
        )
    testdata = ctx["work_dir"] / "testdata"
    testdata.mkdir(parents=True, exist_ok=True)
    sample_path = testdata / sample_name
    sample_path.write_text(sample_text, encoding="utf-8")
    evidence_dir = ctx["work_dir"] / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    command = display_command(cli_argv) + f" (x{runs}, jq-filtered, sha256-compared)"
    hashes = []
    artifacts = []
    for i in range(1, runs + 1):
        argv = [arg.replace("{sample}", str(sample_path)) for arg in cli_argv]
        returncode, output = run_checked(argv, ctx, gate)
        if returncode is None:
            return special_result(gate, "fail", 0, command, output)
        if returncode != 0:
            return special_result(
                gate, "fail", 0, command, f"child exit {returncode}: {one_line(output)}"
            )
        try:
            filtered = subprocess.run(
                [jq, JQ_FILTER],
                input=output,
                capture_output=True,
                text=True,
                timeout=gate.get("timeout_s", 300),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return special_result(gate, "fail", 0, command, f"jq filter failed: {exc}")
        if filtered.returncode != 0:
            return special_result(
                gate, "fail", 0, command, f"jq filter failed: {one_line(filtered.stderr)}"
            )
        out_path = evidence_dir / f"{evidence_prefix}_run_{i}.json"
        out_path.write_text(filtered.stdout, encoding="utf-8")
        hashes.append(hashlib.sha256(filtered.stdout.encode("utf-8")).hexdigest())
        artifacts.append({"path": str(out_path), "sha256": hashes[-1]})
    if len(set(hashes)) != 1:
        differing = [i + 1 for i, h in enumerate(hashes) if h != hashes[0]]
        return special_result(
            gate,
            "fail",
            runs,
            command,
            f"filtered output differs: run(s) {differing} differ from run 1",
            artifacts,
        )
    return special_result(
        gate,
        "pass",
        runs,
        command,
        f"all {runs} runs produced identical filtered output",
        artifacts,
    )


def special_cli_determinism(gate, ctx):
    """CI cli-determinism: scan 5x, jq-filter, compare hashes."""
    return _jq_filtered_runs(
        gate,
        ctx,
        [ctx["python"], "-m", "textforensics.cli", "scan", "--file", "{sample}", "--json"],
        SAMPLE_TEXT_CLI,
        "sample.txt",
        "scan",
    )


def special_case_file_determinism(gate, ctx):
    """CI case-file-determinism: export twice with --deterministic and
    require identical case_sha256."""
    testdata = ctx["work_dir"] / "testdata"
    testdata.mkdir(parents=True, exist_ok=True)
    sample_path = testdata / "sample.txt"
    sample_path.write_text(SAMPLE_TEXT_CASE, encoding="utf-8")
    outputs = []
    command_parts = []
    for name in ("c1.json", "c2.json"):
        out_path = ctx["work_dir"] / name
        argv = [
            ctx["python"],
            "-m",
            "textforensics.cli",
            "case",
            "export",
            "--file",
            str(sample_path),
            "--output",
            str(out_path),
            "--deterministic",
        ]
        command_parts.append(display_command(argv))
        returncode, output = run_checked(argv, ctx, gate)
        if returncode is None:
            return special_result(gate, "fail", 0, " && ".join(command_parts), output)
        if returncode != 0:
            return special_result(
                gate,
                "fail",
                0,
                " && ".join(command_parts),
                f"child exit {returncode}: {one_line(output)}",
            )
        outputs.append(out_path)
    command = " && ".join(command_parts)
    artifacts = file_artifacts(outputs)
    try:
        sha1 = json.loads(outputs[0].read_text(encoding="utf-8")).get("case_sha256")
        sha2 = json.loads(outputs[1].read_text(encoding="utf-8")).get("case_sha256")
    except (OSError, ValueError):
        return special_result(
            gate, "fail", 2, command, "case exports are not valid JSON", artifacts
        )
    if not sha1 or sha1 != sha2:
        return special_result(
            gate,
            "fail",
            2,
            command,
            "case_sha256 differs between deterministic exports",
            artifacts,
        )
    return special_result(
        gate,
        "pass",
        2,
        command,
        "deterministic exports share case_sha256",
        artifacts,
    )


def special_detector_determinism(gate, ctx):
    """CI detector-determinism: report 5x with --deterministic, jq-filter,
    compare hashes."""
    return _jq_filtered_runs(
        gate,
        ctx,
        [
            ctx["python"],
            "-m",
            "textforensics.cli",
            "report",
            "--file",
            "{sample}",
            "--deterministic",
        ],
        SAMPLE_TEXT_REPORT,
        "sample.txt",
        "report",
    )


def special_wheel_reproducibility(gate, ctx):
    """CI build-reproducibility, made fatal (ENG-03): build the wheel
    twice from independent clean snapshots with fixed SOURCE_DATE_EPOCH
    and PYTHONHASHSEED and require byte-identical output. Deviation from
    the workflow, recorded: the workflow pins setuptools==79.0.1, a
    version the repo's own security evidence rejected (ENG-10); the
    local gate uses the ambient build backend instead (--no-isolation,
    no network)."""
    for module in ("build", "wheel"):
        missing = check_missing({"kind": "module", "name": module})
        if missing is not None:
            return special_result(gate, "unavailable", 0, None, missing)
    wheels = []
    artifacts = []
    command_parts = []
    for label in ("repro-a", "repro-b"):
        snapshot = ctx["work_dir"] / label
        if not git_archive_snapshot(ctx["repo_root"], snapshot):
            return special_result(gate, "fail", 0, None, "git archive HEAD failed")
        dist_dir = snapshot / "dist"
        argv = [
            ctx["python"],
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--outdir",
            str(dist_dir),
        ]
        command_parts.append(display_command(argv))
        env = dict(ctx["env"])
        env["SOURCE_DATE_EPOCH"] = "1704067200"
        env["PYTHONHASHSEED"] = "0"
        returncode, output = run_checked(argv, ctx, gate, cwd=snapshot, env=env)
        if returncode is None:
            return special_result(gate, "fail", 0, " && ".join(command_parts), output)
        if returncode != 0:
            return special_result(
                gate,
                "fail",
                0,
                " && ".join(command_parts),
                f"child exit {returncode}: {one_line(output)}",
            )
        built = sorted(dist_dir.glob("*.whl")) if dist_dir.exists() else []
        if len(built) != 1:
            return special_result(
                gate,
                "fail",
                0,
                " && ".join(command_parts),
                f"expected exactly 1 wheel in {label}, found {len(built)}",
            )
        wheels.append(built[0])
        artifacts.append({"path": str(built[0]), "sha256": sha256_file(built[0])})
    command = " && ".join(command_parts)
    hash_a = artifacts[0]["sha256"]
    hash_b = artifacts[1]["sha256"]
    if hash_a != hash_b:
        return special_result(
            gate,
            "fail",
            2,
            command,
            f"wheel builds differ: {hash_a[:12]} vs {hash_b[:12]} (fatal byte comparison; ENG-03)",
            artifacts,
        )
    return special_result(
        gate,
        "pass",
        2,
        command,
        f"two independent builds are byte-identical (sha256 {hash_a[:12]}...)",
        artifacts,
    )


def special_benchmark_compare(gate, ctx):
    """CI benchmark comparison: only meaningful against a resolved
    immutable baseline artifact. No baseline exists for this HEAD, so
    the gate is not_applicable (ENG-13: a success label must not claim
    a matched baseline was evaluated)."""
    baseline = ctx["repo_root"] / "baseline" / "pytest-performance.json"
    if not baseline.exists():
        return special_result(
            gate,
            "not_applicable",
            0,
            None,
            "no baseline artifact for this HEAD (baseline/pytest-performance.json "
            "absent); comparison requires a resolved immutable baseline (ENG-13)",
        )
    argv = [
        ctx["python"],
        "-m",
        "pytest",
        "tests/test_performance.py",
        "--benchmark-only",
        "--benchmark-min-rounds=5",
        f"--benchmark-compare={baseline}",
        "--benchmark-compare-fail=mean:1.20",
        f"--benchmark-json={ctx['work_dir'] / 'pytest-performance-comparison.json'}",
    ]
    command = display_command(argv)
    returncode, output = run_checked(argv, ctx, gate)
    if returncode is None:
        return special_result(gate, "fail", 0, command, output)
    work = parse_work_safe(PYTEST_WORK, output, ctx)
    if returncode != 0:
        return special_result(
            gate, "fail", work, command, f"child exit {returncode}: {one_line(output)}"
        )
    if work == 0:
        return special_result(gate, "zero_work", 0, command, "benchmark comparison ran zero tests")
    return special_result(gate, "pass", work, command, one_line(output) or "comparison passed")


SPECIAL_HANDLERS = {
    "report_card_fresh": special_report_card_fresh,
    "coverage": special_coverage,
    "mutation_diff": special_mutation_diff,
    "package_build": special_package_build,
    "package_twine": special_package_twine,
    "package_wheel_contents": special_package_wheel_contents,
    "wheel_install_smoke": special_wheel_install_smoke,
    "cli_scan_smoke": special_cli_scan_smoke,
    "cli_determinism": special_cli_determinism,
    "case_file_determinism": special_case_file_determinism,
    "detector_determinism": special_detector_determinism,
    "wheel_reproducibility": special_wheel_reproducibility,
    "benchmark_compare": special_benchmark_compare,
}


def run_gate(gate, ctx):
    """Run one gate definition and return its result record."""
    started = time.monotonic()
    if gate["kind"] in ("unavailable", "not_applicable"):
        return make_record(gate, gate["kind"], 0, None, 0.0, gate["reason"])
    if gate["kind"] == "special":
        handler = SPECIAL_HANDLERS[gate["special"]]
        result = handler(gate, ctx)
        duration = time.monotonic() - started
        return make_record(
            gate,
            result["status"],
            result["executed_work"],
            result["command"],
            duration,
            result["detail"],
            result.get("artifacts") or [],
        )
    if gate["kind"] == "subprocess":
        return run_subprocess_gate(gate, ctx)
    raise ValueError(f"unknown gate kind: {gate['kind']}")


# ---------------------------------------------------------------------------
# Gate inventory: the complete CI surface.
#
# required=true  <=> the CI job runs on push (or PR) to main, i.e. it gates
#                   what lands on main. Schedule/dispatch-only jobs,
#                   PR-only checks and advisory jobs are required=false.
#                   An optional gate that FAILS is still shown as fail;
#                   it only does not change the verdict / exit code.
# ---------------------------------------------------------------------------

ENT_DEEP_SCHEMA_PROGRAM = "\n".join(
    [
        "import json",
        "from pathlib import Path",
        "import jsonschema",
        "schemas = sorted(Path('src/textforensics/schemas').glob('*.json'))",
        "assert schemas, 'no schemas found'",
        "for schema_file in schemas:",
        "    data = json.loads(schema_file.read_text(encoding='utf-8'))",
        "    jsonschema.Draft202012Validator.check_schema(data)",
        "    print(f'OK: {schema_file.name}')",
        "from textforensics.schema import load_schema",
        "for name in ('case-file', 'detector-result', 'forensic-bundle'):",
        "    assert load_schema(name)['type'] == 'object', name",
        "print('schema instances OK')",
    ]
)

GATE_DEFS = [
    # -- CI core (ci.yml, push-gated) -------------------------------------
    subprocess_gate(
        "pre-commit",
        ".github/workflows/ci.yml",
        "core",
        ["{venvbin}/pre-commit", "run", "--all-files"],
        {"type": "line_count", "pattern": r"(Passed|Failed|Skipped)$"},
        required=True,
        timeout_s=600,
        missing={"kind": "binary", "name": "pre-commit"},
    ),
    subprocess_gate(
        "ruff",
        ".github/workflows/ci.yml",
        "core",
        ["{venvbin}/ruff", "check", "src", "tests"],
        {"type": "py_files", "dirs": ["src", "tests"]},
        required=True,
        timeout_s=300,
        missing={"kind": "binary", "name": "ruff"},
    ),
    subprocess_gate(
        "compile",
        ".github/workflows/ci.yml",
        "core",
        ["{python}", "-m", "compileall", "-q", "src", "tests"],
        {"type": "py_files", "dirs": ["src", "tests"]},
        required=True,
        timeout_s=300,
    ),
    subprocess_gate(
        "pytest-core",
        ".github/workflows/ci.yml",
        "core",
        [
            "{python}",
            "-m",
            "coverage",
            "run",
            "--source=textforensics",
            "-m",
            "pytest",
            "tests",
            "-q",
            "--tb=short",
        ],
        PYTEST_WORK,
        required=True,
        timeout_s=1800,
        missing={"kind": "module", "name": "coverage"},
        env_extra={"COVERAGE_FILE": "{workdir}/.coverage"},
        coverage_file="{workdir}/.coverage",
    ),
    special_gate(
        "coverage",
        ".github/workflows/ci.yml",
        "core",
        "coverage",
        required=True,
        timeout_s=300,
    ),
    subprocess_gate(
        "golden",
        ".github/workflows/ci.yml",
        "core",
        ["{python}", "scripts/verify_golden.py"],
        {"type": "regex_sum", "patterns": [r"All (\d+) golden file"]},
        required=True,
        timeout_s=300,
    ),
    subprocess_gate(
        "pip-check",
        ".github/workflows/ci.yml",
        "core",
        ["{python}", "-m", "pip", "check"],
        {"type": "installed_dists"},
        required=True,
        timeout_s=300,
    ),
    subprocess_gate(
        "cli-smoke",
        ".github/workflows/ci.yml",
        "core",
        ["{python}", "-m", "textforensics.cli", "--version"],
        {"type": "fixed", "value": 1},
        required=True,
        timeout_s=120,
    ),
    special_gate(
        "cli-scan-smoke",
        ".github/workflows/ci.yml",
        "os-smoke",
        "cli_scan_smoke",
        required=True,
        timeout_s=300,
    ),
    subprocess_gate(
        "claims",
        ".github/workflows/ci.yml",
        "claims-gate",
        ["{python}", "scripts/check_claims.py", "--no-report-card"],
        {"type": "regex_sum", "patterns": [r"(\d+) passed, (\d+) failed"]},
        required=True,
        timeout_s=600,
    ),
    special_gate(
        "report-card-fresh",
        ".github/workflows/ci.yml",
        "claims-gate",
        "report_card_fresh",
        required=True,
        timeout_s=600,
    ),
    subprocess_gate(
        "sbom-check",
        ".github/workflows/ci.yml",
        "sbom",
        ["{python}", "scripts/generate_sbom.py", "--check"],
        {"type": "sbom_components"},
        required=True,
        timeout_s=600,
    ),
    subprocess_gate(
        "semver",
        ".github/workflows/semver.yml",
        "semver-check",
        ["{python}", "scripts/check_semver.py"],
        {"type": "fixed", "value": 1},
        required=True,
        timeout_s=120,
    ),
    # -- Supply chain (supply-chain.yml, push-gated) ----------------------
    subprocess_gate(
        "pip-audit",
        ".github/workflows/supply-chain.yml",
        "pip-audit-gate",
        ["{python}", "scripts/check_pip_audit.py", "--report", "{workdir}/pip-audit-gate.json"],
        {"type": "installed_dists"},
        required=True,
        timeout_s=600,
        missing={"kind": "module", "name": "pip_audit"},
        artifacts=["{workdir}/pip-audit-gate.json"],
    ),
    static_gate(
        "secrets-scan",
        ".github/workflows/supply-chain.yml",
        "secrets",
        "unavailable",
        "requires the gitleaks binary / gitleaks GitHub Action; gitleaks "
        "is not installed in the canonical venv",
        required=True,
    ),
    static_gate(
        "supply-chain-sbom",
        ".github/workflows/supply-chain.yml",
        "sbom",
        "unavailable",
        "requires anchore/sbom-action (Syft); the checked-in SBOM "
        "freshness is covered by the sbom-check gate",
        required=False,
    ),
    # -- Schemas + security tools -----------------------------------------
    subprocess_gate(
        "schemas",
        ".github/workflows/ci.yml",
        "core (pre-commit json-schema-validator hook)",
        ["{python}", "scripts/validate_schemas.py"],
        {"type": "line_count", "pattern": r"^OK: "},
        required=True,
        timeout_s=300,
    ),
    subprocess_gate(
        "bandit",
        ".github/workflows/enterprise-deep-verification.yml",
        "vulnerability-audit",
        ["{venvbin}/bandit", "-r", "src", "-ll", "-ii"],
        {"type": "py_files", "dirs": ["src"]},
        required=False,
        timeout_s=600,
        missing={"kind": "binary", "name": "bandit"},
    ),
    # -- Optional API / MCP surfaces (ci.yml, push-gated) -----------------
    subprocess_gate(
        "api-unittest",
        ".github/workflows/ci.yml",
        "api",
        ["{python}", "-m", "unittest", "tests.test_api", "-v"],
        {"type": "regex_sum", "patterns": [r"Ran (\d+) tests?"]},
        required=True,
        timeout_s=600,
    ),
    subprocess_gate(
        "api-create-app",
        ".github/workflows/ci.yml",
        "api",
        [
            "{python}",
            "-c",
            "from textforensics.api import create_app; "
            "assert create_app() is not None; print('APP OK')",
        ],
        {"type": "fixed", "value": 1},
        required=True,
        timeout_s=300,
    ),
    subprocess_gate(
        "mcp-smoke",
        ".github/workflows/ci.yml",
        "mcp",
        [
            "{python}",
            "-c",
            "from textforensics.mcp_server import _server; "
            "assert _server() is not None; print('MCP OK')",
        ],
        {"type": "fixed", "value": 1},
        required=True,
        timeout_s=300,
    ),
    # -- Package build (ci.yml package job, push-gated) -------------------
    special_gate(
        "package-build",
        ".github/workflows/ci.yml",
        "package",
        "package_build",
        required=True,
        timeout_s=600,
    ),
    special_gate(
        "package-twine",
        ".github/workflows/ci.yml",
        "package",
        "package_twine",
        required=True,
        timeout_s=300,
    ),
    special_gate(
        "package-wheel-contents",
        ".github/workflows/ci.yml",
        "package",
        "package_wheel_contents",
        required=True,
        timeout_s=300,
    ),
    special_gate(
        "wheel-install-smoke",
        ".github/workflows/ci.yml",
        "package",
        "wheel_install_smoke",
        required=True,
        timeout_s=600,
    ),
    # -- Drift observatory (observatory.yml, push-gated smoke) ------------
    subprocess_gate(
        "observatory-tests",
        ".github/workflows/observatory.yml",
        "machinery-smoke",
        [
            "{python}",
            "-m",
            "pytest",
            "tests/test_probe_runs.py",
            "tests/test_probe_runs_e2e.py",
            "tests/test_u3_trustmap.py",
            "tests/test_cli_drift_u3.py",
            "tests/test_validation.py",
            "tests/test_validation_trustmap.py",
            "-q",
        ],
        PYTEST_WORK,
        required=True,
        timeout_s=900,
    ),
    subprocess_gate(
        "drift-status-smoke",
        ".github/workflows/observatory.yml",
        "machinery-smoke",
        [
            "{python}",
            "-m",
            "textforensics.cli",
            "drift",
            "status",
            "--detector-id",
            "textforensics/builtin-heuristic",
            "--runs-dir",
            "{workdir}/empty-probe-runs",
        ],
        {"type": "fixed", "value": 1},
        required=True,
        timeout_s=300,
    ),
    static_gate(
        "observatory-probe-run",
        ".github/workflows/observatory.yml",
        "scheduled-probe-run",
        "unavailable",
        "scheduled probe runs execute on the corpus host where the frozen "
        "corpus cache lives; local verification does not access user caches",
        required=False,
    ),
    # -- Fuzz (fuzz.yml) ---------------------------------------------------
    subprocess_gate(
        "fuzz-regression",
        ".github/workflows/fuzz.yml",
        "fuzz-regression",
        ["{python}", "-m", "pytest", "tests/fuzz/test_fuzz_pytest.py", "-v", "--tb=short"],
        PYTEST_WORK,
        required=True,
        timeout_s=900,
    ),
    static_gate(
        "fuzz-direct-atheris",
        ".github/workflows/fuzz.yml",
        "fuzz-regression",
        "unavailable",
        "atheris is not installed in the canonical venv, so the "
        "direct-atheris step cannot run locally; the pytest-mode fuzz "
        "regression is covered by the fuzz-regression gate",
        required=False,
    ),
    static_gate(
        "fuzz-weekly",
        ".github/workflows/fuzz.yml",
        "fuzz-weekly",
        "not_applicable",
        "schedule/dispatch-only extended campaign (10 min x 9 targets); "
        "out of scope for a local candidate check",
        required=False,
    ),
    static_gate(
        "fuzz-summary",
        ".github/workflows/fuzz.yml",
        "fuzz-summary",
        "not_applicable",
        "aggregation-only job; no independent check",
        required=False,
    ),
    # -- Mutation (mutation.yml) -------------------------------------------
    special_gate(
        "mutation-diff",
        ".github/workflows/mutation.yml",
        "mutation-diff",
        "mutation_diff",
        required=True,
        timeout_s=300,
    ),
    static_gate(
        "mutation-full",
        ".github/workflows/mutation.yml",
        "mutation-full",
        "unavailable",
        "scheduled full campaign (hours); verify_release does not launch "
        "mutation campaigns and no completed run artifact exists for "
        "this HEAD",
        required=False,
    ),
    static_gate(
        "mutation-report",
        ".github/workflows/mutation.yml",
        "mutation-report",
        "not_applicable",
        "aggregation-only job; no independent check",
        required=False,
    ),
    # -- Workflow lint / static analysis / containers (push-gated) --------
    static_gate(
        "workflow-lint",
        ".github/workflows/workflow-lint.yml",
        "actionlint",
        "unavailable",
        "requires the actionlint binary; actionlint is not installed in "
        "the canonical venv (the workflow runs `actionlint -color "
        "-shellcheck='')`",
        required=True,
    ),
    static_gate(
        "codeql",
        ".github/workflows/codeql.yml",
        "analyze",
        "unavailable",
        "requires the GitHub CodeQL action and security-events API; no "
        "local equivalent is installed",
        required=True,
    ),
    static_gate(
        "container",
        ".github/workflows/container.yml",
        "build-and-push",
        "unavailable",
        "requires building and pushing a multi-arch image to ghcr.io; "
        "local verification must not push images",
        required=True,
    ),
    static_gate(
        "sigstore-verification",
        ".github/workflows/repository-integrity.yml",
        "sigstore",
        "unavailable",
        "the CI job now performs real cosign/attestation verification "
        "(ENG-07 fixed in W0), but no signed release artifacts exist "
        "for this HEAD to verify",
        required=True,
    ),
    static_gate(
        "repo-provenance-sbom",
        ".github/workflows/repository-integrity.yml",
        "provenance",
        "unavailable",
        "requires anchore/sbom-action (Syft); the checked-in SBOM "
        "freshness is covered by the sbom-check gate",
        required=True,
    ),
    # -- Reproducibility (reproducibility.yml, push-gated) ----------------
    special_gate(
        "wheel-reproducibility",
        ".github/workflows/reproducibility.yml",
        "build-reproducibility",
        "wheel_reproducibility",
        required=True,
        timeout_s=900,
    ),
    special_gate(
        "cli-determinism",
        ".github/workflows/reproducibility.yml",
        "cli-determinism",
        "cli_determinism",
        required=True,
        timeout_s=600,
    ),
    special_gate(
        "case-file-determinism",
        ".github/workflows/reproducibility.yml",
        "case-file-determinism",
        "case_file_determinism",
        required=True,
        timeout_s=600,
    ),
    special_gate(
        "detector-determinism",
        ".github/workflows/reproducibility.yml",
        "detector-determinism",
        "detector_determinism",
        required=True,
        timeout_s=600,
    ),
    # -- Benchmark (benchmark.yml, schedule/dispatch-only) -----------------
    subprocess_gate(
        "benchmark-script",
        ".github/workflows/benchmark.yml",
        "benchmark",
        [
            "{python}",
            "scripts/benchmark.py",
            "--iterations",
            "5",
            "--output",
            "{workdir}/benchmark-results.json",
        ],
        {"type": "json_key_count", "file": "{workdir}/benchmark-results.json", "key": "benchmarks"},
        required=False,
        timeout_s=600,
        artifacts=["{workdir}/benchmark-results.json"],
    ),
    subprocess_gate(
        "pytest-performance",
        ".github/workflows/benchmark.yml",
        "benchmark",
        [
            "{python}",
            "-m",
            "pytest",
            "tests/test_performance.py",
            "--benchmark-only",
            "--benchmark-min-rounds=5",
            "--benchmark-json={workdir}/pytest-performance.json",
        ],
        PYTEST_WORK,
        required=False,
        timeout_s=900,
    ),
    subprocess_gate(
        "pytest-benchmarks",
        ".github/workflows/benchmark.yml",
        "benchmark",
        [
            "{python}",
            "-m",
            "pytest",
            "tests/test_benchmarks.py",
            "--benchmark-only",
            "--benchmark-json={workdir}/pytest-benchmark.json",
        ],
        PYTEST_WORK,
        required=False,
        timeout_s=900,
    ),
    special_gate(
        "benchmark-compare",
        ".github/workflows/benchmark.yml",
        "benchmark",
        "benchmark_compare",
        required=False,
        timeout_s=900,
    ),
    # -- Enterprise deep verification (schedule/dispatch-only) -------------
    static_gate(
        "ent-deep-suite",
        ".github/workflows/enterprise-deep-verification.yml",
        "test-suite-all-features",
        "unavailable",
        "the CI job is schedule/dispatch-only and no longer uses "
        "--forked (removed in W0, ENG-07); the same suite without "
        "--forked is covered by the pytest-core gate",
        required=False,
    ),
    static_gate(
        "ent-deep-coverage",
        ".github/workflows/enterprise-deep-verification.yml",
        "coverage-verification",
        "unavailable",
        "the CI job is schedule/dispatch-only and no longer uses "
        "--forked (removed in W0, ENG-07); core coverage is covered "
        "by the coverage gate",
        required=False,
    ),
    static_gate(
        "ent-deep-docs",
        ".github/workflows/enterprise-deep-verification.yml",
        "documentation-verification",
        "unavailable",
        "requires sphinx and the `markdown` package, neither installed "
        "in the canonical venv",
        required=False,
    ),
    static_gate(
        "ent-deep-vuln-audit",
        ".github/workflows/enterprise-deep-verification.yml",
        "vulnerability-audit",
        "unavailable",
        "requires an isolated audit venv built from "
        ".[dev,api,mcp,security] with network installs; pip-audit "
        "coverage is provided by the pip-audit gate and bandit by the "
        "bandit gate",
        required=False,
    ),
    subprocess_gate(
        "ent-deep-schema",
        ".github/workflows/enterprise-deep-verification.yml",
        "schema-validation",
        ["{python}", "-c", ENT_DEEP_SCHEMA_PROGRAM],
        {"type": "line_count", "pattern": r"^OK: "},
        required=False,
        timeout_s=300,
    ),
    static_gate(
        "ent-deep-provenance",
        ".github/workflows/enterprise-deep-verification.yml",
        "release-provenance",
        "unavailable",
        "requires anchore/sbom-action (Syft) for the release SBOM; "
        "build/twine/wheel-content checks are covered by the "
        "package-build, package-twine and package-wheel-contents gates",
        required=False,
    ),
    # -- Advisory / PR-only / publication (never executed locally) ---------
    static_gate(
        "scorecard",
        ".github/workflows/scorecard.yml",
        "scorecard",
        "unavailable",
        "requires the OpenSSF Scorecard GitHub Action and SARIF upload; advisory only",
        required=False,
    ),
    static_gate(
        "dependency-review",
        ".github/workflows/dependency-review.yml",
        "dependency-review",
        "not_applicable",
        "PR-only check; a local candidate verification has no pull request",
        required=False,
    ),
    static_gate(
        "download-prefix-probe",
        ".github/workflows/download-prefix-probe.yml",
        "prefix-probe",
        "unavailable",
        "requires network access to probe download prefixes; local "
        "verification does not use the network",
        required=False,
    ),
    static_gate(
        "download-full",
        ".github/workflows/download-prefix-probe.yml",
        "full-download",
        "not_applicable",
        "dispatch-only full dataset download; out of scope for a local candidate check",
        required=False,
    ),
    static_gate(
        "release-dispatch",
        ".github/workflows/release.yml",
        "release",
        "not_applicable",
        "manual publication workflow; verify_release is the "
        "pre-promotion gate and must never dispatch a release",
        required=False,
    ),
]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(gate_defs, ctx, selected=None):
    """Run the gates (or short-circuit on stale SHA / dirty tree) and
    compute (records, verdict, exit_code)."""
    if ctx["stale_sha"]:
        records = [
            make_record(
                gate,
                "not_applicable",
                0,
                None,
                0.0,
                "stale candidate SHA; gates not executed",
            )
            for gate in gate_defs
        ]
    elif ctx["dirty"]:
        records = [
            make_record(
                gate,
                "not_applicable",
                0,
                None,
                0.0,
                "working tree dirty; candidate not verifiable",
            )
            for gate in gate_defs
        ]
    else:
        records = []
        for gate in gate_defs:
            if selected is not None and gate["name"] not in selected:
                records.append(make_record(gate, "skipped", 0, None, 0.0, "not selected by --gate"))
            else:
                records.append(run_gate(gate, ctx))
    required_records = [
        record for record, gate in zip(records, gate_defs, strict=True) if gate["required"]
    ]
    if (
        ctx["stale_sha"]
        or ctx["dirty"]
        or any(record["status"] in INCOMPLETE_STATUSES for record in required_records)
    ):
        return records, "incomplete", 2
    if any(record["status"] == "fail" for record in required_records):
        return records, "fail", 1
    return records, "pass", 0


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_summary(report):
    """Human-readable summary to stdout, always."""
    print(f"verify-release {report['version']}  head {report['head_sha']}")
    candidate = report["candidate_sha"] or "none"
    print(f"candidate: {candidate}  dirty: {report['dirty']}  stale_sha: {report['stale_sha']}")
    if report["stale_sha"]:
        print("stale candidate SHA: gates were not executed")
    elif report["dirty"]:
        print("dirty working tree: gates were not executed")
    name_width = max((len(g["name"]) for g in report["gates"]), default=4)
    for gate in report["gates"]:
        print(
            f"{gate['name']:<{name_width}}  {gate['status']:<15} "
            f"work={gate['executed_work']}  {gate['duration_s']:.2f}s"
        )
    print(f"verdict: {report['verdict']} (exit {report['exit_code']})")
    print(f"work dir: {report['work_dir']}")


def main(argv=None, gate_defs=None):
    """Entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(
        prog="verify_release.py",
        description=(
            "Canonical local verification command for TextForensics: "
            "mirrors the complete CI surface as local gates."
        ),
    )
    parser.add_argument(
        "--json", dest="json_path", default=None, help="write the full machine-readable report here"
    )
    parser.add_argument(
        "--gate",
        dest="gates",
        action="append",
        default=None,
        help="run only the named gate(s); may repeat",
    )
    parser.add_argument(
        "--candidate-sha", default=None, help="expected HEAD SHA; a mismatch is stale (exit 2)"
    )
    args = parser.parse_args(argv)
    defs = GATE_DEFS if gate_defs is None else list(gate_defs)
    if args.gates:
        known = {gate["name"] for gate in defs}
        unknown = [name for name in args.gates if name not in known]
        if unknown:
            print(f"error: unknown gate(s): {', '.join(unknown)}", file=sys.stderr)
            print(f"known gates: {', '.join(sorted(known))}", file=sys.stderr)
            return 2
    repo_root = _git(["rev-parse", "--show-toplevel"], os.getcwd())
    if repo_root is None:
        print("error: not inside a git repository", file=sys.stderr)
        return 2
    work_dir = Path(tempfile.mkdtemp(prefix="verify-release-"))
    started = datetime.now(UTC)
    started_mono = time.monotonic()
    ctx = build_context(repo_root, work_dir, candidate_sha=args.candidate_sha)
    records, verdict, exit_code = evaluate(
        defs, ctx, selected=set(args.gates) if args.gates else None
    )
    finished = datetime.now(UTC)
    report = {
        "command": " ".join(shlex.quote(arg) for arg in sys.argv),
        "version": VERSION,
        "candidate_sha": args.candidate_sha,
        "head_sha": ctx["head_sha"],
        "dirty": ctx["dirty"],
        "stale_sha": ctx["stale_sha"],
        "interpreter": {
            "executable": sys.executable,
            "version": sys.version,
        },
        "os": platform.platform(),
        "repo_root": str(ctx["repo_root"]),
        "work_dir": str(work_dir),
        "started": started.isoformat(),
        "finished": finished.isoformat(),
        "duration_s": round(time.monotonic() - started_mono, 3),
        "gates": records,
        "verdict": verdict,
        "exit_code": exit_code,
    }
    print_summary(report)
    if args.json_path:
        try:
            Path(args.json_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write --json report: {exc}", file=sys.stderr)
            return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
