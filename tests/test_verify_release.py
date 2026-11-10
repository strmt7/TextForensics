"""Tests for scripts/verify_release.py (W0 canonical verification command).

RED-first tests: each test states the contract behaviour from the frozen
W0 brief before the implementation exists. Synthetic gates use tiny Python
one-liners; the full suite is never run inside these unit tests.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import chdir
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_release", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vr = load_module()


def clean_ctx():
    """A context for the real repo forced clean: synthetic-gate tests must
    not depend on the developer worktree's dirty state."""
    return vr.build_context(
        REPO_ROOT,
        work_dir=Path(tempfile.mkdtemp()),
        head_sha="0" * 40,
        dirty=False,
    )


PASS_GATE = vr.subprocess_gate(
    name="synthetic-pass",
    ci_workflow="test",
    ci_job="synthetic",
    argv=[sys.executable, "-c", "print('WORK 3')"],
    work={"type": "regex_sum", "patterns": [r"WORK (\d+)"]},
    required=True,
)


def git(*args, cwd):
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def make_repo(path: Path, dirty: bool = False) -> None:
    path.mkdir(parents=True, exist_ok=True)
    git("init", "-q", cwd=path)
    (path / "README.md").write_text("test repo\n", encoding="utf-8")
    git("add", "README.md", cwd=path)
    git(
        "-c",
        "user.name=Test User",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-q",
        "-m",
        "initial",
        cwd=path,
    )
    if dirty:
        (path / "README.md").write_text("test repo\nmodified\n", encoding="utf-8")


class TestVerifyReleaseContract(unittest.TestCase):
    """Contract tests for the frozen W0 verification-command behaviour."""

    def test_passing_gate_exit_0(self):
        """A synthetic passing gate yields exit 0 with executed_work > 0."""
        ctx = clean_ctx()
        records, verdict, exit_code = vr.evaluate([PASS_GATE], ctx)
        self.assertEqual(exit_code, 0)
        self.assertEqual(verdict, "pass")
        self.assertEqual(records[0]["status"], "pass")
        self.assertGreater(records[0]["executed_work"], 0)
        self.assertEqual(records[0]["executed_work"], 3)

    def test_failing_gate_exit_1(self):
        """A synthetic failing gate yields exit 1."""
        gate = vr.subprocess_gate(
            name="synthetic-fail",
            ci_workflow="test",
            ci_job="synthetic",
            argv=[sys.executable, "-c", "import sys; sys.exit(1)"],
            work={"type": "fixed", "value": 1},
            required=True,
        )
        ctx = clean_ctx()
        records, verdict, exit_code = vr.evaluate([gate], ctx)
        self.assertEqual(exit_code, 1)
        self.assertEqual(verdict, "fail")
        self.assertEqual(records[0]["status"], "fail")

    def test_skipped_gate_exit_2(self):
        """A synthetic gate reporting skipped yields exit 2."""
        ctx = clean_ctx()
        records, verdict, exit_code = vr.evaluate([PASS_GATE], ctx, selected={"some-other-gate"})
        self.assertEqual(exit_code, 2)
        self.assertEqual(verdict, "incomplete")
        self.assertEqual(records[0]["status"], "skipped")

    def test_zero_work_gate_exit_2(self):
        """A synthetic gate executing zero work yields exit 2, status zero_work."""
        gate = vr.subprocess_gate(
            name="synthetic-zero",
            ci_workflow="test",
            ci_job="synthetic",
            argv=[sys.executable, "-c", "print('WORK 0')"],
            work={"type": "regex_sum", "patterns": [r"WORK (\d+)"]},
            required=True,
        )
        ctx = clean_ctx()
        records, verdict, exit_code = vr.evaluate([gate], ctx)
        self.assertEqual(exit_code, 2)
        self.assertEqual(verdict, "incomplete")
        self.assertEqual(records[0]["status"], "zero_work")
        self.assertEqual(records[0]["executed_work"], 0)

    def test_child_exit_2_is_gate_fail(self):
        """A synthetic child exit 2 yields gate fail (not pass)."""
        gate = vr.subprocess_gate(
            name="synthetic-exit2",
            ci_workflow="test",
            ci_job="synthetic",
            argv=[sys.executable, "-c", "import sys; sys.exit(2)"],
            work={"type": "fixed", "value": 1},
            required=True,
        )
        ctx = clean_ctx()
        records, verdict, exit_code = vr.evaluate([gate], ctx)
        self.assertEqual(records[0]["status"], "fail")
        self.assertIn("child exit 2", records[0]["detail"])
        self.assertEqual(exit_code, 1)
        self.assertEqual(verdict, "fail")

    def test_stale_candidate_sha_exit_2_without_executing_gates(self):
        """A stale --candidate-sha yields exit 2 without executing gates."""
        marker_gate = vr.subprocess_gate(
            name="synthetic-marker",
            ci_workflow="test",
            ci_job="synthetic",
            argv=[
                sys.executable,
                "-c",
                "import pathlib; pathlib.Path(r'MARKER').write_text('ran')",
            ],
            work={"type": "fixed", "value": 1},
            required=True,
        )
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            make_repo(repo)
            json_path = Path(tmp) / "report.json"
            with chdir(repo):
                exit_code = vr.main(
                    [
                        "--json",
                        str(json_path),
                        "--candidate-sha",
                        "0" * 40,
                    ],
                    gate_defs=[marker_gate],
                )
            self.assertEqual(exit_code, 2)
            self.assertFalse((repo / "MARKER").exists())
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertTrue(report["stale_sha"])
            self.assertEqual(report["verdict"], "incomplete")
            self.assertEqual(report["exit_code"], 2)
            self.assertEqual([g["status"] for g in report["gates"]], ["not_applicable"])

    def test_dirty_working_tree_exit_2(self):
        """A dirty working tree yields exit 2 (disposable git repo fixture)."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            make_repo(repo, dirty=True)
            json_path = Path(tmp) / "report.json"
            with chdir(repo):
                exit_code = vr.main(
                    ["--json", str(json_path)],
                    gate_defs=[PASS_GATE],
                )
            self.assertEqual(exit_code, 2)
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertTrue(report["dirty"])
            self.assertEqual(report["verdict"], "incomplete")
            self.assertEqual([g["status"] for g in report["gates"]], ["not_applicable"])

    def test_missing_tool_unavailable_exit_2(self):
        """A missing tool yields unavailable + exit 2."""
        gate = vr.subprocess_gate(
            name="synthetic-missing-tool",
            ci_workflow="test",
            ci_job="synthetic",
            argv=[sys.executable, "-c", "print('WORK 1')"],
            work={"type": "fixed", "value": 1},
            required=True,
            missing={"kind": "binary", "name": "definitely-not-a-real-tool-xyz"},
        )
        ctx = clean_ctx()
        records, verdict, exit_code = vr.evaluate([gate], ctx)
        self.assertEqual(exit_code, 2)
        self.assertEqual(verdict, "incomplete")
        self.assertEqual(records[0]["status"], "unavailable")
        self.assertIn("definitely-not-a-real-tool-xyz", records[0]["detail"])

    def test_json_report_shape(self):
        """--json writes valid JSON with all required top-level fields and
        only the six-status vocabulary."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            make_repo(repo)
            json_path = Path(tmp) / "report.json"
            with chdir(repo):
                exit_code = vr.main(
                    ["--json", str(json_path)],
                    gate_defs=[PASS_GATE],
                )
            self.assertEqual(exit_code, 0)
            report = json.loads(json_path.read_text(encoding="utf-8"))
            for field in (
                "command",
                "version",
                "candidate_sha",
                "head_sha",
                "dirty",
                "interpreter",
                "os",
                "started",
                "finished",
                "gates",
                "verdict",
                "exit_code",
            ):
                self.assertIn(field, report)
            self.assertEqual(report["version"], vr.VERSION)
            self.assertFalse(report["dirty"])
            self.assertEqual(report["verdict"], "pass")
            self.assertEqual(report["exit_code"], 0)
            for gate in report["gates"]:
                self.assertIn(gate["status"], vr.STATUSES)
                self.assertIn("executed_work", gate)
                self.assertIn("command", gate)
                self.assertIn("duration_s", gate)
                self.assertIn("detail", gate)
                self.assertIn("required", gate)

    def test_real_subprocess_gate_positive_work(self):
        """A real subprocess gate records executed_work > 0 and pass."""
        gate = vr.subprocess_gate(
            name="synthetic-real-subprocess",
            ci_workflow="test",
            ci_job="synthetic",
            argv=[sys.executable, "-c", "print('WORK 7')"],
            work={"type": "regex_sum", "patterns": [r"WORK (\d+)"]},
            required=True,
        )
        ctx = clean_ctx()
        records, _verdict, exit_code = vr.evaluate([gate], ctx)
        self.assertEqual(exit_code, 0)
        self.assertEqual(records[0]["status"], "pass")
        self.assertEqual(records[0]["executed_work"], 7)
        # The real ruff --version, when the tool is resolvable, is a second
        # real subprocess gate with positive work.
        ruff = shutil.which("ruff") or str(Path(sys.executable).parent / "ruff")
        if not Path(ruff).exists():
            self.skipTest("ruff binary not available in this environment")
        ruff_gate = vr.subprocess_gate(
            name="synthetic-ruff-version",
            ci_workflow="test",
            ci_job="synthetic",
            argv=[ruff, "--version"],
            work={"type": "fixed", "value": 1},
            required=True,
        )
        records, _verdict, exit_code = vr.evaluate([ruff_gate], ctx)
        self.assertEqual(exit_code, 0)
        self.assertEqual(records[0]["status"], "pass")
        self.assertGreater(records[0]["executed_work"], 0)

    def test_mutation_diff_without_artifact_is_unavailable(self):
        """The mutation-diff special gate is unavailable when no run
        artifact exists for the HEAD (it never launches a campaign)."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            make_repo(repo)
            defs = [g for g in vr.GATE_DEFS if g["name"] == "mutation-diff"]
            self.assertEqual(len(defs), 1)
            ctx = vr.build_context(repo, work_dir=Path(tempfile.mkdtemp()))
            records, verdict, exit_code = vr.evaluate(defs, ctx)
            self.assertEqual(records[0]["status"], "unavailable")
            self.assertEqual(exit_code, 2)
            self.assertEqual(verdict, "incomplete")

    def test_gate_defs_well_formed(self):
        """Every shipped gate def is well-formed and uses only the frozen
        status vocabulary; names are unique."""
        names = [g["name"] for g in vr.GATE_DEFS]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreater(len(names), 20)
        for gate in vr.GATE_DEFS:
            self.assertIn("ci_workflow", gate)
            self.assertIn("ci_job", gate)
            self.assertIsInstance(gate["required"], bool)
            self.assertIn(gate["kind"], ("subprocess", "unavailable", "not_applicable", "special"))
            if gate["kind"] in ("unavailable", "not_applicable"):
                self.assertTrue(gate.get("reason"), gate["name"])
            if gate["kind"] == "subprocess":
                self.assertTrue(gate.get("argv"), gate["name"])
            if gate["kind"] == "special":
                self.assertTrue(gate.get("special"), gate["name"])
        self.assertEqual(
            set(vr.STATUSES),
            {"pass", "fail", "skipped", "unavailable", "not_applicable", "zero_work"},
        )

    def test_child_env_prepends_venv_bin(self):
        """Children see the canonical venv's binaries: pre-commit hooks
        invoke bare `python` and tests invoke bare `textforensics`."""
        ctx = clean_ctx()
        venv_bin = str(Path(sys.executable).parent)
        first_entry = ctx["env"]["PATH"].split(os.pathsep)[0]
        self.assertEqual(first_entry, venv_bin)

    def test_bare_python_resolves_for_children(self):
        """A synthetic gate invoking bare `python` passes: without the
        venv bin dir on the child PATH it fails with FileNotFoundError
        (the pre-commit / schema-CLI failure mode)."""
        gate = vr.subprocess_gate(
            name="synthetic-bare-python",
            ci_workflow="test",
            ci_job="synthetic",
            argv=["python", "-c", "print('WORK 1')"],
            work={"type": "regex_sum", "patterns": [r"WORK (\d+)"]},
            required=True,
        )
        ctx = clean_ctx()
        records, _verdict, exit_code = vr.evaluate([gate], ctx)
        self.assertEqual(exit_code, 0)
        self.assertEqual(records[0]["status"], "pass")
        self.assertEqual(records[0]["executed_work"], 1)

    def test_unknown_gate_name_is_usage_error(self):
        """An unknown --gate name is rejected instead of silently ignored."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            make_repo(repo)
            with chdir(repo):
                exit_code = vr.main(["--gate", "no-such-gate"], gate_defs=[PASS_GATE])
            self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
