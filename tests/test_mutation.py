#!/usr/bin/env python3
"""
Integration tests for Cosmic Ray mutation testing setup (8.x).

These tests verify that:
1. Cosmic Ray 8.x is properly installed and configured
2. The TOML configuration file is valid and loadable by cosmic-ray itself
3. The mutation runner script works correctly
4. Mutation testing can execute without errors
5. The workflow and the runner agree on the target module list, and the
   no-op case (no relevant module changed) passes instead of failing
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


def _load_runner(runner_path: Path):
    """Load scripts/run_mutation.py as a module (scripts/ is not a package)."""
    spec = importlib.util.spec_from_file_location("run_mutation", runner_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CosmicRayIntegrationTests(unittest.TestCase):
    """Test Cosmic Ray mutation testing integration."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        cls.project_root = Path(__file__).parent.parent
        cls.config_path = cls.project_root / ".cosmic-ray.toml"
        cls.runner_path = cls.project_root / "scripts" / "run_mutation.py"
        cls.runner = _load_runner(cls.runner_path)

    def test_cosmic_ray_installed(self):
        """Verify cosmic-ray 8.x is installed and accessible."""
        # Prefer the module invocation (works even when the venv bin dir is
        # not on PATH); fall back to the console script as CI installs it.
        for cmd in (
            [sys.executable, "-m", "cosmic_ray.cli", "--version"],
            ["cosmic-ray", "--version"],
        ):
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.assertIn("8.", result.stdout, f"Expected cosmic-ray 8.x, got: {result.stdout}")
                return
        self.fail("cosmic-ray not installed: neither module nor console script works")

    def test_config_file_exists(self):
        """Verify .cosmic-ray.toml configuration exists and the YAML one is gone."""
        self.assertTrue(self.config_path.exists(), "Configuration file not found")
        self.assertFalse(
            (self.project_root / ".cosmic-ray.yml").exists(),
            "Stale .cosmic-ray.yml must be removed: cosmic-ray 8.x is TOML-only",
        )

    def test_config_file_valid_toml(self):
        """Verify configuration file is valid TOML with the 8.x keys."""
        with open(self.config_path, "rb") as f:
            config = tomllib.load(f)

        self.assertIn("cosmic-ray", config)
        cosmic_ray = config["cosmic-ray"]

        # 8.x keys (not the 7.x `mutation` / `test_runner` sections).
        self.assertIn("module-path", cosmic_ray)
        self.assertIn("excluded-modules", cosmic_ray)
        self.assertIn("test-command", cosmic_ray)
        self.assertIn("timeout", cosmic_ray)
        self.assertIn("distributor", cosmic_ray)
        self.assertNotIn("mutation", config)
        self.assertNotIn("test_runner", config)

        # Check target modules are present (as filesystem paths).
        module_paths = cosmic_ray["module-path"]
        expected_paths = [
            "src/textforensics/benchmark.py",
            "src/textforensics/trust.py",
            "src/textforensics/consensus.py",
            "src/textforensics/calibration.py",
        ]
        for path in expected_paths:
            self.assertIn(path, module_paths, f"Expected module path {path} not in config")
        for path in module_paths:
            self.assertTrue(
                (self.project_root / path).is_file(), f"Configured module path missing: {path}"
            )

        # Check excluded modules
        self.assertIn("textforensics.cli", cosmic_ray["excluded-modules"])

        # Check distributor and timeout
        self.assertEqual(cosmic_ray["distributor"]["name"], "local")
        self.assertEqual(cosmic_ray["timeout"], 30)

    def test_config_loadable_by_cosmic_ray(self):
        """Verify cosmic-ray 8.x itself can parse the checked-in config."""
        from cosmic_ray.config import load_config

        config = load_config(str(self.config_path))
        self.assertEqual(config.distributor_name, "local")
        self.assertEqual(config.timeout, 30.0)
        self.assertIn("src/textforensics/trust.py", config["module-path"])

    def test_runner_generated_config_loadable(self):
        """Verify the runner's generated per-run TOML loads in cosmic-ray."""
        from cosmic_ray.config import deserialize_config

        toml_text = self.runner.build_toml_config(
            ["textforensics.trust"], self.project_root, timeout=10
        )
        config = deserialize_config(toml_text)
        self.assertEqual(
            config["module-path"], [str(self.project_root / "src/textforensics/trust.py")]
        )
        self.assertIn("tests/test_trust.py", config["test-command"])
        self.assertEqual(config.distributor_name, "local")

    def test_test_command_scoping(self):
        """Verify the per-mutant test command is scoped to the module's tests."""
        scoped = self.runner.test_command_for(["textforensics.trust"], self.project_root)
        self.assertEqual(
            scoped,
            "python -m pytest tests/test_trust.py tests/test_w1_worker_d.py "
            "tests/test_audit_w2_worker_a.py -x -q",
        )
        # Policy tests live in test_enterprise_policy.py, not test_policy.py;
        # the override map scopes them instead of falling back to the full
        # suite (whose ~3-minute runtime exceeds the per-test-run timeout
        # and fails the cosmic-ray baseline before any mutant runs).
        policy = self.runner.test_command_for(["textforensics.policy"], self.project_root)
        self.assertEqual(
            policy,
            "python -m pytest tests/test_enterprise_policy.py "
            "tests/test_execution_policy.py tests/test_audit_w2_worker_a.py -x -q",
        )
        # W2 worker test files are part of the per-mutant command for the
        # modules they cover (audit-w2-f §10 follow-up).
        casefile = self.runner.test_command_for(["textforensics.casefile"], self.project_root)
        self.assertEqual(
            casefile,
            "python -m pytest tests/test_casefile.py tests/test_w1_worker_d.py "
            "tests/test_casefile_v3.py -x -q",
        )
        probe_runs = self.runner.test_command_for(["textforensics.probe_runs"], self.project_root)
        self.assertEqual(
            probe_runs,
            "python -m pytest tests/test_probe_runs.py tests/test_w2_worker_d.py -x -q",
        )
        verify = self.runner.test_command_for(["textforensics.verify"], self.project_root)
        self.assertEqual(
            verify,
            "python -m pytest tests/test_verify.py tests/test_casefile_v3.py -x -q",
        )
        adversarial = self.runner.test_command_for(["textforensics.adversarial"], self.project_root)
        self.assertEqual(
            adversarial,
            "python -m pytest tests/test_adversarial.py tests/test_w2_worker_e_if12.py -x -q",
        )
        # Observatory is deliberately NOT in _MODULE_TEST_FILES: eight
        # test files import it, so a bare override would narrow coverage;
        # it still falls back to the full suite.
        observatory = self.runner.test_command_for(["textforensics.observatory"], self.project_root)
        self.assertEqual(observatory, "python -m pytest tests/ -x -q --tb=short")
        # A module without a dedicated test file still falls back to the
        # full suite.
        full = self.runner.test_command_for(["textforensics.nonexistent"], self.project_root)
        self.assertEqual(full, "python -m pytest tests/ -x -q --tb=short")

    def test_runner_script_exists(self):
        """Verify mutation runner script exists."""
        self.assertTrue(self.runner_path.exists(), "Runner script not found")
        # On Windows, executable bit check doesn't apply the same way
        # On CI, the file may not have executable bit set due to git checkout
        if sys.platform != "win32":
            is_executable = bool(self.runner_path.stat().st_mode & 0o111)
            if not is_executable:
                # In CI environments, the executable bit may not be preserved
                # Skip this check but log a message instead of warning
                import logging

                logging.getLogger(__name__).info(
                    "Runner script missing executable bit (CI environment)"
                )
            # We don't fail the test if executable bit is missing in CI
            # but we verify the file exists and is readable
            self.assertTrue(self.runner_path.is_file(), "Runner script should be a file")

    def test_runner_help(self):
        """Verify runner script shows help."""
        result = subprocess.run(
            [sys.executable, str(self.runner_path), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("mutation", result.stdout.lower())
        self.assertIn("diff", result.stdout)
        self.assertIn("full", result.stdout)
        self.assertIn("safety-critical", result.stdout)
        self.assertIn("budget", result.stdout)

    def test_runner_check_results(self):
        """Verify runner can check results."""
        # Create a temporary summary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {"total": 10, "killed": 10, "surviving": 0, "timeout": 0, "error": 0, "skipped": 0},
                f,
            )
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(self.runner_path), "--check-results", temp_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"Check results failed: {result.stderr}")
            self.assertIn("All mutations caught", result.stdout)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_runner_check_results_surviving(self):
        """Verify runner detects surviving mutants."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {"total": 10, "killed": 8, "surviving": 2, "timeout": 0, "error": 0, "skipped": 0},
                f,
            )
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(self.runner_path), "--check-results", temp_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2, "Should return 2 for surviving mutants")
            self.assertIn("surviving mutant", result.stdout.lower())
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_runner_check_results_budget_exceeded(self):
        """Verify runner detects budget exceeded (high timeout ratio)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "total": 100,
                    "killed": 50,
                    "surviving": 0,
                    "timeout": 20,  # 20% timeout ratio
                    "error": 0,
                    "skipped": 0,
                },
                f,
            )
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(self.runner_path), "--check-results", temp_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 3, "Should return 3 for budget exceeded")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_runner_check_results_no_op_passes(self):
        """Verify the legitimate no-op summary passes (defect 5 fix)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.runner._no_op_summary(), f)
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(self.runner_path), "--check-results", temp_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"No-op summary must pass: {result.stdout}")
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_runner_check_results_bare_zero_fails(self):
        """Verify a zero summary WITHOUT the marker still fails (not a vacuous pass)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {"total": 0, "killed": 0, "surviving": 0, "timeout": 0, "error": 0, "skipped": 0},
                f,
            )
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(self.runner_path), "--check-results", temp_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1, "Bare zero summary must fail")
            self.assertIn("No mutations were run", result.stdout)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_exec_timeout_for_budget_zero_has_no_cap(self):
        """A budget-0 (full) session has no wall-clock exec cap.

        The old hard 3600 s kill died mid-mutant on a ~20 h full session,
        left a mutant baked into the source, and produced no dump and no
        summary. Budget 0 must return None (no subprocess timeout).
        """
        self.assertIsNone(self.runner.exec_timeout_for(0, 30))
        self.assertIsNone(self.runner.exec_timeout_for(0, 30, None))

    def test_exec_timeout_for_budget_scales(self):
        """A budgeted run keeps the old scaled cap."""
        self.assertEqual(self.runner.exec_timeout_for(200, 30), 200 * 45)
        self.assertEqual(self.runner.exec_timeout_for(10, 10), 10 * 25)

    def test_exec_timeout_for_explicit_overrides(self):
        """An explicit --exec-timeout wins; 0 means no cap; negative fails."""
        self.assertEqual(self.runner.exec_timeout_for(0, 30, 120), 120)
        self.assertEqual(self.runner.exec_timeout_for(200, 30, 120), 120)
        self.assertIsNone(self.runner.exec_timeout_for(200, 30, 0))
        with self.assertRaises(ValueError):
            self.runner.exec_timeout_for(200, 30, -5)

    def test_check_results_partial_run_with_pending_fails(self):
        """A summary with pending work items must never pass.

        Even when every completed mutant was killed, unexecuted items are
        not kills: gating on the partial summary would be a vacuous pass.
        The operator must resume the session and gate on the finished run.
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "total": 10,
                    "killed": 10,
                    "surviving": 0,
                    "timeout": 0,
                    "error": 0,
                    "skipped": 0,
                    "pending": 5,
                },
                f,
            )
            temp_path = f.name

        try:
            result = subprocess.run(
                [sys.executable, str(self.runner_path), "--check-results", temp_path],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1, "Partial run must fail")
            self.assertIn("never executed", result.stdout)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_runner_help_documents_resume(self):
        """--help documents the resume procedure (fix/runner-timeout-resume)."""
        result = subprocess.run(
            [sys.executable, str(self.runner_path), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("--resume", result.stdout)
        self.assertIn("--exec-timeout", result.stdout)
        self.assertIn("git checkout", result.stdout)
        self.assertIn("index.lock", result.stdout)
        self.assertIn("no wall-clock cap", result.stdout.lower())

    def test_exec_session_timeout_dumps_partial_and_returns_error(self):
        """On exec timeout the partial session is dumped, not lost.

        The old path let subprocess.TimeoutExpired propagate as a
        traceback: no dump, no summary, exit by exception. The new path
        dumps the partial session (completed items kept, rest pending),
        appends an exec_timeout error record so the gate fails loudly,
        and returns exit 1.
        """
        from unittest import mock

        killed = {
            "work_item": {"job_id": "a", "mutations": []},
            "result": {"worker_outcome": "normal", "test_outcome": "killed"},
        }
        pending = {"work_item": {"job_id": "b", "mutations": []}, "result": None}
        # Dump JSONL is [work_item, work_result] pairs, not records.
        dump_stdout = (
            json.dumps([killed["work_item"], killed["result"]])
            + "\n"
            + json.dumps([pending["work_item"], None])
            + "\n"
        )

        def fake_run_command(cmd, cwd=None, timeout=None):
            if cmd[1] == "exec":
                raise subprocess.TimeoutExpired(cmd, timeout)
            if cmd[1] == "dump":
                return subprocess.CompletedProcess(cmd, 0, stdout=dump_stdout, stderr="")
            raise AssertionError(f"unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmpdir:
            dump_path = Path(tmpdir) / "sess.json"
            with mock.patch.object(self.runner, "run_command", side_effect=fake_run_command):
                exit_code, records = self.runner._exec_session(
                    Path("cfg.toml"),
                    Path("sess.sqlite"),
                    dump_path,
                    5,
                    "sess",
                    Path("mutation-results/sess.toml"),
                )
            self.assertEqual(exit_code, 1)
            self.assertTrue(dump_path.is_file(), "partial dump must be written")
            self.assertEqual(records[-1].get("error"), "exec_timeout")
            summary = self.runner.parse_results(records)
            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["killed"], 1)
            self.assertEqual(summary["pending"], 1)
            self.assertEqual(summary["error"], 1)

    def test_dirty_target_modules_parses_porcelain(self):
        """The resume dirty-source guard reads git porcelain correctly.

        A modified tracked module blocks the resume; untracked files and
        files outside src/textforensics/ do not.
        """
        from unittest import mock

        porcelain = (
            " M src/textforensics/trust.py\n"
            "?? src/textforensics/new.py\n"
            " M README.md\n"
            "D  src/textforensics/old.py\n"
        )
        fake = subprocess.CompletedProcess(["git", "status"], 0, stdout=porcelain, stderr="")
        with mock.patch.object(self.runner, "run_command", return_value=fake):
            dirty, error = self.runner._dirty_target_modules(self.project_root)
        self.assertIsNone(error)
        self.assertEqual(dirty, ["src/textforensics/trust.py", "src/textforensics/old.py"])

    def test_parse_dump_records(self):
        """Verify 8.x dump JSONL records parse into killed/survived/pending."""
        records = [
            {
                "work_item": {"job_id": "a", "mutations": []},
                "result": {
                    "worker_outcome": "normal",
                    "test_outcome": "killed",
                    "output": None,
                    "diff": None,
                },
            },
            {
                "work_item": {"job_id": "b", "mutations": []},
                "result": {
                    "worker_outcome": "normal",
                    "test_outcome": "survived",
                    "output": None,
                    "diff": None,
                },
            },
            {
                "work_item": {"job_id": "c", "mutations": []},
                "result": {
                    "worker_outcome": "normal",
                    "test_outcome": "incompetent",
                    "output": None,
                    "diff": None,
                },
            },
            {
                "work_item": {"job_id": "d", "mutations": []},
                "result": {
                    "worker_outcome": "exception",
                    "test_outcome": None,
                    "output": None,
                    "diff": None,
                },
            },
            {"work_item": {"job_id": "e", "mutations": []}, "result": None},
        ]
        summary = self.runner.parse_results(records)
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["killed"], 1)
        self.assertEqual(summary["surviving"], 1)
        self.assertEqual(summary["incompetent"], 1)
        self.assertEqual(summary["error"], 1)
        self.assertEqual(summary["pending"], 1)

    def test_diff_mode_no_changes(self):
        """Test diff mode when no relevant modules changed (exit 0 + marker)."""
        result = subprocess.run(
            [sys.executable, str(self.runner_path), "--mode", "diff", "--base-sha", "HEAD"],
            capture_output=True,
            text=True,
            cwd=self.project_root,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, f"Unexpected exit code: {result.returncode}")
        summary_path = self.project_root / "mutation-results" / "summary.json"
        self.assertTrue(summary_path.exists(), "Diff no-op must write a summary")
        with open(summary_path) as f:
            summary = json.load(f)
        self.assertEqual(summary.get("skipped_reason"), "no-relevant-changes")

    def test_baseline_tests_pass(self):
        """Verify baseline tests pass (required for mutation testing)."""
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_benchmark.py", "-x", "-q", "--tb=short"],
            capture_output=True,
            text=True,
            cwd=self.project_root,
            timeout=60,
        )
        self.assertEqual(
            result.returncode, 0, f"Baseline tests failed: {result.stdout}\n{result.stderr}"
        )

    def test_target_modules_importable(self):
        """Verify all target modules can be imported."""
        target_modules = [
            "textforensics.benchmark",
            "textforensics.trust",
            "textforensics.consensus",
            "textforensics.calibration",
            "textforensics.detectors",
            "textforensics.analyzers",
            "textforensics.engine",
            "textforensics.policy",
            "textforensics.casefile",
            "textforensics.execution_policy",
        ]

        # The subprocess resolves imports from this worktree's src/
        # (PYTHONPATH), not from whatever copy of the package the venv
        # happens to have installed: a fresh worktree's new modules
        # (e.g. execution_policy, added by W1) do not exist in the
        # installed copy yet, and the test must verify the code under
        # test, not the installed one.
        import os

        env = {**os.environ, "PYTHONPATH": str(self.project_root / "src")}
        for module in target_modules:
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-c", f"import {module}"],
                    capture_output=True,
                    text=True,
                    cwd=self.project_root,
                    env=env,
                )
                self.assertEqual(
                    result.returncode, 0, f"Failed to import {module}: {result.stderr}"
                )


class EquivalentBaselineTests(unittest.TestCase):
    """Tests for the equivalent-mutant baseline (mutation-baseline.toml).

    The baseline accepts only mutants verified equivalent (see the baseline
    file's header for the proof); the gate still fails on any unexplained
    survivor (exit 2) and on any stale entry (exit 1).
    """

    #: The 810 distinct start positions of the 4361 baseline entries,
    #: grouped by module. Re-derived from the resolved baseline (see
    #: hidden_files/audit-w2-f2-test-literals.json); the W1 refresh (956
    #: entries re-derived on audit-w1 head 0da6013) moved 137 of the
    #: 278 pre-W1 positions, and the W1 proof added 40 new ones
    #: (execution_policy is new; the rest are new annotation/runtime
    #: sites in the changed W1 functions). The W2 refresh (1425
    #: entries re-derived on audit-w2 head 739efc0) and the W2 proof
    #: (2179 appended) took the set to 669 positions over 25 modules;
    #: the F2 re-proof append (214 entries) took it to 810.
    EXPECTED_POSITIONS = {
        # textforensics._standalone_verify (33 positions).
        (133, 24),
        (133, 72),
        (137, 21),
        (137, 38),
        (140, 24),
        (141, 20),
        (141, 68),
        (145, 17),
        (145, 34),
        (147, 17),
        (177, 23),
        (199, 73),
        (1346, 30),
        (1365, 21),
        (1414, 13),
        (1420, 36),
        (1432, 35),
        (1434, 33),
        (1436, 34),
        (1437, 36),
        (1467, 46),
        (1468, 20),
        (1470, 74),
        (1470, 76),
        (1471, 52),
        (1484, 30),
        (1566, 22),
        (1667, 34),
        (1701, 30),
        (1860, 27),
        (1862, 29),
        (1864, 29),
        (1879, 86),
        # textforensics.adversarial (21 positions).
        (289, 47),
        (289, 74),
        (307, 11),
        (723, 8),
        (724, 41),
        (725, 33),
        (726, 22),
        (771, 27),
        (800, 26),
        (810, 26),
        (837, 26),
        (855, 65),
        (855, 67),
        (855, 74),
        (863, 24),
        (863, 27),
        (871, 4),
        (872, 37),
        (873, 74),
        (874, 29),
        (875, 18),
        # textforensics.analyzers (4 positions).
        (32, 13),
        (34, 13),
        (41, 13),
        (43, 13),
        # textforensics.benchmark (49 positions).
        (32, 29),
        (35, 46),
        (35, 51),
        (35, 53),
        (41, 14),
        (74, 58),
        (89, 34),
        (93, 18),
        (100, 32),
        (101, 32),
        (102, 32),
        (103, 40),
        (104, 38),
        (123, 14),
        (146, 14),
        (155, 54),
        (156, 51),
        (175, 36),
        (176, 41),
        (242, 14),
        (247, 42),
        (297, 35),
        (301, 35),
        (338, 40),
        (404, 23),
        (406, 23),
        (412, 24),
        (464, 4),
        (514, 34),
        (525, 23),
        (526, 25),
        (527, 4),
        (602, 19),
        (602, 38),
        (699, 18),
        (758, 30),
        (766, 30),
        (780, 14),
        (784, 28),
        (828, 14),
        (876, 44),
        (881, 15),
        (883, 15),
        (976, 11),
        (980, 11),
        (999, 31),
        (1010, 14),
        (1023, 26),
        (1025, 25),
        # textforensics.calibration (106 positions).
        (160, 13),
        (160, 16),
        (397, 32),
        (398, 24),
        (398, 62),
        (404, 23),
        (404, 64),
        (409, 32),
        (409, 59),
        (436, 27),
        (454, 25),
        (458, 25),
        (461, 47),
        (464, 17),
        (464, 30),
        (468, 25),
        (506, 23),
        (508, 43),
        (514, 23),
        (515, 36),
        (517, 69),
        (518, 27),
        (520, 27),
        (523, 23),
        (525, 23),
        (527, 23),
        (536, 17),
        (551, 31),
        (551, 56),
        (552, 31),
        (552, 56),
        (580, 18),
        (580, 52),
        (615, 20),
        (676, 54),
        (885, 54),
        (950, 15),
        (1058, 36),
        (1086, 36),
        (1122, 41),
        (1146, 62),
        (1161, 36),
        (1197, 28),
        (1198, 35),
        (1199, 46),
        (1200, 36),
        (1202, 38),
        (1203, 45),
        (1204, 40),
        (1205, 35),
        (1206, 26),
        (1207, 33),
        (1208, 24),
        (1209, 36),
        (1210, 22),
        (1211, 19),
        (1212, 25),
        (1213, 36),
        (1214, 20),
        (1292, 59),
        (1295, 79),
        (1307, 83),
        (1331, 37),
        (1383, 8),
        (1385, 15),
        (1404, 8),
        (1406, 27),
        (1424, 36),
        (1426, 15),
        (1453, 36),
        (1455, 27),
        (1476, 37),
        (1479, 17),
        (1479, 20),
        (1497, 83),
        (1501, 18),
        (1504, 53),
        (1506, 29),
        (1520, 17),
        (1521, 61),
        (1546, 49),
        (1550, 40),
        (1562, 71),
        (1734, 26),
        (1770, 54),
        (1771, 51),
        (1809, 39),
        (1810, 16),
        (1811, 43),
        (1812, 44),
        (1820, 65),
        (1820, 91),
        (1827, 19),
        (1830, 34),
        (1833, 42),
        (1905, 53),
        (1911, 35),
        (1916, 35),
        (1967, 26),
        (1968, 19),
        (2031, 20),
        (2036, 15),
        (2046, 38),
        (2080, 21),
        (2097, 26),
        (2098, 25),
        # textforensics.casefile (96 positions).
        (244, 41),
        (317, 4),
        (318, 24),
        (319, 15),
        (320, 16),
        (321, 14),
        (335, 43),
        (336, 4),
        (337, 24),
        (338, 27),
        (339, 32),
        (340, 30),
        (341, 33),
        (342, 47),
        (343, 59),
        (344, 62),
        (345, 40),
        (459, 55),
        (473, 4),
        (477, 14),
        (534, 4),
        (535, 30),
        (536, 21),
        (537, 28),
        (538, 27),
        (539, 25),
        (540, 23),
        (618, 58),
        (637, 69),
        (660, 4),
        (661, 50),
        (769, 35),
        (770, 43),
        (825, 18),
        (826, 4),
        (827, 13),
        (882, 43),
        (884, 60),
        (930, 42),
        (931, 4),
        (932, 31),
        (1004, 37),
        (1108, 54),
        (1117, 15),
        (1136, 56),
        (1150, 29),
        (1167, 27),
        (1276, 25),
        (1279, 31),
        (1280, 41),
        (1281, 29),
        (1282, 34),
        (1283, 24),
        (1284, 30),
        (1285, 42),
        (1286, 35),
        (1287, 35),
        (1288, 43),
        (1352, 28),
        (1353, 19),
        (1367, 15),
        (1370, 15),
        (1475, 44),
        (1540, 32),
        (1540, 53),
        (1600, 60),
        (1639, 4),
        (1642, 16),
        (1643, 14),
        (1673, 14),
        (1676, 25),
        (1687, 72),
        (1712, 36),
        (1712, 44),
        (1712, 65),
        (1765, 48),
        (1766, 24),
        (1781, 61),
        (1895, 25),
        (1895, 56),
        (1945, 31),
        (1947, 29),
        (1991, 31),
        (1992, 4),
        (1993, 29),
        (2134, 14),
        (2135, 34),
        (2136, 31),
        (2137, 29),
        (2257, 16),
        (2259, 63),
        (2282, 14),
        (2284, 14),
        (2285, 34),
        (2286, 31),
        (2287, 29),
        # textforensics.consensus (28 positions).
        (77, 69),
        (81, 24),
        (82, 34),
        (102, 32),
        (103, 33),
        (110, 38),
        (135, 30),
        (136, 33),
        (137, 74),
        (139, 21),
        (268, 29),
        (276, 29),
        (277, 29),
        (291, 51),
        (298, 14),
        (304, 29),
        (305, 29),
        (306, 17),
        (325, 51),
        (337, 41),
        (339, 14),
        (345, 33),
        (357, 42),
        (358, 17),
        (411, 17),
        (412, 12),
        (430, 46),
        (483, 90),
        # textforensics.detectors (14 positions).
        (74, 36),
        (84, 45),
        (155, 58),
        (265, 75),
        (374, 23),
        (714, 4),
        (715, 28),
        (716, 36),
        (717, 30),
        (717, 54),
        (771, 28),
        (786, 4),
        (787, 28),
        (788, 36),
        # textforensics.engine (5 positions).
        (17, 81),
        (22, 22),
        (84, 16),
        (93, 8),
        (94, 12),
        # textforensics.evidence (69 positions).
        (1009, 48),
        (1009, 68),
        (1011, 21),
        (1049, 4),
        (1051, 36),
        (1052, 48),
        (1052, 68),
        (1053, 18),
        (1053, 24),
        (1068, 21),
        (1070, 31),
        (1102, 31),
        (1106, 39),
        (1106, 77),
        (1121, 14),
        (1348, 16),
        (1368, 26),
        (1378, 33),
        (1381, 47),
        (1384, 17),
        (1398, 17),
        (1401, 37),
        (1401, 63),
        (1402, 17),
        (1416, 17),
        (1417, 24),
        (1433, 37),
        (1433, 63),
        (1434, 17),
        (1449, 25),
        (1466, 37),
        (1466, 63),
        (1467, 17),
        (1488, 47),
        (1489, 41),
        (1489, 67),
        (1497, 17),
        (1497, 40),
        (1514, 41),
        (1514, 67),
        (1522, 17),
        (1522, 40),
        (1535, 24),
        (1561, 17),
        (1563, 34),
        (1617, 16),
        (1659, 74),
        (1660, 4),
        (1752, 19),
        (1753, 19),
        (1755, 31),
        (1756, 18),
        (1756, 24),
        (1759, 32),
        (1760, 36),
        (1761, 48),
        (1761, 68),
        (1802, 74),
        (1845, 29),
        (1880, 35),
        (1883, 33),
        (1964, 30),
        (2156, 4),
        (2157, 31),
        (2158, 18),
        (2158, 24),
        (2161, 36),
        (2162, 48),
        (2162, 68),
        # textforensics.execution_policy (24 positions).
        (171, 8),
        (172, 29),
        (173, 30),
        (174, 32),
        (176, 40),
        (193, 8),
        (194, 29),
        (195, 30),
        (196, 32),
        (198, 40),
        (268, 67),
        (346, 30),
        (351, 48),
        (351, 72),
        (397, 28),
        (398, 4),
        (399, 36),
        (428, 28),
        (429, 4),
        (430, 36),
        (483, 4),
        (484, 14),
        (485, 20),
        (526, 42),
        # textforensics.explain (12 positions).
        (143, 22),
        (185, 22),
        (225, 57),
        (232, 54),
        (234, 30),
        (320, 8),
        (321, 45),
        (356, 50),
        (362, 56),
        (402, 27),
        (439, 23),
        (455, 54),
        # textforensics.mixed_origin (11 positions).
        (127, 4),
        (128, 31),
        (129, 26),
        (130, 21),
        (131, 18),
        (131, 24),
        (132, 20),
        (179, 43),
        (185, 12),
        (205, 12),
        (214, 16),
        # textforensics.model_card (8 positions).
        (267, 11),
        (271, 80),
        (279, 11),
        (287, 4),
        (290, 11),
        (299, 56),
        (299, 72),
        (474, 65),
        # textforensics.observatory (1 positions).
        (124, 53),
        # textforensics.policy (58 positions).
        (107, 34),
        (107, 50),
        (126, 30),
        (126, 41),
        (126, 57),
        (140, 37),
        (160, 45),
        (160, 60),
        (160, 71),
        (179, 4),
        (180, 16),
        (180, 27),
        (181, 27),
        (213, 18),
        (215, 59),
        (264, 46),
        (299, 74),
        (315, 8),
        (316, 20),
        (316, 31),
        (317, 25),
        (337, 8),
        (338, 20),
        (338, 31),
        (347, 48),
        (353, 8),
        (354, 20),
        (354, 31),
        (436, 43),
        (436, 58),
        (436, 69),
        (451, 18),
        (452, 35),
        (469, 4),
        (470, 16),
        (470, 27),
        (517, 31),
        (518, 33),
        (625, 8),
        (626, 20),
        (626, 31),
        (657, 33),
        (662, 77),
        (662, 78),
        (665, 34),
        (665, 53),
        (821, 19),
        (951, 25),
        (952, 19),
        (953, 23),
        (1012, 39),
        (1129, 29),
        (1157, 40),
        (1193, 33),
        (1194, 35),
        (1200, 41),
        (1208, 43),
        (1215, 35),
        # textforensics.probe_metrics (58 positions).
        (114, 27),
        (114, 43),
        (114, 71),
        (131, 71),
        (158, 32),
        (158, 40),
        (181, 47),
        (193, 17),
        (195, 17),
        (203, 41),
        (213, 17),
        (215, 17),
        (223, 30),
        (260, 8),
        (261, 12),
        (261, 16),
        (261, 21),
        (262, 13),
        (262, 24),
        (265, 15),
        (265, 28),
        (270, 20),
        (270, 33),
        (272, 20),
        (272, 33),
        (295, 9),
        (295, 12),
        (302, 19),
        (302, 35),
        (304, 21),
        (307, 15),
        (310, 52),
        (330, 26),
        (330, 28),
        (341, 51),
        (399, 47),
        (423, 50),
        (424, 36),
        (424, 56),
        (447, 66),
        (450, 91),
        (466, 73),
        (482, 62),
        (483, 19),
        (483, 27),
        (503, 55),
        (503, 66),
        (542, 4),
        (576, 57),
        (576, 68),
        (577, 59),
        (577, 70),
        (581, 38),
        (587, 30),
        (588, 35),
        (592, 47),
        (642, 16),
        (643, 18),
        # textforensics.probe_runs (49 positions).
        (415, 47),
        (480, 43),
        (481, 43),
        (482, 29),
        (488, 46),
        (504, 46),
        (505, 43),
        (572, 49),
        (639, 52),
        (694, 34),
        (697, 61),
        (698, 17),
        (727, 61),
        (728, 17),
        (750, 56),
        (776, 17),
        (801, 50),
        (802, 50),
        (803, 29),
        (807, 46),
        (808, 18),
        (896, 69),
        (904, 49),
        (1022, 51),
        (1023, 25),
        (1025, 35),
        (1026, 50),
        (1027, 41),
        (1028, 16),
        (1117, 23),
        (1171, 32),
        (1177, 56),
        (1178, 62),
        (1181, 56),
        (1182, 85),
        (1242, 39),
        (1631, 16),
        (1632, 20),
        (1636, 32),
        (1639, 41),
        (1640, 18),
        (1641, 25),
        (1643, 26),
        (1644, 25),
        (1648, 41),
        (1649, 41),
        (1650, 41),
        (1651, 24),
        (1652, 50),
        # textforensics.report (18 positions).
        (354, 4),
        (355, 34),
        (356, 21),
        (357, 31),
        (358, 23),
        (359, 43),
        (361, 23),
        (363, 25),
        (365, 28),
        (366, 29),
        (367, 38),
        (368, 36),
        (369, 22),
        (439, 82),
        (484, 75),
        (489, 66),
        (499, 76),
        (529, 93),
        # textforensics.result_codec (7 positions).
        (124, 8),
        (125, 23),
        (172, 15),
        (177, 20),
        (179, 8),
        (180, 23),
        (216, 15),
        # textforensics.schema (6 positions).
        (94, 27),
        (94, 43),
        (357, 60),
        (383, 48),
        (403, 69),
        (461, 19),
        # textforensics.semantic (50 positions).
        (480, 47),
        (480, 74),
        (497, 11),
        (507, 25),
        (507, 53),
        (507, 82),
        (567, 27),
        (603, 26),
        (614, 26),
        (639, 83),
        (654, 68),
        (654, 70),
        (654, 77),
        (655, 24),
        (656, 26),
        (656, 35),
        (660, 80),
        (660, 82),
        (660, 89),
        (661, 28),
        (662, 26),
        (662, 35),
        (666, 74),
        (666, 76),
        (666, 83),
        (667, 26),
        (668, 26),
        (668, 35),
        (672, 69),
        (672, 71),
        (672, 78),
        (673, 23),
        (674, 26),
        (674, 35),
        (678, 74),
        (678, 76),
        (678, 83),
        (679, 26),
        (680, 26),
        (680, 35),
        (682, 54),
        (687, 26),
        (710, 65),
        (710, 67),
        (710, 74),
        (718, 24),
        (718, 27),
        (734, 4),
        (736, 29),
        (737, 18),
        # textforensics.trust (38 positions).
        (142, 53),
        (187, 78),
        (213, 4),
        (214, 28),
        (381, 24),
        (392, 20),
        (392, 67),
        (396, 17),
        (396, 34),
        (398, 17),
        (421, 4),
        (422, 31),
        (425, 28),
        (426, 18),
        (426, 24),
        (429, 28),
        (430, 26),
        (431, 22),
        (432, 31),
        (483, 25),
        (501, 37),
        (503, 37),
        (522, 4),
        (526, 32),
        (527, 31),
        (528, 28),
        (529, 18),
        (529, 24),
        (532, 28),
        (533, 26),
        (534, 22),
        (535, 31),
        (546, 24),
        (639, 32),
        (642, 32),
        (669, 39),
        (670, 44),
        (671, 39),
        # textforensics.validation (29 positions).
        (1983, 17),
        (1983, 29),
        (2020, 21),
        (2032, 4),
        (2034, 18),
        (2034, 24),
        (2062, 4),
        (2065, 18),
        (2065, 24),
        (2067, 35),
        (2154, 4),
        (2159, 18),
        (2159, 24),
        (2165, 33),
        (2209, 77),
        (2213, 87),
        (2301, 46),
        (2342, 42),
        (2392, 20),
        (2392, 67),
        (2396, 17),
        (2396, 34),
        (2443, 4),
        (2446, 18),
        (2446, 24),
        (2451, 36),
        (2615, 40),
        (2700, 54),
        (2740, 51),
        # textforensics.verify (19 positions).
        (80, 64),
        (112, 24),
        (116, 20),
        (116, 67),
        (120, 17),
        (120, 34),
        (122, 17),
        (127, 67),
        (155, 20),
        (155, 67),
        (159, 17),
        (159, 34),
        (254, 31),
        (289, 26),
        (658, 33),
        (663, 33),
        (668, 33),
        (673, 33),
        (678, 33),
    }

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).parent.parent
        cls.runner = _load_runner(cls.project_root / "scripts" / "run_mutation.py")
        cls.baseline_path = cls.project_root / "mutation-baseline.toml"
        cls.baseline = cls.runner.load_baseline(cls.baseline_path)
        cls.trust_module_path = str(cls.project_root / "src" / "textforensics" / "trust.py")

    def _record(self, *, operator, occurrence, start_pos, end_pos, outcome, module_path=None):
        return {
            "work_item": {
                "job_id": f"test-{operator}-{occurrence}",
                "mutations": [
                    {
                        "module_path": module_path or self.trust_module_path,
                        "operator_name": operator,
                        "occurrence": occurrence,
                        "start_pos": list(start_pos),
                        "end_pos": list(end_pos),
                        "operator_args": {},
                        "definition_name": "test",
                    }
                ],
            },
            "result": {
                "worker_outcome": "normal",
                "test_outcome": outcome,
                "output": None,
                "diff": None,
            },
        }

    def _record_for_entry(self, entry, outcome):
        return self._record(
            operator=entry["operator"],
            occurrence=entry["occurrence"],
            start_pos=entry["start_pos"],
            end_pos=entry["end_pos"],
            outcome=outcome,
            module_path=str(
                self.project_root / "src" / (entry["module"].replace(".", "/") + ".py")
            ),
        )

    def _check_summary(self, summary):
        """Run --check-results on a summary dict; return the process result."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(summary, f)
            temp_path = f.name
        try:
            return subprocess.run(
                [
                    sys.executable,
                    str(self.project_root / "scripts" / "run_mutation.py"),
                    "--check-results",
                    temp_path,
                ],
                capture_output=True,
                text=True,
            )
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_baseline_file_loads_with_4361_entries(self):
        """The baseline has exactly the 4361 verified equivalent mutants.

        69 annotation BitOr mutants + 4 unreachable-condition
        NumberReplacer mutants for trust (see the baseline file's header
        for both proofs), plus 78 annotation BitOr mutants + 4
        unobservable-value NumberReplacer mutants for policy (wave 4E),
        plus 21 annotation BitOr mutants (3 Pow + 9 RShift + 9 Sub) +
        10 domain-equivalent mutants + 1 unreachable-condition mutant
        for policy (Phase 5 policy-298, full 506-item session at
        928dbc0; the 40 killable survivors are killed by tests in
        tests/test_enterprise_policy.py, class
        TestPolicyMutationKills298).
        plus 165 annotation BitOr mutants + 4 unobservable-value
        NumberReplacer mutants + 27 domain-equivalent mutants for
        benchmark (Phase 5 survivors wave, full 909-item session at
        8e6ffd1; the 27 baselined 2026-11-08 in the kind wave).
        plus 121 annotation BitOr mutants + 7 runtime mutants (6
        unobservable-value, 1 unreachable-condition) + 11
        domain-equivalent mutants for consensus (mutation-survivors
        wave, full run on 8e6ffd1; the 11 domain-equivalent entries
        were baselined by the kind wave, 2026-11-08).
        plus 5 unobservable-value mutants and 330
        annotation BitOr mutants for calibration (prefix-200 wave and
        full-session remainder wave).
        plus 56 domain-equivalent mutants + 6 ulp-equivalent mutants
        for calibration (Phase 5 mutation-survivors kind wave, full
        1937-item session at 884f590; kinds landed on
        fix/mutation-kinds).
        plus 66 annotation BitOr mutants + 1 domain-equivalent
        mutant for detectors (Phase 2, full 606-item session at
        dd8bd83; the 1 domain-equivalent entry is the
        normalize_prediction IsNot_Is no-op guard, baselined on
        fix/mutation-p2-detectors).
        plus 4 domain-equivalent mutants for analyzers (Phase 5
        mutation-survivors wave 2, full 516-item session at dd8bd83;
        the 4 baselined 2026-11-08 on fix/mutation-p2-analyzers).
        plus 4 unobservable-value NumberReplacer mutants + 1
        domain-equivalent ReplaceFalseWithTrue mutant for engine
        (Phase 5 survivors wave 2, full 322-item session at dd8bd83;
        the 5 baselined 2026-11-08 in the kind wave).
        plus 649 arg + 22 return annotation BitOr mutants + 25
        domain-equivalent mutants + 6 unobservable-value mutants
        for casefile (Phase 2, re-derived 2026-11-09 against main
        e75a773: the Phase-1 full-session dump was lost when its
        worktree was deleted, so the 671 annotation survivors were
        re-derived structurally from the 2118-item work list with
        the runner's own annotation machinery — 61 positions (59
        arg + 2 return) x 11 operators — and each entry re-validated
        with validate_baseline_entry; the 117 runtime survivors
        (25 domain + 6 unobservable + 86 gaps) were re-derived by
        hand-applying each candidate's exact diff against the 154
        committed kill tests, and each of the 31 baselined entries
        carries a hand-applied differential probe with 0 diffs.
        The one fluke is included: BitOr_BitXor occurrence 32 at
        L1277:25 was recorded KILLED in the lost dump only because
        /tmp filled up (Errno 28) — it is an equivalent annotation
        survivor like the other 10 mutants at that position. One
        annotation `|` generates NO mutant and is NOT a missing
        survivor: L1648:19 (`temp_path: str | None = None`, an
        AnnAssign in `write_case_file`) — cosmic-ray 8.7.0
        deliberately skips a `|` in an assignment annotation.
        Match keys include occurrence: two entries share the
        (module, operator, start_pos, end_pos) of L628:76 and differ
        only by occurrence (50 vs 51) — renumbered from L553:76 /
        44 vs 45 by the W1 refresh (see below).
        W1 (audit-w1, head 0da6013): the audit's source changes
        shifted line positions in trust, policy, detectors and
        casefile, so 956 entries were re-derived onto the new
        positions (line-text anchoring; 191 occurrences renumbered,
        12 entries in changed functions hand-re-verified with
        differential batteries, 0 stale afterwards) and their ids
        renamed to the current occurrence (the refresh had left ids
        at the old occurrence, which collided with the new W1
        annotation mutants). The W1 proof then ran the 1285 new /
        changed-code mutants (516 execution_policy + 161 policy +
        207 detectors + 107 trust + 294 casefile): 840 killed,
        445 survived; 297 survivors are baselined here (281
        annotation BitOr + 16 domain-equivalent: 11 Mul_Div
        keyword-only markers, 4 CompletenessAccounting comparisons
        and 1 detectors post-call gate, the last 5 verified by
        differential probe). The other 148 survivors were PROVEN
        killable by new tests (148/148 probe kills) and are NOT
        baselined — they stay unexplained pending the coordinator's
        decision on the follow-up tests. Per-module W1 additions:
        execution_policy 175 (165 annotation + 10 domain, new
        module), policy +57 (55 annotation + 2 domain), detectors
        +47 (44 annotation + 3 domain), trust +18 (17 annotation +
        1 domain), casefile +0 (no new equivalents; its 294 new
        mutants were 291 killed / 3 proven killable).
        W2 (audit-w2, head 739efc0): the audit's source changes
        shifted lines in calibration.py, benchmark.py, casefile.py,
        policy.py and trust.py and added new mutation points, so all
        1425 stale entries were re-derived from the live cosmic-ray
        enumeration on that head by line-text-anchored matching
        (identical source line + columns + enclosing function +
        annotation text), never by blind line shifting; 1399 entries
        were refreshed, 26 were DROPPED (22 policy `date | None`
        annotation entries whose annotation W2 changed to
        `date | datetime | None`, and 4 entries whose recorded
        equivalence W2 broke — calibration ReplaceFalseWithTrue:24
        and trust NumberReplacer:48/50/51, all proven killable by
        differential probe), and 737 ids were renamed to the current
        occurrence. The W2 proof then ran the 10,983-item proof set
        over the 20 W2-changed modules and appended 2179 new entries
        (1976 annotation BitOr + 203 domain-equivalent), taking the
        baseline 1994 -> 1968 -> 4147. The 2288 remaining
        new/changed-code mutants were proven killable (1154 in the
        first reprove) and are NOT baselined.
        F2 (audit-w2-f2, 2026-11-11): the re-proof of the 1134
        first-reprove survivors against the Batch 6c-strengthened
        kill tests killed 891 and left 243; the 29 killable survivors
        were killed by Batch 6d follow-up tests (29/29 disk-verified
        DISTINGUISHED, then 29/29 KILLED in the re-proof), and the
        214 proven-equivalent survivors were appended here (208
        domain-equivalent + 6 unobservable-value, each with a
        source-verified reason), taking the baseline 4147 -> 4361
        with 0 unexplained.
        """
        self.assertEqual(self.baseline["version"], 1)
        self.assertEqual(self.baseline["source_run"], "42393966895")
        self.assertEqual(self.baseline["source_commit"], "153b5ab")
        entries = self.baseline["entries"]
        self.assertEqual(len(entries), 4361)
        self.assertEqual(len({e["id"] for e in entries}), 4361, "entry ids must be unique")
        keys = {
            (
                e["module"],
                e["operator"],
                tuple(e["start_pos"]),
                tuple(e["end_pos"]),
                e["occurrence"],
            )
            for e in entries
        }
        self.assertEqual(len(keys), 4361, "match keys must be unique")
        from collections import Counter

        self.assertEqual(
            Counter(e["operator"] for e in entries),
            {
                "core/ExceptionReplacer": 8,
                "core/NumberReplacer": 108,
                "core/ReplaceAndWithOr": 5,
                "core/ReplaceBinaryOperator_Add_BitOr": 11,
                "core/ReplaceBinaryOperator_Add_BitXor": 1,
                "core/ReplaceBinaryOperator_Add_FloorDiv": 1,
                "core/ReplaceBinaryOperator_Add_LShift": 11,
                "core/ReplaceBinaryOperator_Add_Mul": 1,
                "core/ReplaceBinaryOperator_Add_Pow": 1,
                "core/ReplaceBinaryOperator_BitOr_Add": 342,
                "core/ReplaceBinaryOperator_BitOr_BitAnd": 343,
                "core/ReplaceBinaryOperator_BitOr_BitXor": 343,
                "core/ReplaceBinaryOperator_BitOr_Div": 342,
                "core/ReplaceBinaryOperator_BitOr_FloorDiv": 342,
                "core/ReplaceBinaryOperator_BitOr_LShift": 341,
                "core/ReplaceBinaryOperator_BitOr_Mod": 341,
                "core/ReplaceBinaryOperator_BitOr_Mul": 341,
                "core/ReplaceBinaryOperator_BitOr_Pow": 341,
                "core/ReplaceBinaryOperator_BitOr_RShift": 341,
                "core/ReplaceBinaryOperator_BitOr_Sub": 341,
                "core/ReplaceBinaryOperator_Div_Add": 1,
                "core/ReplaceBinaryOperator_Div_BitAnd": 1,
                "core/ReplaceBinaryOperator_Div_BitOr": 1,
                "core/ReplaceBinaryOperator_Div_BitXor": 1,
                "core/ReplaceBinaryOperator_Div_FloorDiv": 1,
                "core/ReplaceBinaryOperator_Div_LShift": 1,
                "core/ReplaceBinaryOperator_Div_Mod": 1,
                "core/ReplaceBinaryOperator_Div_Mul": 1,
                "core/ReplaceBinaryOperator_Div_Pow": 1,
                "core/ReplaceBinaryOperator_Div_RShift": 1,
                "core/ReplaceBinaryOperator_Div_Sub": 1,
                "core/ReplaceBinaryOperator_Mul_Add": 1,
                "core/ReplaceBinaryOperator_Mul_BitAnd": 1,
                "core/ReplaceBinaryOperator_Mul_BitOr": 1,
                "core/ReplaceBinaryOperator_Mul_Div": 68,
                "core/ReplaceBinaryOperator_Mul_FloorDiv": 2,
                "core/ReplaceBinaryOperator_Sub_Add": 2,
                "core/ReplaceBinaryOperator_Sub_BitOr": 1,
                "core/ReplaceBinaryOperator_Sub_BitXor": 3,
                "core/ReplaceBinaryOperator_Sub_Div": 1,
                "core/ReplaceBinaryOperator_Sub_FloorDiv": 1,
                "core/ReplaceBinaryOperator_Sub_LShift": 1,
                "core/ReplaceBinaryOperator_Sub_Mul": 1,
                "core/ReplaceBinaryOperator_Sub_Pow": 1,
                "core/ReplaceBinaryOperator_Sub_RShift": 1,
                "core/ReplaceComparisonOperator_Eq_Gt": 2,
                "core/ReplaceComparisonOperator_Eq_GtE": 87,
                "core/ReplaceComparisonOperator_Eq_Is": 17,
                "core/ReplaceComparisonOperator_Eq_IsNot": 2,
                "core/ReplaceComparisonOperator_Eq_Lt": 4,
                "core/ReplaceComparisonOperator_Eq_LtE": 89,
                "core/ReplaceComparisonOperator_Eq_NotEq": 1,
                "core/ReplaceComparisonOperator_GtE_Eq": 5,
                "core/ReplaceComparisonOperator_GtE_Gt": 6,
                "core/ReplaceComparisonOperator_GtE_Is": 1,
                "core/ReplaceComparisonOperator_GtE_IsNot": 1,
                "core/ReplaceComparisonOperator_GtE_Lt": 3,
                "core/ReplaceComparisonOperator_GtE_LtE": 3,
                "core/ReplaceComparisonOperator_GtE_NotEq": 4,
                "core/ReplaceComparisonOperator_Gt_GtE": 11,
                "core/ReplaceComparisonOperator_Gt_Is": 3,
                "core/ReplaceComparisonOperator_Gt_NotEq": 16,
                "core/ReplaceComparisonOperator_IsNot_Is": 1,
                "core/ReplaceComparisonOperator_Is_Eq": 4,
                "core/ReplaceComparisonOperator_LtE_Eq": 3,
                "core/ReplaceComparisonOperator_LtE_Lt": 3,
                "core/ReplaceComparisonOperator_Lt_Eq": 1,
                "core/ReplaceComparisonOperator_Lt_Gt": 3,
                "core/ReplaceComparisonOperator_Lt_Is": 1,
                "core/ReplaceComparisonOperator_Lt_LtE": 2,
                "core/ReplaceComparisonOperator_Lt_NotEq": 7,
                "core/ReplaceComparisonOperator_NotEq_Gt": 14,
                "core/ReplaceComparisonOperator_NotEq_IsNot": 4,
                "core/ReplaceComparisonOperator_NotEq_Lt": 12,
                "core/ReplaceComparisonOperator_NotEq_LtE": 2,
                "core/ReplaceContinueWithBreak": 5,
                "core/ReplaceFalseWithTrue": 8,
                "core/ReplaceOrWithAnd": 5,
                "core/ReplaceTrueWithFalse": 23,
                "core/ReplaceUnaryOperator_Delete_USub": 2,
                "core/ReplaceUnaryOperator_USub_Invert": 1,
                "core/ReplaceUnaryOperator_USub_Not": 2,
                "core/ReplaceUnaryOperator_USub_UAdd": 2,
            },
        )
        self.assertEqual({tuple(e["start_pos"]) for e in entries}, self.EXPECTED_POSITIONS)
        for entry in entries:
            self.assertIn(
                entry["module"],
                {
                    "textforensics._standalone_verify",
                    "textforensics.adversarial",
                    "textforensics.analyzers",
                    "textforensics.benchmark",
                    "textforensics.calibration",
                    "textforensics.casefile",
                    "textforensics.consensus",
                    "textforensics.detectors",
                    "textforensics.engine",
                    "textforensics.evidence",
                    "textforensics.execution_policy",
                    "textforensics.explain",
                    "textforensics.mixed_origin",
                    "textforensics.model_card",
                    "textforensics.observatory",
                    "textforensics.policy",
                    "textforensics.probe_metrics",
                    "textforensics.probe_runs",
                    "textforensics.report",
                    "textforensics.result_codec",
                    "textforensics.schema",
                    "textforensics.semantic",
                    "textforensics.trust",
                    "textforensics.validation",
                    "textforensics.verify",
                },
            )
            self.assertTrue(entry["reason"], f"entry {entry['id']} needs a reason")
            self.assertIn(entry["function"], entry["reason"])
            if entry["kind"] in self.runner.BASELINE_ANNOTATION_KINDS:
                self.assertIn(entry["annotation"], entry["reason"])
            else:
                self.assertIn(
                    entry["kind"],
                    {
                        "unreachable-condition",
                        "unobservable-value",
                        "domain-equivalent",
                        "ulp-equivalent",
                    },
                )
                self.assertIn(entry["source_text"], entry["reason"])
                self.assertEqual(len(entry["source_fingerprint"]), 64)

    def test_runtime_entries(self):
        """The 605 runtime entries carry their equivalence proofs."""
        runtime = [
            e for e in self.baseline["entries"] if e["kind"] in self.runner.BASELINE_RUNTIME_KINDS
        ]
        self.assertEqual(len(runtime), 605)
        unreachable = [e for e in runtime if e["kind"] == "unreachable-condition"]
        self.assertEqual(len(unreachable), 3)
        by_id = {e["id"]: e for e in runtime}
        self.assertEqual(
            {e["occurrence"] for e in unreachable},
            {15, 45, 95},
            "occurrences must match the W2 refresh (the W1 set was "
            "{12, 45, 48, 50, 51, 95}; the trust entries 48/50/51 were "
            "DROPPED in the W2 refresh because W2 broke their recorded "
            "equivalence — see the baseline header note — and 12 was "
            "renumbered to 15 by the same refresh: it is the "
            "PolicyRevisionFloor._atomic_write_bytes missing_ok entry)",
        )
        # The two entries that shared L628:76 (occurrences 50 and 51)
        # are gone: they were among the trust entries dropped in the
        # W2 refresh, so no unreachable-condition entry sits there now.
        at_628_76 = [e for e in unreachable if tuple(e["start_pos"]) == (628, 76)]
        self.assertEqual(len(at_628_76), 0)
        self.assertEqual(
            by_id["textforensics.trust:core/NumberReplacer:45"]["function"],
            "build_trust_map",
        )
        self.assertEqual(by_id["textforensics.trust:core/NumberReplacer:45"]["source_text"], "0")
        unobservable = [e for e in runtime if e["kind"] == "unobservable-value"]
        self.assertEqual(len(unobservable), 35)
        self.assertEqual(
            {e["occurrence"] for e in unobservable},
            {
                0,
                1,
                2,
                3,
                4,
                8,
                10,
                11,
                19,
                22,
                23,
                24,
                25,
                27,
                36,
                37,
                38,
                50,
                64,
                65,
                80,
                81,
                105,
                128,
                172,
                173,
                486,
                487,
            },
            "occurrences must match the W2 refresh + W2 proof + F2 "
            "re-proof append (the W1 set was {0, 1, 2, 3, 4, 8, 9, 10, "
            "19, 22, 23, 24, 25, 27, 36, 37, 38, 48, 64, 65, 81, 95, "
            "118}; W2 renumbered the calibration _coerce_label entries "
            "9 -> 11 and 118 -> 128 and the casefile entry 48 -> 50, "
            "dropped the trust 95 entry, and added 80/81 (probe_runs "
            "abstention n), 105 (casefile), 172/173 (probe_metrics "
            "holm_adjusted) and 486/487 (_standalone_verify exit_code))",
        )
        self.assertEqual(
            {e["function"] for e in unobservable},
            {
                "CapabilityPolicyEngine.evaluate",
                "_load_enterprise_policy_schema",
                "dataset_sha256",
                "_family_vote",
                "cohens_kappa",
                "percent_agreement",
                "build_agreement_matrix",
                "CalibrationCurve._validate_parameters",
                "DatasetReference.from_dict",
                "_coerce_label",
                "_disagreement",
                "_analyze_text_internal",
                "_compare_scores",
                "_replay_trust_map_v3",
                "replay_case_file",
                "write_case_file",
                "_slice_metrics",
                "holm_adjusted",
                "verify_bundle_bytes",
            },
        )
        self.assertEqual(
            {e["source_text"] for e in unobservable},
            {"2", "1", "4", "1024", "0", "0.0", "1.0", "False", "!=", "==", "or"},
        )
        # The two lru_cache entries share one position and function.
        # (W2 moved the decorator L668:19 -> L821:19.)
        at_821_19 = [e for e in unobservable if tuple(e["start_pos"]) == (821, 19)]
        self.assertEqual(len(at_821_19), 2)
        self.assertEqual({e["occurrence"] for e in at_821_19}, {22, 23})
        self.assertEqual(len({e["source_fingerprint"] for e in at_821_19}), 1)
        # The four benchmark chunk-size entries share one function (and
        # hence one fingerprint) across two positions.
        bench = [e for e in unobservable if e["module"] == "textforensics.benchmark"]
        self.assertEqual(len(bench), 4)
        self.assertEqual({e["occurrence"] for e in bench}, {0, 1, 2, 3})
        self.assertEqual({tuple(e["start_pos"]) for e in bench}, {(35, 46), (35, 53)})
        self.assertEqual({e["source_text"] for e in bench}, {"1024"})
        self.assertEqual(len({e["source_fingerprint"] for e in bench}), 1)
        # The two cohens_kappa p_o else-branch entries share one position
        # and function (consensus).
        at_337_41 = [e for e in unobservable if tuple(e["start_pos"]) == (337, 41)]
        self.assertEqual(len(at_337_41), 2)
        self.assertEqual({e["occurrence"] for e in at_337_41}, {64, 65})
        self.assertEqual({e["source_text"] for e in at_337_41}, {"0.0"})
        self.assertEqual(len({e["source_fingerprint"] for e in at_337_41}), 1)
        # The three zip strict=False entries (consensus). Scoped to
        # consensus: calibration's _coerce_label entry also has
        # source_text "False" (see below) and must not be counted here.
        strict_false = [
            e
            for e in unobservable
            if e["source_text"] == "False" and e["module"] == "textforensics.consensus"
        ]
        self.assertEqual(len(strict_false), 3)
        self.assertEqual(
            {e["function"] for e in strict_false},
            {"percent_agreement", "cohens_kappa", "build_agreement_matrix"},
        )
        self.assertEqual(
            {e["id"] for e in strict_false},
            {
                "textforensics.consensus:core/ReplaceFalseWithTrue:0",
                "textforensics.consensus:core/ReplaceFalseWithTrue:1",
                "textforensics.consensus:core/ReplaceFalseWithTrue:2",
            },
        )
        # The two calibration entries share one position and function.
        # (W2 moved them L255:47 -> L461:47.)
        at_461_47 = [e for e in unobservable if tuple(e["start_pos"]) == (461, 47)]
        self.assertEqual(len(at_461_47), 2)
        self.assertEqual({e["occurrence"] for e in at_461_47}, {36, 37})
        self.assertEqual({e["source_text"] for e in at_461_47}, {"0.0"})
        self.assertEqual(len({e["source_fingerprint"] for e in at_461_47}), 1)
        # The calibration _coerce_label False entry (remainder wave).
        coerce_false = [
            e
            for e in unobservable
            if e["source_text"] == "False" and e["module"] == "textforensics.calibration"
        ]
        self.assertEqual(len(coerce_false), 1)
        self.assertEqual({e["occurrence"] for e in coerce_false}, {11})
        self.assertEqual({e["function"] for e in coerce_false}, {"_coerce_label"})
        self.assertEqual({tuple(e["start_pos"]) for e in coerce_false}, {(1479, 20)})
        # The two _coerce_label entries share one function (and hence
        # one fingerprint) but sit at different positions in it.
        # (W2 renumbered 9 -> 11 and 118 -> 128 and moved the False
        # entry L942:20 -> L1479:20.)
        coerce = [e for e in unobservable if e["function"] == "_coerce_label"]
        self.assertEqual(len(coerce), 2)
        self.assertEqual({e["occurrence"] for e in coerce}, {11, 128})
        self.assertEqual({e["source_text"] for e in coerce}, {"0", "False"})
        self.assertEqual(len({e["source_fingerprint"] for e in coerce}), 1)
        # The four engine entries (full 322-item session at dd8bd83):
        # occ 3 in _disagreement, occ 19/37/38 in _analyze_text_internal.
        engine_unobs = [e for e in unobservable if e["module"] == "textforensics.engine"]
        self.assertEqual(len(engine_unobs), 4)
        self.assertEqual({e["occurrence"] for e in engine_unobs}, {3, 19, 37, 38})
        self.assertEqual(
            {e["function"] for e in engine_unobs},
            {"_disagreement", "_analyze_text_internal"},
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in engine_unobs},
            {(22, 22), (84, 16), (93, 8), (94, 12)},
        )
        self.assertEqual({e["source_text"] for e in engine_unobs}, {"2", "0.0", "1.0"})
        # Two functions, hence two fingerprints (the three
        # _analyze_text_internal entries share one).
        self.assertEqual(len({e["source_fingerprint"] for e in engine_unobs}), 2)
        # The six casefile entries (re-derived 2026-11-09 against main
        # e75a773; Phase 2, full 2118-item session — the Phase-1 dump
        # was lost, so the survivor set was re-derived structurally):
        # occ 10 in write_case_file (renumbered from 11 by the W1
        # refresh), occ 81 in _compare_scores, occ 24/25 in
        # _replay_trust_map_v3, occ 48/27 in replay_case_file.
        casefile_unobs = [e for e in unobservable if e["module"] == "textforensics.casefile"]
        self.assertEqual(len(casefile_unobs), 6)
        self.assertEqual({e["occurrence"] for e in casefile_unobs}, {10, 24, 25, 27, 50, 81})
        self.assertEqual(
            {e["function"] for e in casefile_unobs},
            {"_compare_scores", "_replay_trust_map_v3", "replay_case_file", "write_case_file"},
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in casefile_unobs},
            {(1687, 72), (1766, 24), (1895, 25), (1895, 56), (2257, 16), (2259, 63)},
        )
        self.assertEqual(
            {e["source_text"] for e in casefile_unobs},
            {"!=", "1", "==", "False", "or"},
        )
        # Four functions, hence four fingerprints.
        self.assertEqual(len({e["source_fingerprint"] for e in casefile_unobs}), 4)
        # The 561 domain-equivalent entries (151 from the pre-W2
        # waves — kind wave 2026-11-08 + casefile Phase 2 2026-11-09
        # + policy-298 2026-11-09 + the W1 proof 2026-11-11 — plus
        # 203 from the W2 proof append 2026-11-11, plus 208 from the
        # F2 re-proof append 2026-11-11, minus 1 dropped in the W2
        # refresh: 151 + 203 + 208 - 1 = 561). Final per-module
        # counts: _standalone_verify 43, adversarial 19, analyzers 4,
        # benchmark 39, calibration 83, casefile 27, consensus 11,
        # detectors 4, engine 1, evidence 43, execution_policy 10,
        # explain 11, mixed_origin 6, model_card 5, policy 20,
        # probe_metrics 64, probe_runs 25, report 6, result_codec 4,
        # schema 4, semantic 66, trust 19, validation 22, verify 25.
        domain = [e for e in runtime if e["kind"] == "domain-equivalent"]
        self.assertEqual(len(domain), 561)
        self.assertEqual(
            {e["module"] for e in domain},
            {
                "textforensics._standalone_verify",
                "textforensics.adversarial",
                "textforensics.analyzers",
                "textforensics.benchmark",
                "textforensics.calibration",
                "textforensics.casefile",
                "textforensics.consensus",
                "textforensics.detectors",
                "textforensics.engine",
                "textforensics.evidence",
                "textforensics.execution_policy",
                "textforensics.explain",
                "textforensics.mixed_origin",
                "textforensics.model_card",
                "textforensics.policy",
                "textforensics.probe_metrics",
                "textforensics.probe_runs",
                "textforensics.report",
                "textforensics.result_codec",
                "textforensics.schema",
                "textforensics.semantic",
                "textforensics.trust",
                "textforensics.validation",
                "textforensics.verify",
            },
        )
        self.assertTrue(all("ulp_bound_ulps" not in e for e in domain))
        # Benchmark's 39 (27 from the full 909-item session — 13
        # round-1 + 14 round-2 genuinely-equivalent survivors — plus
        # 9 from the W2 proof and 3 from the F2 re-proof append).
        bench_domain = [e for e in domain if e["module"] == "textforensics.benchmark"]
        self.assertEqual(len(bench_domain), 39)
        self.assertEqual(
            {e["occurrence"] for e in bench_domain},
            {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17},
            "occurrences must match the benchmark full-session dump "
            "(13 round-1 + 14 round-2 genuinely-equivalent survivors) "
            "plus the W2 proof and F2 re-proof appends",
        )
        self.assertEqual(
            {e["function"] for e in bench_domain},
            {
                "_load_scores",
                "dataset_sha256",
                "_compute_content_hash",
                "_compute_sample_hashes",
                "calibrate_threshold_jsonl",
                "verify_fingerprint",
                "_metrics",
                "DisjointnessProof.__post_init__",
                "_sample_and_group_hashes",
                "benchmark_with_calibration_jsonl",
                "check_disjointness",
                "prove_disjointness",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in bench_domain},
            {
                (74, 58),
                (35, 51),
                (175, 36),
                (176, 41),
                (100, 32),
                (101, 32),
                (102, 32),
                (103, 40),
                (104, 38),
                (89, 34),
                (93, 18),
                (156, 51),
                (155, 54),
                (297, 35),
                (301, 35),
                (404, 23),
                (406, 23),
                (412, 24),
                (464, 4),
                (514, 34),
                (527, 4),
                (602, 19),
                (602, 38),
                (699, 18),
                (758, 30),
                (766, 30),
                (876, 44),
                (976, 11),
                (980, 11),
            },
        )
        # The six chunk-size Mul entries share one position and function
        # (and hence one fingerprint) with the four baselined
        # NumberReplacer entries at the same line, plus two more at
        # their own positions (W2 proof).
        mul = [
            e for e in bench_domain if e["operator"].startswith("core/ReplaceBinaryOperator_Mul_")
        ]
        self.assertEqual(len(mul), 6)
        self.assertEqual({tuple(e["start_pos"]) for e in mul}, {(35, 51), (464, 4), (527, 4)})
        self.assertEqual({e["source_text"] for e in mul}, {"*"})
        self.assertEqual(len({e["source_fingerprint"] for e in mul}), 3)
        # The ten _metrics denominator-guard entries (Add_LShift / Add_BitOr
        # at the same five positions) share one function and fingerprint.
        guard = [
            e
            for e in bench_domain
            if e["function"] == "_metrics"
            and e["operator"].startswith("core/ReplaceBinaryOperator_Add_")
        ]
        self.assertEqual(len(guard), 10)
        self.assertEqual(
            {tuple(e["start_pos"]) for e in guard},
            {(100, 32), (101, 32), (102, 32), (103, 40), (104, 38)},
        )
        self.assertEqual({e["source_text"] for e in guard}, {"+"})
        self.assertEqual(len({e["source_fingerprint"] for e in guard}), 1)
        # Consensus's 11: the no-kind equivalents from the consensus
        # full-session run, baselined once the kind + validator landed.
        cons_domain = [e for e in domain if e["module"] == "textforensics.consensus"]
        self.assertEqual(len(cons_domain), 11)
        self.assertEqual(
            {e["occurrence"] for e in cons_domain},
            {0, 1, 2, 5, 7, 8},
            "occurrences must match the consensus full-session dump "
            "(corrected re-verification + coordinator clean re-run, "
            "792/653/139/128/11)",
        )
        self.assertEqual(
            {e["function"] for e in cons_domain},
            {
                "_family_vote",
                "family_balanced_consensus",
                "percent_agreement",
                "cohens_kappa",
                "fleiss_kappa",
            },
        )
        self.assertEqual(
            {e["source_text"] for e in cons_domain},
            {">", "==", "!=", "<", "|", "continue"},
        )
        self.assertEqual(
            {e["module"] for e in cons_domain},
            {"textforensics.consensus"},
        )
        # Calibration's 83: the 56 domain equivalents from the full
        # 1937-item calibration session, plus 22 from the W2 proof
        # and 5 from the F2 re-proof append.
        calib_domain = [e for e in domain if e["module"] == "textforensics.calibration"]
        self.assertEqual(len(calib_domain), 83)
        self.assertEqual(
            {e["occurrence"] for e in calib_domain},
            {
                0,
                1,
                2,
                3,
                4,
                5,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
                29,
                32,
                33,
                34,
                37,
                38,
                39,
                42,
            },
            "occurrences must match the calibration full-session dump (1937/1539/397/335/62) "
            "plus the W2 proof and F2 re-proof appends",
        )
        self.assertEqual(
            {e["function"] for e in calib_domain},
            {
                "CalibrationArtifact.validation_issues",
                "CalibrationCurve.__post_init__",
                "CalibrationCurve._calibrate_beta",
                "CalibrationCurve._calibrate_isotonic",
                "CalibrationCurve._validate_parameters",
                "CalibrationCurve.calibrate",
                "CalibrationCurve.from_dict",
                "CalibrationCurve.is_legacy",
                "CalibrationManager._load_all",
                "CalibrationManager._save_artifact",
                "CalibrationManager.get_calibrated_result_for_identity",
                "CalibrationManager.get_calibrated_score_for_identity",
                "_probability_metrics",
                "evaluate_threshold",
                "migrate_legacy_temperature_curve",
                "select_threshold",
                "validate_no_contamination",
            },
        )
        self.assertEqual(
            {e["module"] for e in calib_domain},
            {"textforensics.calibration"},
        )
        # Detectors' 4: the normalize_prediction IsNot_Is no-op guard
        # (Phase 2, full 606-item session at dd8bd83; its position
        # moved L260:75 -> L265:75 in the W1 refresh) plus 3 W1 proof
        # entries — 2 Mul_Div `*,` keyword-only markers
        # (execute_detector, run_all_detectors) and the Eq_GtE
        # post-call gate (validate_prediction narrows execution to
        # {'local', 'remote'} first, so == and >= coincide;
        # verified by differential probe). The mutated span of the
        # IsNot_Is entry is `is not` (L265:75-81), not `is not None`:
        # the operator replaces the `is not` comparison, so the
        # source text is the two-word operator.
        det_domain = [e for e in domain if e["module"] == "textforensics.detectors"]
        self.assertEqual(len(det_domain), 4)
        self.assertEqual({e["occurrence"] for e in det_domain}, {0, 4, 6, 7})
        self.assertEqual(
            {e["function"] for e in det_domain},
            {"normalize_prediction", "execute_detector", "run_all_detectors"},
        )
        self.assertEqual({e["source_text"] for e in det_domain}, {"is not", "*", "=="})
        self.assertEqual(
            {e["operator"] for e in det_domain},
            {
                "core/ReplaceComparisonOperator_IsNot_Is",
                "core/ReplaceBinaryOperator_Mul_Div",
                "core/ReplaceComparisonOperator_Eq_GtE",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in det_domain},
            {(265, 75), (714, 4), (771, 28), (786, 4)},
        )
        self.assertEqual(
            {e["id"] for e in det_domain},
            {
                "textforensics.detectors:core/ReplaceComparisonOperator_IsNot_Is:0",
                "textforensics.detectors:core/ReplaceBinaryOperator_Mul_Div:4",
                "textforensics.detectors:core/ReplaceBinaryOperator_Mul_Div:7",
                "textforensics.detectors:core/ReplaceComparisonOperator_Eq_GtE:6",
            },
        )
        # Analyzers's 4: the boundary equivalences in the linear
        # interpolation helpers, from the full 516-item session
        # (512 killed / 4 surviving / 0 error) at dd8bd83.
        analyzers_domain = [e for e in domain if e["module"] == "textforensics.analyzers"]
        self.assertEqual(len(analyzers_domain), 4)
        self.assertEqual(
            {e["occurrence"] for e in analyzers_domain},
            {0, 1},
            "occurrences must match the analyzers full-session dump "
            "(LtE_Lt occ 0/1, GtE_Gt occ 0/1)",
        )
        self.assertEqual(
            {e["function"] for e in analyzers_domain},
            {"_high_when_low", "_high_when_high"},
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in analyzers_domain},
            {(32, 13), (34, 13), (41, 13), (43, 13)},
        )
        self.assertEqual(
            {e["source_text"] for e in analyzers_domain},
            {"<=", ">="},
        )
        # The two entries in each helper share one function (and hence
        # one fingerprint).
        self.assertEqual(len({e["source_fingerprint"] for e in analyzers_domain}), 2)
        # Engine's 1: the zip strict=False entry in _weighted_score
        # (full 322-item session at dd8bd83).
        engine_domain = [e for e in domain if e["module"] == "textforensics.engine"]
        self.assertEqual(len(engine_domain), 1)
        self.assertEqual({e["occurrence"] for e in engine_domain}, {0})
        self.assertEqual({e["function"] for e in engine_domain}, {"_weighted_score"})
        self.assertEqual({tuple(e["start_pos"]) for e in engine_domain}, {(17, 81)})
        self.assertEqual({e["source_text"] for e in engine_domain}, {"False"})
        self.assertEqual(
            {e["operator"] for e in engine_domain},
            {"core/ReplaceFalseWithTrue"},
        )
        # Casefile's 27: the 25 domain equivalents from the re-derived
        # 2118-item session (1330 killed / 788 surviving, probe-proven
        # 2026-11-09; the Phase-1 dump was lost, so the survivor set
        # was re-derived structurally and each entry re-validated).
        # 13 Mul_Div `*,` -> `/,` keyword-only-marker no-ops, 5 Eq_GtE
        # + 3 Eq_LtE + 1 NotEq_Gt + 2 NotEq_Lt `==`/`!=` coincidences
        # on validated domains, and 1 NumberReplacer maxsplit 1 -> 2.
        # Every entry carries a hand-applied differential probe with
        # 0 diffs (specs casefile-mut-tools/p2/probes/spec-<idx>.json).
        casefile_domain = [e for e in domain if e["module"] == "textforensics.casefile"]
        self.assertEqual(len(casefile_domain), 27)
        self.assertEqual(
            {e["occurrence"] for e in casefile_domain},
            {1, 2, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22},
            "occurrences must match the casefile re-derived survivor list "
            "(2118-item session, 1330 killed / 788 surviving) plus the "
            "W2 proof and F2 re-proof appends",
        )
        self.assertEqual(
            {e["function"] for e in casefile_domain},
            {
                "_checklist_item",
                "_compare_scores",
                "_observations_match",
                "_replay_trust_map_inner",
                "_validate_portable_bundle",
                "_verify_case_sections",
                "append_custody_entry",
                "build_case_input",
                "build_checklist",
                "build_detector_observations",
                "build_limitations",
                "build_validation_refs",
                "chain_custody_entry",
                "seal_case_file",
                "verify_case_file",
                "verify_case_file_path",
            },
        )
        self.assertEqual(
            {e["source_text"] for e in casefile_domain},
            {"!=", "*", "0", "1", "=="},
        )
        # The fourteen Mul_Div entries share the `*,` marker (and one
        # source text) across fourteen functions, hence fourteen
        # fingerprints.
        mul_div = [
            e for e in casefile_domain if e["operator"] == "core/ReplaceBinaryOperator_Mul_Div"
        ]
        self.assertEqual(len(mul_div), 14)
        self.assertEqual({e["source_text"] for e in mul_div}, {"*"})
        self.assertEqual(len({e["source_fingerprint"] for e in mul_div}), 14)
        # Sixteen functions, hence sixteen fingerprints overall.
        self.assertEqual(len({e["source_fingerprint"] for e in casefile_domain}), 16)
        # Policy's 20: the 12 domain equivalents from the full 506-item
        # policy-298 session (352 killed / 154 surviving / 0 error) at
        # 928dbc0, classified in hidden_files/policy-298-classification.md
        # (positions refreshed by the W1 refresh: 137->231, 209->313,
        # 210->314, 242->370, 243->371, 381->509, 384->512, 848->976,
        # 876->1004), plus 2 W1 proof Mul_Div `*,` keyword-only
        # markers (claim_is_expired, _claim_is_effective), plus 8 from
        # the W2 proof (6 more Mul_Div markers and the Eq_Is /
        # Eq_LtE / NotEq_IsNot coincidences; the W2 refresh
        # renumbered the policy-298 occurrences, e.g. Eq_Is 1-5 ->
        # 0/2/3/4/5/6 and Eq_LtE 6/7/11/12 -> 7/8/12/13).
        policy_domain = [e for e in domain if e["module"] == "textforensics.policy"]
        self.assertEqual(len(policy_domain), 20)
        self.assertEqual(
            {e["occurrence"] for e in policy_domain},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 13},
            "occurrences must match the policy-298 full-session dump "
            "as renumbered by the W2 refresh plus the W1 Mul_Div 0/1 "
            "and the W2 proof Mul_Div 2-7",
        )
        self.assertEqual(
            {e["function"] for e in policy_domain},
            {
                "CapabilityLedger.enforce",
                "CapabilityLedger.get",
                "CapabilityLedger.is_validated",
                "validate_claim",
                "ledger_to_trust_dimension",
                "CapabilityPolicyEngine.evaluate",
                "PolicyRevisionFloor.check_policy",
                "PolicyRevisionFloor.advance_floor",
                "claim_is_expired",
                "_claim_is_effective",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in policy_domain},
            {
                (160, 45),
                (179, 4),
                (213, 18),
                (215, 59),
                (315, 8),
                (337, 8),
                (347, 48),
                (353, 8),
                (436, 43),
                (451, 18),
                (452, 35),
                (469, 4),
                (517, 31),
                (518, 33),
                (625, 8),
                (662, 77),
                (665, 34),
                (665, 53),
                (1129, 29),
                (1157, 40),
            },
        )
        self.assertEqual(
            {e["source_text"] for e in policy_domain},
            {"==", "-", "*", "!="},
        )
        self.assertEqual(
            {e["operator"] for e in policy_domain},
            {
                "core/ReplaceComparisonOperator_Eq_Is",
                "core/ReplaceComparisonOperator_Eq_LtE",
                "core/ReplaceComparisonOperator_NotEq_IsNot",
                "core/ReplaceUnaryOperator_USub_Invert",
                "core/ReplaceBinaryOperator_Mul_Div",
            },
        )
        self.assertEqual(
            {e["id"] for e in policy_domain},
            {
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:0",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:1",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:2",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:3",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:4",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:5",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:6",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:7",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:0",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:2",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:3",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:4",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:5",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:6",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:7",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:8",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:12",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:13",
                "textforensics.policy:core/ReplaceComparisonOperator_NotEq_IsNot:0",
                "textforensics.policy:core/ReplaceUnaryOperator_USub_Invert:1",
            },
        )
        # Execution_policy's 10 (W1 proof, new module): 6 Mul_Div
        # `*,` keyword-only markers + 3 Eq_GtE + 1 Eq_LtE
        # CompletenessAccounting comparisons (the 4 comparisons were
        # verified by differential probe over the full 0..3 sweep).
        exec_domain = [e for e in domain if e["module"] == "textforensics.execution_policy"]
        self.assertEqual(len(exec_domain), 10)
        self.assertEqual({e["occurrence"] for e in exec_domain}, {0, 1, 2, 3, 4, 5})
        self.assertEqual(
            {e["function"] for e in exec_domain},
            {
                "ExecutionPolicy.default_local_only",
                "ExecutionPolicy.with_remote_consent",
                "CompletenessAccounting.is_complete",
                "assert_execution_allowed",
                "CompletenessAccounting.support_eligible",
                "check_execution_allowed",
                "public_error_body",
                "diagnostic_record",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in exec_domain},
            {
                (171, 8),
                (193, 8),
                (346, 30),
                (351, 48),
                (351, 72),
                (398, 4),
                (429, 4),
                (483, 4),
                (526, 42),
            },
        )
        self.assertEqual({e["source_text"] for e in exec_domain}, {"*", "=="})
        self.assertEqual(
            {e["operator"] for e in exec_domain},
            {
                "core/ReplaceBinaryOperator_Mul_Div",
                "core/ReplaceComparisonOperator_Eq_GtE",
                "core/ReplaceComparisonOperator_Eq_LtE",
            },
        )
        # The two support_eligible entries at (351, 48) share one
        # position and function (hence one fingerprint); the six
        # Mul_Div entries sit in six functions (six fingerprints).
        self.assertEqual(len({e["source_fingerprint"] for e in exec_domain}), 8)
        # Trust's 19: the 1 Mul_Div `*,` keyword-only marker from the
        # W1 proof in _stability_dimension, plus 17 from the W2 proof
        # and 1 from the F2 re-proof append (the Eq_Lt:18
        # out_of_scope-minimum entry).
        trust_domain = [e for e in domain if e["module"] == "textforensics.trust"]
        self.assertEqual(len(trust_domain), 19)
        self.assertEqual(
            {e["occurrence"] for e in trust_domain},
            {0, 1, 2, 6, 8, 9, 10, 11, 12, 13, 17, 18, 19},
        )
        self.assertEqual(
            {e["function"] for e in trust_domain},
            {
                "_overall_state",
                "_stability_dimension",
                "assess_trust_map",
                "build_trust_map",
                "trust_map_from_capability_ledger",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in trust_domain},
            {
                (213, 4),
                (381, 24),
                (392, 20),
                (392, 67),
                (396, 17),
                (396, 34),
                (398, 17),
                (421, 4),
                (483, 25),
                (501, 37),
                (503, 37),
                (522, 4),
                (639, 32),
                (642, 32),
                (669, 39),
                (670, 44),
                (671, 39),
            },
        )
        self.assertEqual({e["source_text"] for e in trust_domain}, {"*", "==", "is"})
        self.assertEqual(
            {e["operator"] for e in trust_domain},
            {
                "core/ReplaceBinaryOperator_Mul_Div",
                "core/ReplaceComparisonOperator_Eq_GtE",
                "core/ReplaceComparisonOperator_Eq_Is",
                "core/ReplaceComparisonOperator_Eq_Lt",
                "core/ReplaceComparisonOperator_Eq_LtE",
                "core/ReplaceComparisonOperator_Is_Eq",
            },
        )
        # The 6 ulp-equivalent entries (kind wave, calibration only).
        ulp = [e for e in runtime if e["kind"] == "ulp-equivalent"]
        self.assertEqual(len(ulp), 6)
        self.assertEqual({e["module"] for e in ulp}, {"textforensics.calibration"})
        self.assertEqual(
            {e["ulp_bound_ulps"] for e in ulp},
            {0, 1, 2, 3},
            "bounds are the measured per-entry maxima, not a blanket cap",
        )
        for entry in ulp:
            self.assertTrue(entry["swept_domain"], f"{entry['id']} needs a swept domain")
        for entry in runtime:
            with self.subTest(entry=entry["id"]):
                ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
                self.assertTrue(ok, f"{entry['id']} failed re-validation: {reason}")

    def test_all_baseline_entries_validate_against_current_source(self):
        """Every entry re-validates (AST position + annotation text + owner)."""
        for entry in self.baseline["entries"]:
            with self.subTest(entry=entry["id"]):
                ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
                self.assertTrue(ok, f"{entry['id']} failed re-validation: {reason}")

    def test_postponed_evaluation_precondition_benchmark(self):
        """benchmark.py still uses `from __future__ import annotations` (PEP 563)."""
        import ast as _ast

        source = (self.project_root / "src" / "textforensics" / "benchmark.py").read_text()
        self.assertTrue(self.runner._has_postponed_evaluation(_ast.parse(source)))

    def test_postponed_evaluation_precondition(self):
        """trust.py still uses `from __future__ import annotations` (PEP 563)."""
        import ast as _ast

        source = (self.project_root / "src" / "textforensics" / "trust.py").read_text()
        self.assertTrue(self.runner._has_postponed_evaluation(_ast.parse(source)))

    def test_postponed_evaluation_precondition_policy(self):
        """policy.py still uses `from __future__ import annotations` (PEP 563)."""
        import ast as _ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        self.assertTrue(self.runner._has_postponed_evaluation(_ast.parse(source)))

    def test_postponed_evaluation_precondition_consensus(self):
        """consensus.py still uses `from __future__ import annotations` (PEP 563)."""
        import ast as _ast

        source = (self.project_root / "src" / "textforensics" / "consensus.py").read_text()
        self.assertTrue(self.runner._has_postponed_evaluation(_ast.parse(source)))

    def test_postponed_evaluation_precondition_detectors(self):
        """detectors.py still uses `from __future__ import annotations` (PEP 563)."""
        import ast as _ast

        source = (self.project_root / "src" / "textforensics" / "detectors.py").read_text()
        self.assertTrue(self.runner._has_postponed_evaluation(_ast.parse(source)))

    def test_postponed_evaluation_precondition_casefile(self):
        """casefile.py still uses `from __future__ import annotations` (PEP 563)."""
        import ast as _ast

        source = (self.project_root / "src" / "textforensics" / "casefile.py").read_text()
        self.assertTrue(self.runner._has_postponed_evaluation(_ast.parse(source)))

    def test_postponed_evaluation_precondition_execution_policy(self):
        """execution_policy.py still uses `from __future__ import annotations` (PEP 563)."""
        import ast as _ast

        source = (self.project_root / "src" / "textforensics" / "execution_policy.py").read_text()
        self.assertTrue(self.runner._has_postponed_evaluation(_ast.parse(source)))

    def test_no_annotation_evaluation_in_repo(self):
        """Nothing in src/ or tests/ evaluates annotations.

        This is the repo-wide invariant the equivalence proof rests on: if
        any code called get_type_hints / read __annotations__ / used
        eval_str / TypeAdapter on these types, a mutated annotation string
        could change runtime behaviour. This test file itself names the
        APIs, so it is excluded from the search.
        """
        import re

        patterns = [
            re.compile(r"get_type_hints"),
            re.compile(r"__annotations__"),
            re.compile(r"eval_str"),
            re.compile(r"get_annotations"),
            re.compile(r"ForwardRef"),
            re.compile(r"TypeAdapter"),
        ]
        hits = []
        for base in (self.project_root / "src", self.project_root / "tests"):
            for path in sorted(base.rglob("*.py")):
                if path.resolve() == Path(__file__).resolve():
                    continue
                text = path.read_text()
                for pattern in patterns:
                    if pattern.search(text):
                        hits.append(f"{path.relative_to(self.project_root)}: {pattern.pattern}")
        self.assertEqual(hits, [], f"annotation-evaluating code found: {hits}")

    def test_equivalent_mutant_accepted(self):
        """Survivors matching re-validated entries are accepted (exit 0)."""
        entries = self.baseline["entries"][:2]
        records = [self._record_for_entry(e, "survived") for e in entries]
        records.append(
            self._record(
                operator="core/AddNot",
                occurrence=0,
                start_pos=(124, 19),
                end_pos=(124, 27),
                outcome="killed",
            )
        )
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["surviving"], 2)
        self.assertEqual(summary["equivalent"], 2)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in entries])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_non_baseline_survivor_still_fails(self):
        """A survivor with no baseline entry still fails (exit 2)."""
        records = [
            self._record(
                operator="core/AddNot",
                occurrence=8,
                start_pos=(124, 19),
                end_pos=(124, 27),
                outcome="survived",
            ),
            self._record(
                operator="core/AddNot",
                occurrence=9,
                start_pos=(126, 19),
                end_pos=(126, 27),
                outcome="killed",
            ),
        ]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["surviving"], 1)
        self.assertEqual(summary["equivalent"], 0)
        self.assertEqual(summary["unexplained_surviving"], 1)
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("1 unexplained", result.stdout)

    def test_summary_reports_excluded_count(self):
        """The summary reports equivalent/dormant/superseded/stale transparently."""
        entries = self.baseline["entries"][:2]
        records = [self._record_for_entry(e, "survived") for e in entries]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        for key in (
            "equivalent",
            "equivalent_mutants",
            "equivalent_dormant",
            "equivalent_dormant_ids",
            "equivalent_superseded",
            "equivalent_superseded_ids",
            "unexplained_surviving",
            "stale_baseline_entries",
            "baseline_entries",
        ):
            self.assertIn(key, summary, f"summary is missing {key}")
        self.assertEqual(summary["baseline_entries"], 4361)
        self.assertEqual(summary["equivalent"], 2)
        # The other 4359 entries matched no live survivor in this run.
        self.assertEqual(summary["equivalent_dormant"], 4359)
        self.assertEqual(summary["equivalent_superseded"], 0)
        self.assertEqual(summary["stale_baseline_entries"], [])
        # Raw counts are never relabelled: the survivors stay in `surviving`.
        self.assertEqual(summary["surviving"], 2)
        self.assertEqual(summary["killed"], 0)

    def test_dormant_and_superseded_reported(self):
        """An entry whose mutant was killed is superseded, not equivalent."""
        entries = self.baseline["entries"][:2]
        records = [
            self._record_for_entry(entries[0], "survived"),
            self._record_for_entry(entries[1], "killed"),
        ]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["equivalent"], 1)
        self.assertEqual(summary["equivalent_mutants"], [entries[0]["id"]])
        self.assertEqual(summary["equivalent_superseded"], 1)
        self.assertEqual(summary["equivalent_superseded_ids"], [entries[1]["id"]])
        self.assertEqual(summary["equivalent_dormant"], 4359)
        self.assertEqual(summary["unexplained_surviving"], 0)
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_stale_baseline_entry_fails_loudly(self):
        """An entry whose position moved out of an annotation fails (exit 1)."""
        import copy

        entry = copy.deepcopy(self.baseline["entries"][0])
        # Move the entry onto runtime code (L311 is `if excluded_incomplete:`).
        entry["start_pos"] = [311, 20]
        entry["end_pos"] = [311, 21]
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertFalse(ok, "moved entry must not validate")
        self.assertIn("no longer holds `|`", reason)

        tampered = copy.deepcopy(self.baseline)
        tampered["entries"] = [entry] + self.baseline["entries"][1:]
        records = [self._record_for_entry(entry, "survived")]
        summary = self.runner.parse_results(records, tampered, self.project_root)
        self.assertEqual(len(summary["stale_baseline_entries"]), 1)
        self.assertEqual(summary["stale_baseline_entries"][0]["id"], entry["id"])
        # A stale entry never excuses its survivor: it counts as unexplained
        # too, but the stale failure (exit 1) takes precedence over exit 2.
        self.assertEqual(summary["unexplained_surviving"], 1)
        self.assertEqual(summary["equivalent"], 0)
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("stale baseline", result.stdout.lower())

    def test_changed_annotation_text_is_stale(self):
        """An entry whose annotation text changed fails re-validation."""
        import copy

        entry = copy.deepcopy(self.baseline["entries"][0])
        entry["annotation"] = "TrustDimension | str | None"
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertFalse(ok, "changed annotation text must not validate")
        self.assertIn("annotation text changed", reason)

    def test_classify_baseline_parses_each_module_once(self):
        """Full-baseline re-validation parses each module exactly once.

        Regression test for the Core 3.11 CI stall (test 2562 exceeded
        10 minutes on CPython 3.11.18): ``validate_baseline_entry``
        used to re-read, re-parse and re-walk the module for every one
        of the 4361 entries. The per-module context cache must parse
        each of the 25 modules once, and a second full classify must
        parse nothing.
        """
        runner = self.runner
        real_parse = runner.ast.parse
        calls = {"n": 0}

        def counting_parse(source, *args, **kwargs):
            calls["n"] += 1
            return real_parse(source, *args, **kwargs)

        runner._clear_module_context_cache()
        try:
            runner.ast.parse = counting_parse
            summary = runner.classify_baseline([], self.baseline, self.project_root)
            self.assertEqual(summary["baseline_entries"], 4361)
            self.assertEqual(len(summary["stale_baseline_entries"]), 0)
            self.assertEqual(calls["n"], 25, "one parse per distinct module")
            # A second full classify hits the cache: no further parses,
            # and the result is identical.
            summary2 = runner.classify_baseline([], self.baseline, self.project_root)
            self.assertEqual(summary2, summary)
            self.assertEqual(calls["n"], 25, "second classify must parse nothing")
        finally:
            runner.ast.parse = real_parse
            runner._clear_module_context_cache()

    def test_module_context_cache_returns_same_object(self):
        """Two loads of the same unchanged module return one context."""
        runner = self.runner
        path = self.project_root / "src" / "textforensics" / "trust.py"
        runner._clear_module_context_cache()
        try:
            first, err1 = runner._load_module_context(path)
            second, err2 = runner._load_module_context(path)
            self.assertIsNone(err1)
            self.assertIsNone(err2)
            self.assertIs(first, second, "same file must return the cached context")
            self.assertEqual(len(runner._MODULE_CONTEXT_CACHE), 1)
        finally:
            runner._clear_module_context_cache()

    def test_module_context_cache_invalidated_on_source_change(self):
        """Editing a module re-parses it instead of serving a stale tree."""
        import tempfile

        runner = self.runner
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src" / "textforensics"
            src.mkdir(parents=True)
            module = src / "synthetic.py"
            module.write_text(
                "from __future__ import annotations\n\n\n"
                "def f(x: float | None) -> float | None:\n"
                "    return x\n"
            )
            entry = {
                "id": "textforensics.synthetic:core/ReplaceBinaryOperator_BitOr_Add:0",
                "module": "textforensics.synthetic",
                "operator": "core/ReplaceBinaryOperator_BitOr_Add",
                "occurrence": 0,
                "start_pos": [4, 15],
                "end_pos": [4, 16],
                "function": "f",
                "kind": "arg",
                "annotation": "float | None",
                "reason": "synthetic",
            }
            ok, reason = runner.validate_baseline_entry(entry, root)
            self.assertTrue(ok, reason)
            # Change the annotation so the entry no longer matches: the
            # cache must notice the edit (mtime/size) and re-parse, not
            # serve the stale tree that still validates.
            module.write_text(
                "from __future__ import annotations\n\n\n"
                "def f(x: float | int) -> float | int:\n"
                "    return x\n"
            )
            ok, reason = runner.validate_baseline_entry(entry, root)
            self.assertFalse(ok, "edited module must re-validate against the new source")
            self.assertIn("annotation text changed", reason)
        runner._clear_module_context_cache()

    def test_unreachable_condition_mutants_accepted(self):
        """Survivors matching re-validated runtime entries are accepted (exit 0)."""
        runtime = [e for e in self.baseline["entries"] if e["kind"] == "unreachable-condition"]
        self.assertEqual(len(runtime), 3)
        records = [self._record_for_entry(e, "survived") for e in runtime]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["surviving"], 3)
        self.assertEqual(summary["equivalent"], 3)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_domain_equivalent_mutants_accepted(self):
        """Survivors matching re-validated domain-equivalent entries are accepted (exit 0)."""
        runtime = [e for e in self.baseline["entries"] if e["kind"] == "domain-equivalent"]
        self.assertEqual(len(runtime), 561)
        self.assertEqual(
            {e["module"] for e in runtime},
            {
                "textforensics._standalone_verify",
                "textforensics.adversarial",
                "textforensics.analyzers",
                "textforensics.benchmark",
                "textforensics.calibration",
                "textforensics.casefile",
                "textforensics.consensus",
                "textforensics.detectors",
                "textforensics.engine",
                "textforensics.evidence",
                "textforensics.execution_policy",
                "textforensics.explain",
                "textforensics.mixed_origin",
                "textforensics.model_card",
                "textforensics.policy",
                "textforensics.probe_metrics",
                "textforensics.probe_runs",
                "textforensics.report",
                "textforensics.result_codec",
                "textforensics.schema",
                "textforensics.semantic",
                "textforensics.trust",
                "textforensics.validation",
                "textforensics.verify",
            },
        )
        records = [self._record_for_entry(e, "survived") for e in runtime]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["total"], 561)
        self.assertEqual(summary["surviving"], 561)
        self.assertEqual(summary["equivalent"], 561)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_unobservable_value_mutants_accepted(self):
        """Survivors matching re-validated unobservable-value entries are accepted (exit 0)."""
        runtime = [e for e in self.baseline["entries"] if e["kind"] == "unobservable-value"]
        self.assertEqual(len(runtime), 35)
        module_paths = {
            "textforensics.policy": str(self.project_root / "src" / "textforensics" / "policy.py"),
            "textforensics.benchmark": str(
                self.project_root / "src" / "textforensics" / "benchmark.py"
            ),
            "textforensics.consensus": str(
                self.project_root / "src" / "textforensics" / "consensus.py"
            ),
            "textforensics.calibration": str(
                self.project_root / "src" / "textforensics" / "calibration.py"
            ),
            "textforensics.engine": str(self.project_root / "src" / "textforensics" / "engine.py"),
            "textforensics.casefile": str(
                self.project_root / "src" / "textforensics" / "casefile.py"
            ),
            "textforensics._standalone_verify": str(
                self.project_root / "src" / "textforensics" / "_standalone_verify.py"
            ),
            "textforensics.probe_runs": str(
                self.project_root / "src" / "textforensics" / "probe_runs.py"
            ),
            "textforensics.probe_metrics": str(
                self.project_root / "src" / "textforensics" / "probe_metrics.py"
            ),
        }
        records = [
            self._record(
                operator=e["operator"],
                occurrence=e["occurrence"],
                start_pos=e["start_pos"],
                end_pos=e["end_pos"],
                outcome="survived",
                module_path=module_paths[e["module"]],
            )
            for e in runtime
        ]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["total"], 35)
        self.assertEqual(summary["surviving"], 35)
        self.assertEqual(summary["equivalent"], 35)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_occurrence_disambiguates_same_position_mutants(self):
        """Two entries at one position differ only by occurrence — and match only their own mutant.

        L1365:21 in verify_bundle_bytes carries occurrences 486 (`2` ->
        `3`, unobservable-value) and 487 (`2` -> `1`, unobservable-value)
        — the report dict's initial exit_code, overwritten on every path
        before return. A survivor with an occurrence that matches neither
        entry (e.g. a hypothetical `2` -> `0`) must stay unexplained
        even though its position matches both entries.
        (The W1 pair at L628:76, occurrences 50/51, is gone: those trust
        entries were dropped in the W2 refresh, so the test moved to the
        F2 re-proof pair.)
        """
        runtime = {
            e["occurrence"]: e
            for e in self.baseline["entries"]
            if e["kind"] == "unobservable-value"
            and e["module"] == "textforensics._standalone_verify"
            and tuple(e["start_pos"]) == (1365, 21)
        }
        entry_486 = runtime[486]
        entry_487 = runtime[487]
        self.assertEqual(tuple(entry_486["start_pos"]), tuple(entry_487["start_pos"]))
        self.assertEqual(tuple(entry_486["end_pos"]), tuple(entry_487["end_pos"]))

        records = [
            self._record_for_entry(entry_486, "survived"),
            self._record_for_entry(entry_487, "survived"),
            self._record(
                operator="core/NumberReplacer",
                occurrence=99,
                start_pos=(1365, 21),
                end_pos=(1365, 22),
                outcome="survived",
                module_path=str(
                    self.project_root / "src" / "textforensics" / "_standalone_verify.py"
                ),
            ),
        ]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["surviving"], 3)
        self.assertEqual(summary["equivalent"], 2)
        self.assertEqual(summary["equivalent_mutants"], [entry_486["id"], entry_487["id"]])
        self.assertEqual(summary["unexplained_surviving"], 1)
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_stale_runtime_entry_fails_loudly(self):
        """A runtime entry whose function changed fails re-validation (exit 1)."""
        import copy

        runtime = [e for e in self.baseline["entries"] if e["kind"] == "unreachable-condition"]
        cases = {
            "changed fingerprint": (
                "source_fingerprint",
                "0" * 64,
                "fingerprint mismatch",
            ),
            "changed source text": ("source_text", "9", "no longer holds"),
            "changed function": (
                "function",
                "assess_trust_map",
                "enclosing function changed",
            ),
        }
        for name, (field, value, fragment) in cases.items():
            with self.subTest(case=name):
                entry = copy.deepcopy(runtime[0])
                entry[field] = value
                ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
                self.assertFalse(ok, f"{name} must not validate")
                self.assertIn(fragment, reason)

        entry = copy.deepcopy(runtime[0])
        entry["source_fingerprint"] = "0" * 64
        tampered = copy.deepcopy(self.baseline)
        tampered["entries"] = [entry] + [
            e for e in self.baseline["entries"] if e["id"] != entry["id"]
        ]
        records = [self._record_for_entry(entry, "survived")]
        summary = self.runner.parse_results(records, tampered, self.project_root)
        self.assertEqual(len(summary["stale_baseline_entries"]), 1)
        self.assertEqual(summary["stale_baseline_entries"][0]["id"], entry["id"])
        self.assertEqual(summary["unexplained_surviving"], 1)
        self.assertEqual(summary["equivalent"], 0)
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("stale baseline", result.stdout.lower())

    def test_runtime_entry_fields_required(self):
        """Runtime entries need source_text + source_fingerprint; unknown kinds fail."""
        base = (
            "version = 1\n"
            '[[equivalent]]\nid = "x"\nmodule = "textforensics.trust"\n'
            'operator = "core/NumberReplacer"\noccurrence = 39\n'
            'start_pos = [437, 24]\nend_pos = [437, 25]\nfunction = "build_trust_map"\n'
            'reason = "r"\n'
        )
        cases = {
            "runtime entry missing source_text": (
                base + 'kind = "unreachable-condition"\nsource_fingerprint = "' + "0" * 64 + '"\n'
            ),
            "runtime entry missing source_fingerprint": (
                base + 'kind = "unreachable-condition"\nsource_text = "0"\n'
            ),
            "unobservable-value entry missing source_text": (
                base + 'kind = "unobservable-value"\nsource_fingerprint = "' + "0" * 64 + '"\n'
            ),
            "unobservable-value entry missing source_fingerprint": (
                base + 'kind = "unobservable-value"\nsource_text = "0"\n'
            ),
            "domain-equivalent entry missing source_text": (
                base + 'kind = "domain-equivalent"\nsource_fingerprint = "' + "0" * 64 + '"\n'
            ),
            "domain-equivalent entry missing source_fingerprint": (
                base + 'kind = "domain-equivalent"\nsource_text = "0"\n'
            ),
            "ulp-equivalent entry missing source_text": (
                base
                + 'kind = "ulp-equivalent"\nsource_fingerprint = "'
                + "0" * 64
                + '"\nulp_bound_ulps = 2\nswept_domain = "[-20, 20]"\n'
            ),
            "unknown kind": base + 'kind = "magic"\nannotation = "x"\n',
            "annotation entry missing annotation": (base + 'kind = "arg"\n'),
        }
        for name, text in cases.items():
            with (
                self.subTest(case=name),
                tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f,
            ):
                f.write(text)
                temp_path = f.name
            try:
                with self.assertRaises(ValueError):
                    self.runner.load_baseline(Path(temp_path))
            finally:
                Path(temp_path).unlink(missing_ok=True)

    def test_unobservable_value_entry_validates(self):
        """A well-formed "unobservable-value" entry re-validates.

        The entry is built with the runner's own helpers (enclosing
        function + fingerprint from the current policy.py source) at
        the real position of the `2` in `"validated": 2`
        (CapabilityPolicyEngine.evaluate, L657:33) — the dispatch for
        the new runtime kind must accept it exactly like an
        unreachable-condition entry.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 657, 33)
        self.assertEqual(name, "CapabilityPolicyEngine.evaluate")
        entry = {
            "id": "test:unobservable-value",
            "module": "textforensics.policy",
            "operator": "core/NumberReplacer",
            "occurrence": 4,
            "start_pos": [657, 33],
            "end_pos": [657, 34],
            "function": name,
            "kind": "unobservable-value",
            "reason": "synthetic test entry",
            "source_text": "2",
            "source_fingerprint": self.runner._function_fingerprint(source, node),
        }
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"unobservable-value entry must validate: {reason}")

    def _synthetic_domain_equivalent_entry(self):
        """A well-formed synthetic "domain-equivalent" entry.

        Built with the runner's own helpers at the real position of the
        `2` in `"validated": 2` (CapabilityPolicyEngine.evaluate,
        L657:33); the reason names the proof shape (closed-domain value
        identity), as the kind requires.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 657, 33)
        self.assertEqual(name, "CapabilityPolicyEngine.evaluate")
        return {
            "id": "test:domain-equivalent",
            "module": "textforensics.policy",
            "operator": "core/NumberReplacer",
            # 999, not the real mutant's occurrence: the real
            # unobservable-value entry at this position carries
            # occurrence 4, and a synthetic entry sharing its match key
            # would be shadowed by it in classify_baseline.
            "occurrence": 999,
            "start_pos": [657, 33],
            "end_pos": [657, 34],
            "function": name,
            "kind": "domain-equivalent",
            "reason": (
                "closed-domain value identity in CapabilityPolicyEngine.evaluate: "
                "the replacement coincides with the original on every value "
                "the expression can take (source_text 2)"
            ),
            "source_text": "2",
            "source_fingerprint": self.runner._function_fingerprint(source, node),
        }

    def _synthetic_ulp_equivalent_entry(self):
        """A well-formed synthetic "ulp-equivalent" entry.

        Built with the runner's own helpers at the real position of the
        `0.0` in `_sigmoid`'s `if value >= 0.0:` (calibration.py,
        L160:16), with the recorded sweep bound (2 ulps) and domain.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "calibration.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 160, 16)
        self.assertEqual(name, "_sigmoid")
        return {
            "id": "test:ulp-equivalent",
            "module": "textforensics.calibration",
            "operator": "core/ReplaceComparisonOperator_GtE_Gt",
            # 999, as above: keep the synthetic entry's match key clear
            # of every real baseline entry.
            "occurrence": 999,
            "start_pos": [160, 16],
            "end_pos": [160, 19],
            "function": name,
            "kind": "ulp-equivalent",
            "reason": ("at most 2 ulps apart in _sigmoid over the swept domain (source_text 0.0)"),
            "source_text": "0.0",
            "source_fingerprint": self.runner._function_fingerprint(source, node),
            "ulp_bound_ulps": 2,
            "swept_domain": "[-20, 20], 40,000 points",
        }

    def test_domain_equivalent_entry_validates(self):
        """A well-formed "domain-equivalent" entry re-validates.

        The kind reuses `_validate_runtime_entry` exactly (source_text
        + enclosing-function fingerprint + function name), mirroring
        "unobservable-value"; no new fields are required for it.
        """
        entry = self._synthetic_domain_equivalent_entry()
        self.assertNotIn("ulp_bound_ulps", entry)
        self.assertNotIn("swept_domain", entry)
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"domain-equivalent entry must validate: {reason}")

    def test_ulp_equivalent_entry_validates(self):
        """A well-formed "ulp-equivalent" entry re-validates.

        Same runtime pinning as the other runtime kinds, plus the two
        required per-entry fields (bound + swept domain).
        """
        entry = self._synthetic_ulp_equivalent_entry()
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"ulp-equivalent entry must validate: {reason}")

    def test_stale_new_kind_entry_fails_loudly(self):
        """A new-kind entry whose source no longer matches fails (exit 1)."""
        import copy

        for entry in (
            self._synthetic_domain_equivalent_entry(),
            self._synthetic_ulp_equivalent_entry(),
        ):
            with self.subTest(kind=entry["kind"]):
                stale = copy.deepcopy(entry)
                stale["source_fingerprint"] = "0" * 64
                ok, reason = self.runner.validate_baseline_entry(stale, self.project_root)
                self.assertFalse(ok, f"stale {entry['kind']} entry must not validate")
                self.assertIn("fingerprint mismatch", reason)

                tampered = copy.deepcopy(self.baseline)
                tampered["entries"] = [stale] + self.baseline["entries"]
                records = [self._record_for_entry(stale, "survived")]
                summary = self.runner.parse_results(records, tampered, self.project_root)
                self.assertEqual(len(summary["stale_baseline_entries"]), 1)
                self.assertEqual(summary["stale_baseline_entries"][0]["id"], entry["id"])
                self.assertEqual(summary["unexplained_surviving"], 1)
                self.assertEqual(summary["equivalent"], 0)
                result = self._check_summary(summary)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("stale baseline", result.stdout.lower())

    def test_ulp_equivalent_fields_required(self):
        """An "ulp-equivalent" entry without bound/domain is rejected.

        Both at load time (ValueError from `load_baseline`) and at
        re-validation time (a synthetic dict that bypasses the loader
        still fails `validate_baseline_entry`). Other kinds must NOT
        require these fields: a "domain-equivalent" entry without them
        loads and validates (see
        `test_domain_equivalent_entry_validates`).
        """
        import copy
        import tempfile

        base = (
            "version = 1\n"
            '[[equivalent]]\nid = "x"\nmodule = "textforensics.calibration"\n'
            'operator = "core/ReplaceComparisonOperator_GtE_Gt"\noccurrence = 2\n'
            'start_pos = [160, 16]\nend_pos = [160, 19]\nfunction = "_sigmoid"\n'
            'reason = "r"\nsource_text = "0.0"\nsource_fingerprint = "' + "0" * 64 + '"\n'
        )
        cases = {
            "missing ulp_bound_ulps": (
                base + 'kind = "ulp-equivalent"\nswept_domain = "[-20, 20]"\n'
            ),
            "missing swept_domain": (base + 'kind = "ulp-equivalent"\nulp_bound_ulps = 2\n'),
            "negative bound": (
                base
                + 'kind = "ulp-equivalent"\nulp_bound_ulps = -1\n'
                + 'swept_domain = "[-20, 20]"\n'
            ),
            "non-integer bound": (
                base
                + 'kind = "ulp-equivalent"\nulp_bound_ulps = "2"\n'
                + 'swept_domain = "[-20, 20]"\n'
            ),
            "empty swept_domain": (
                base + 'kind = "ulp-equivalent"\nulp_bound_ulps = 2\n' + 'swept_domain = ""\n'
            ),
        }
        for name, text in cases.items():
            with (
                self.subTest(case=name),
                tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f,
            ):
                f.write(text)
                temp_path = f.name
            try:
                with self.assertRaises(ValueError, msg=name):
                    self.runner.load_baseline(Path(temp_path))
            finally:
                Path(temp_path).unlink(missing_ok=True)

        # Re-validation rejects them too, even without the loader.
        entry = self._synthetic_ulp_equivalent_entry()
        tampered_cases = {
            "missing ulp_bound_ulps": ("ulp_bound_ulps", None),
            "missing swept_domain": ("swept_domain", None),
            "negative bound": ("ulp_bound_ulps", -1),
            "non-integer bound": ("ulp_bound_ulps", "2"),
            "boolean bound": ("ulp_bound_ulps", True),
            "empty swept_domain": ("swept_domain", ""),
        }
        for name, (field, value) in tampered_cases.items():
            with self.subTest(case=name):
                tampered = copy.deepcopy(entry)
                if value is None:
                    del tampered[field]
                else:
                    tampered[field] = value
                ok, reason = self.runner.validate_baseline_entry(tampered, self.project_root)
                self.assertFalse(ok, f"{name} must not validate")
                self.assertIn(field, reason)

    def test_ulp_equivalent_zero_bound_accepted(self):
        """An "ulp-equivalent" entry with bound 0 loads and validates.

        A bound of 0 is a measured value — no observed difference over
        the swept domain (e.g. the `_sigmoid` `>=` -> `>` mutant, whose
        two branches compute exactly 0.5 at value == 0.0) — not a
        missing bound. Both at load time (no ValueError from
        `load_baseline`) and at re-validation time
        (`validate_baseline_entry` on a synthetic dict).
        """
        import tempfile

        text = (
            "version = 1\n"
            '[[equivalent]]\nid = "x"\nmodule = "textforensics.calibration"\n'
            'operator = "core/ReplaceComparisonOperator_GtE_Gt"\noccurrence = 2\n'
            'start_pos = [160, 16]\nend_pos = [160, 19]\nfunction = "_sigmoid"\n'
            'reason = "r"\nsource_text = "0.0"\nsource_fingerprint = "' + "0" * 64 + '"\n'
            'kind = "ulp-equivalent"\nulp_bound_ulps = 0\n'
            'swept_domain = "[-20, 20]"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(text)
            temp_path = f.name
        try:
            baseline = self.runner.load_baseline(Path(temp_path))
        finally:
            Path(temp_path).unlink(missing_ok=True)
        self.assertEqual(len(baseline["entries"]), 1)
        self.assertEqual(baseline["entries"][0]["ulp_bound_ulps"], 0)

        # Re-validation accepts it too.
        entry = self._synthetic_ulp_equivalent_entry()
        entry["ulp_bound_ulps"] = 0
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"bound-0 ulp-equivalent entry must validate: {reason}")

    def test_incompetent_with_worker_exception_is_not_an_error(self):
        """A worker exception with test_outcome "incompetent" parses as incompetent.

        Regression test for the calibration prefix error-1: cosmic-ray
        8.7.0's ExceptionReplacer crashed inside the operator (before
        any mutant code existed), arriving as worker_outcome="exception"
        with test_outcome="incompetent". There is no behaviour to kill
        or baseline, so it must not count as an error — but a worker
        exception with any other test_outcome stays an error.
        """
        incompetent = self._record(
            operator="core/ExceptionReplacer",
            occurrence=5,
            start_pos=(727, 10),
            end_pos=(727, 20),
            outcome="incompetent",
        )
        incompetent["result"]["worker_outcome"] = "exception"
        summary = self.runner.parse_results([incompetent], self.baseline, self.project_root)
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["incompetent"], 1)
        self.assertEqual(summary["error"], 0)
        self.assertEqual(summary["killed"], 0)
        self.assertEqual(summary["surviving"], 0)

        for outcome in ("killed", "survived", "timeout"):
            with self.subTest(outcome=outcome):
                record = self._record(
                    operator="core/ExceptionReplacer",
                    occurrence=5,
                    start_pos=(727, 10),
                    end_pos=(727, 20),
                    outcome=outcome,
                )
                record["result"]["worker_outcome"] = "exception"
                summary = self.runner.parse_results([record], self.baseline, self.project_root)
                self.assertEqual(summary["error"], 1, f"{outcome} + exception must stay an error")
                self.assertEqual(summary["incompetent"], 0)

    def test_decorator_position_entry_validates(self):
        """A runtime entry on a decorator line re-validates.

        The `4` in `@lru_cache(maxsize=4)` (L821:19) sits on the
        decorator line, above the `def` line: the enclosing-function
        lookup and the function fingerprint must both cover the
        decorator, or the entry for it could never validate.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 821, 19)
        self.assertEqual(name, "_load_enterprise_policy_schema")
        entry = {
            "id": "test:decorator-position",
            "module": "textforensics.policy",
            "operator": "core/NumberReplacer",
            "occurrence": 22,
            "start_pos": [821, 19],
            "end_pos": [821, 20],
            "function": name,
            "kind": "unobservable-value",
            "reason": "synthetic test entry",
            "source_text": "4",
            "source_fingerprint": self.runner._function_fingerprint(source, node),
        }
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"decorator-position entry must validate: {reason}")
        # The fingerprint pins the decorator: changing maxsize must
        # change the fingerprint.
        changed = source.replace("@lru_cache(maxsize=4)", "@lru_cache(maxsize=9)", 1)
        changed_tree = ast.parse(changed)
        _, changed_node = self.runner._enclosing_function(changed_tree, 821, 19)
        self.assertNotEqual(
            self.runner._function_fingerprint(changed, changed_node),
            entry["source_fingerprint"],
        )

    def test_malformed_baseline_rejected(self):
        """Wrong version / missing field / duplicate id fail loudly at load."""
        cases = {
            "wrong version": "version = 2\n",
            "missing field": (
                'version = 1\n[[equivalent]]\nid = "x"\nmodule = "textforensics.trust"\n'
            ),
            "duplicate id": (
                "version = 1\n"
                '[[equivalent]]\nid = "dup"\nmodule = "textforensics.trust"\n'
                'operator = "core/ReplaceBinaryOperator_BitOr_Add"\noccurrence = 0\n'
                'start_pos = [130, 53]\nend_pos = [130, 54]\nfunction = "TrustMap.dimension"\n'
                'kind = "return"\nannotation = "TrustDimension | None"\nreason = "r"\n'
                '[[equivalent]]\nid = "dup"\nmodule = "textforensics.trust"\n'
                'operator = "core/ReplaceBinaryOperator_BitOr_BitAnd"\noccurrence = 0\n'
                'start_pos = [130, 53]\nend_pos = [130, 54]\nfunction = "TrustMap.dimension"\n'
                'kind = "return"\nannotation = "TrustDimension | None"\nreason = "r"\n'
            ),
        }
        for name, text in cases.items():
            with (
                self.subTest(case=name),
                tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f,
            ):
                f.write(text)
                temp_path = f.name
            try:
                with self.assertRaises(ValueError):
                    self.runner.load_baseline(Path(temp_path))
            finally:
                Path(temp_path).unlink(missing_ok=True)

    def test_explicit_missing_baseline_file_fails(self):
        """--baseline pointing at a missing file fails loudly (exit 1)."""
        result = subprocess.run(
            [
                sys.executable,
                str(self.project_root / "scripts" / "run_mutation.py"),
                "--baseline",
                "/tmp/definitely-not-a-baseline.toml",
                "--mode",
                "diff",
                "--base-sha",
                "HEAD",
            ],
            capture_output=True,
            text=True,
            cwd=self.project_root,
            timeout=60,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Baseline file not found", result.stderr)


class MutationWorkflowTests(unittest.TestCase):
    """Test that the workflow and the runner agree (defects 1–3 regressions)."""

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).parent.parent
        cls.workflow = cls.project_root / ".github" / "workflows" / "mutation.yml"
        cls.runner = _load_runner(cls.project_root / "scripts" / "run_mutation.py")

    def test_workflow_module_filter_matches_runner(self):
        """The workflow grep list must match run_mutation.py target_modules."""
        import yaml

        with open(self.workflow) as f:
            workflow = yaml.safe_load(f)
        get_changed = next(
            s
            for s in workflow["jobs"]["mutation-diff"]["steps"]
            if s["name"] == "Get changed files"
        )
        script = get_changed["run"]
        for module in self.runner.TARGET_MODULES:
            stem = module.split(".")[-1]
            self.assertIn(stem, script, f"Workflow filter omits target module {module}")
        for stale in ("threshold_selection", "robustness"):
            self.assertNotIn(stale, script, f"Workflow filter still lists stale module {stale}")

    def test_workflow_writes_changed_files_output(self):
        """The Get changed files step must write changed_files to $GITHUB_OUTPUT."""
        import yaml

        with open(self.workflow) as f:
            workflow = yaml.safe_load(f)
        get_changed = next(
            s
            for s in workflow["jobs"]["mutation-diff"]["steps"]
            if s["name"] == "Get changed files"
        )
        script = get_changed["run"]
        self.assertIn("changed_files<<EOF", script)
        self.assertIn("$GITHUB_OUTPUT", script)

    def test_workflow_push_base_is_event_before(self):
        """Push events must diff against github.event.before, not origin/main."""
        import yaml

        with open(self.workflow) as f:
            workflow = yaml.safe_load(f)
        get_changed = next(
            s
            for s in workflow["jobs"]["mutation-diff"]["steps"]
            if s["name"] == "Get changed files"
        )
        script = get_changed["run"]
        self.assertIn("github.event.before", script)
        self.assertNotIn('BASE_SHA="origin/main"', script)
        self.assertIn("github.event.pull_request.base.sha", script)

    def test_workflow_no_mutation_summary_has_marker(self):
        """The No mutation needed step must write the skipped_reason marker."""
        import yaml

        with open(self.workflow) as f:
            workflow = yaml.safe_load(f)
        no_mutation = next(
            s
            for s in workflow["jobs"]["mutation-diff"]["steps"]
            if s["name"] == "No mutation needed"
        )
        self.assertIn("no-relevant-changes", no_mutation["run"])


if __name__ == "__main__":
    unittest.main()
