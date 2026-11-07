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
        self.assertEqual(scoped, "python -m pytest tests/test_trust.py -x -q")
        # A module without a dedicated test file falls back to the full suite.
        full = self.runner.test_command_for(["textforensics.policy"], self.project_root)
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
        ]

        for module in target_modules:
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-c", f"import {module}"],
                    capture_output=True,
                    text=True,
                    cwd=self.project_root,
                )
                self.assertEqual(
                    result.returncode, 0, f"Failed to import {module}: {result.stderr}"
                )


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
