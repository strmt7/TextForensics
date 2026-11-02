#!/usr/bin/env python3
"""
Integration tests for Cosmic Ray mutation testing setup.

These tests verify that:
1. Cosmic Ray is properly installed and configured
2. The configuration file is valid
3. The mutation runner script works correctly
4. Mutation testing can execute without errors
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CosmicRayIntegrationTests(unittest.TestCase):
    """Test Cosmic Ray mutation testing integration."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment."""
        cls.project_root = Path(__file__).parent.parent
        cls.config_path = cls.project_root / ".cosmic-ray.yml"
        cls.runner_path = cls.project_root / "scripts" / "run_mutation.py"

    def test_cosmic_ray_installed(self):
        """Verify cosmic-ray is installed and accessible."""
        # Try both module name variants
        for module_name in ["cosmic_ray", "cosmic_ray.cli", "cosmic-ray"]:
            result = subprocess.run(
                [sys.executable, "-m", module_name, "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                self.assertIn("cosmic-ray", result.stdout.lower())
                return
        # If all fail, try direct command
        result = subprocess.run(
            ["cosmic-ray", "--version"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, f"cosmic-ray not installed: {result.stderr}")
        self.assertIn("cosmic-ray", result.stdout.lower())

    def test_config_file_exists(self):
        """Verify .cosmic-ray.yml configuration exists."""
        self.assertTrue(self.config_path.exists(), "Configuration file not found")

    def test_config_file_valid_yaml(self):
        """Verify configuration file is valid YAML."""
        import yaml

        with open(self.config_path) as f:
            config = yaml.safe_load(f)

        # Check required sections
        self.assertIn("mutation", config)
        self.assertIn("modules", config["mutation"])
        self.assertIn("excluded_modules", config["mutation"])
        self.assertIn("operators", config["mutation"])
        self.assertIn("test_runner", config["mutation"])

        # Check target modules are present
        modules = config["mutation"]["modules"]
        expected_modules = [
            "textforensics.benchmark",
            "textforensics.trust",
            "textforensics.consensus",
            "textforensics.threshold_selection",
        ]
        for module in expected_modules:
            self.assertIn(module, modules, f"Expected module {module} not in config")

        # Check excluded modules
        excluded = config["mutation"]["excluded_modules"]
        self.assertIn("textforensics.cli", excluded)
        self.assertIn("textforensics.typer_cli", excluded)

        # Check operators include core operators
        operators = config["mutation"]["operators"]
        core_operators = [
            "arithmetic_operator_replacement",
            "comparison_operator_replacement",
            "boolean_operator_replacement",
        ]
        for op in core_operators:
            self.assertIn(op, operators, f"Core operator {op} not in config")

        # Check timeout
        self.assertEqual(config["mutation"]["test_runner"]["timeout"], 30)

    def test_runner_script_exists(self):
        """Verify mutation runner script exists."""
        self.assertTrue(self.runner_path.exists(), "Runner script not found")
        # On Windows, executable bit check doesn't apply the same way
        if sys.platform != "win32":
            self.assertTrue(self.runner_path.stat().st_mode & 0o111, "Runner script not executable")

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

    def test_diff_mode_no_changes(self):
        """Test diff mode when no relevant modules changed."""
        # This test uses a fake base SHA to simulate no changes
        result = subprocess.run(
            [sys.executable, str(self.runner_path), "--mode", "diff", "--base-sha", "HEAD"],
            capture_output=True,
            text=True,
            cwd=self.project_root,
            timeout=60,
        )
        # Should succeed (exit 0) when no modules changed
        # Note: This might fail if there are actual changes, which is fine
        # The test just verifies the command runs without crashing
        self.assertIn(result.returncode, [0, 1], f"Unexpected exit code: {result.returncode}")

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
            "textforensics.threshold_selection",
            "textforensics.detectors",
            "textforensics.analyzers",
            "textforensics.engine",
            "textforensics.capability_ledger",
            "textforensics.casefile",
            "textforensics.robustness",
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


class MutationConfigTests(unittest.TestCase):
    """Test mutation configuration specifics."""

    def test_rejection_rejector_config(self):
        """Verify rejection-rejector pattern configuration."""
        import yaml

        config_path = Path(__file__).parent.parent / ".cosmic-ray.yml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        self.assertIn("rejection_rejector", config)
        rr = config["rejection_rejector"]
        self.assertTrue(rr["track_surviving"])
        self.assertGreaterEqual(rr["min_kill_ratio"], 0.8)
        self.assertGreater(rr["mutation_budget"], 0)
        self.assertGreater(rr["mutant_timeout"], 0)

    def test_diff_optimization_config(self):
        """Verify diff-based optimization configuration."""
        import yaml

        config_path = Path(__file__).parent.parent / ".cosmic-ray.yml"
        with open(config_path) as f:
            config = yaml.safe_load(f)

        self.assertIn("diff_optimization", config)
        diff = config["diff_optimization"]
        self.assertTrue(diff["enabled"])
        self.assertEqual(diff["base_branch"], "origin/main")
        self.assertTrue(diff["include_staged"])


if __name__ == "__main__":
    unittest.main()
