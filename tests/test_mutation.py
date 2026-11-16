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
            "tests/test_audit_w2_worker_a.py tests/test_audit_w2_worker_f_trust.py -x -q",
        )
        # Policy tests live in test_enterprise_policy.py, not test_policy.py;
        # the override map scopes them instead of falling back to the full
        # suite (whose ~3-minute runtime exceeds the per-test-run timeout
        # and fails the cosmic-ray baseline before any mutant runs).
        policy = self.runner.test_command_for(["textforensics.policy"], self.project_root)
        self.assertEqual(
            policy,
            "python -m pytest tests/test_enterprise_policy.py "
            "tests/test_execution_policy.py tests/test_audit_w2_worker_a.py "
            "tests/test_audit_w2_worker_f_policy.py "
            "tests/test_audit_w4_worker_f_policy.py -x -q",
        )
        # W2 worker test files are part of the per-mutant command for the
        # modules they cover (audit-w2-f §10 follow-up).
        casefile = self.runner.test_command_for(["textforensics.casefile"], self.project_root)
        self.assertEqual(
            casefile,
            "python -m pytest tests/test_casefile.py tests/test_w1_worker_d.py "
            "tests/test_casefile_v3.py tests/test_casefile_v4.py "
            "tests/test_audit_w2_worker_f_casefile.py "
            "tests/test_audit_w3_worker_b.py "
            "tests/test_audit_w3_worker_f_casefile.py -x -q",
        )
        probe_runs = self.runner.test_command_for(["textforensics.probe_runs"], self.project_root)
        self.assertEqual(
            probe_runs,
            "python -m pytest tests/test_probe_runs.py tests/test_w2_worker_d.py "
            "tests/test_audit_w2_worker_f_probe_runs.py "
            "tests/test_audit_w4_worker_f_probe_runs.py "
            "tests/test_audit_w5_worker_f_probe_runs.py -x -q",
        )
        verify = self.runner.test_command_for(["textforensics.verify"], self.project_root)
        self.assertEqual(
            verify,
            "python -m pytest tests/test_verify.py tests/test_casefile_v3.py "
            "tests/test_verify_consolidation.py "
            "tests/test_audit_w2_worker_f_verify.py "
            "tests/test_audit_w3_worker_b.py tests/test_audit_w3_worker_c.py "
            "tests/test_audit_w3_worker_f_verify.py "
            "tests/test_audit_w3_worker_f4_verify.py -x -q",
        )
        adversarial = self.runner.test_command_for(["textforensics.adversarial"], self.project_root)
        self.assertEqual(
            adversarial,
            "python -m pytest tests/test_adversarial.py tests/test_w2_worker_e_if12.py "
            "tests/test_audit_w2_worker_f_adversarial.py -x -q",
        )
        # The W2 kill-test files are part of the per-mutant command for
        # every module they cover (audit-w2 decision (c.1)); modules
        # without a prior map entry get one (dedicated file + kill tests).
        calibration = self.runner.test_command_for(["textforensics.calibration"], self.project_root)
        self.assertEqual(
            calibration,
            "python -m pytest tests/test_calibration.py "
            "tests/test_audit_w2_worker_f_calibration.py "
            "tests/test_audit_w4_worker_f_calibration.py -x -q",
        )
        benchmark = self.runner.test_command_for(["textforensics.benchmark"], self.project_root)
        self.assertEqual(
            benchmark,
            "python -m pytest tests/test_benchmark.py "
            "tests/test_audit_w2_worker_f_benchmark.py -x -q",
        )
        validation = self.runner.test_command_for(["textforensics.validation"], self.project_root)
        self.assertEqual(
            validation,
            "python -m pytest tests/test_validation.py "
            "tests/test_audit_w2_worker_f_validation.py -x -q",
        )
        report = self.runner.test_command_for(["textforensics.report"], self.project_root)
        self.assertEqual(
            report,
            "python -m pytest tests/test_report.py tests/test_audit_w2_worker_f_report.py "
            "tests/test_audit_w5_worker_f_report.py -x -q",
        )
        mixed_origin = self.runner.test_command_for(
            ["textforensics.mixed_origin"], self.project_root
        )
        self.assertEqual(
            mixed_origin,
            "python -m pytest tests/test_mixed_origin.py "
            "tests/test_audit_w2_worker_f_mixed_origin.py -x -q",
        )
        schema = self.runner.test_command_for(["textforensics.schema"], self.project_root)
        self.assertEqual(
            schema,
            "python -m pytest tests/test_schema.py tests/test_audit_w2_worker_f_schema.py -x -q",
        )
        standalone_verify = self.runner.test_command_for(
            ["textforensics._standalone_verify"], self.project_root
        )
        self.assertEqual(
            standalone_verify,
            "python -m pytest tests/test_standalone_verify.py "
            "tests/test_audit_w2_worker_f__standalone_verify.py "
            "tests/test_audit_w3_worker_f__standalone_verify.py -x -q",
        )
        probe_metrics = self.runner.test_command_for(
            ["textforensics.probe_metrics"], self.project_root
        )
        self.assertEqual(
            probe_metrics,
            "python -m pytest tests/test_probe_metrics.py tests/test_w2_worker_d.py "
            "tests/test_audit_w2_worker_f_probe_metrics.py -x -q",
        )
        model_card = self.runner.test_command_for(["textforensics.model_card"], self.project_root)
        self.assertEqual(
            model_card,
            "python -m pytest tests/test_model_card.py tests/test_w2_worker_d.py "
            "tests/test_audit_w2_worker_f_model_card.py -x -q",
        )
        result_codec = self.runner.test_command_for(
            ["textforensics.result_codec"], self.project_root
        )
        self.assertEqual(
            result_codec,
            "python -m pytest tests/test_result_codec.py tests/test_w2_worker_d.py "
            "tests/test_audit_w2_worker_f_result_codec.py "
            "tests/test_audit_w3_worker_f_result_codec.py "
            "tests/test_audit_w5_worker_f_result_codec.py -x -q",
        )
        # W3 kill-test files are part of the per-mutant command for the
        # modules they cover (audit-w3): watermarking, ledger and
        # timestamp each get their W3 kill-test file.
        watermarking = self.runner.test_command_for(
            ["textforensics.watermarking"], self.project_root
        )
        self.assertEqual(
            watermarking,
            "python -m pytest tests/test_watermarking.py "
            "tests/test_audit_w3_worker_f_watermarking.py -x -q",
        )
        ledger = self.runner.test_command_for(["textforensics.ledger"], self.project_root)
        self.assertEqual(
            ledger,
            "python -m pytest tests/test_audit_log.py tests/test_audit_w3_worker_f_ledger.py "
            "tests/test_audit_w4_worker_f_ledger.py "
            "tests/test_audit_w6_worker_f_ledger.py -x -q",
        )
        # Ledger deliberately does NOT scope to test_audit_anchor.py:
        # its 9 C08/C09 tests are red by design for W4 (audit-w3).
        # The W4 kill-test files are part of the per-mutant command for
        # the modules they cover (audit-w4-f2): cli, detection_cache,
        # emergency_stop, retry and workspace_integrity each get a new
        # map entry (dedicated file + W4 kill-test file).
        cli = self.runner.test_command_for(["textforensics.cli"], self.project_root)
        self.assertEqual(
            cli,
            "python -m pytest tests/test_cli.py tests/test_audit_w4_worker_f_cli.py "
            "tests/test_audit_w5_worker_f_cli.py -x -q",
        )
        detection_cache = self.runner.test_command_for(
            ["textforensics.detection_cache"], self.project_root
        )
        self.assertEqual(
            detection_cache,
            "python -m pytest tests/test_detection_cache.py "
            "tests/test_audit_w4_worker_f_detection_cache.py -x -q",
        )
        emergency_stop = self.runner.test_command_for(
            ["textforensics.emergency_stop"], self.project_root
        )
        self.assertEqual(
            emergency_stop,
            "python -m pytest tests/test_emergency_stop.py "
            "tests/test_audit_w4_worker_f_emergency_stop.py -x -q",
        )
        retry = self.runner.test_command_for(["textforensics.retry"], self.project_root)
        self.assertEqual(
            retry,
            "python -m pytest tests/test_retry.py tests/test_audit_w4_worker_f_retry.py -x -q",
        )
        workspace_integrity = self.runner.test_command_for(
            ["textforensics.workspace_integrity"], self.project_root
        )
        self.assertEqual(
            workspace_integrity,
            "python -m pytest tests/test_workspace_integrity.py "
            "tests/test_audit_w4_worker_f_workspace_integrity.py -x -q",
        )
        timestamp = self.runner.test_command_for(["textforensics.timestamp"], self.project_root)
        self.assertEqual(
            timestamp,
            "python -m pytest tests/test_timestamp.py "
            "tests/test_audit_w3_worker_c.py "
            "tests/test_audit_w3_worker_f_timestamp.py -x -q",
        )
        bundle = self.runner.test_command_for(["textforensics.bundle"], self.project_root)
        self.assertEqual(
            bundle,
            "python -m pytest tests/test_bundle.py "
            "tests/test_audit_w3_worker_c.py "
            "tests/test_audit_w3_worker_f_bundle.py "
            "tests/test_audit_w6_worker_f_bundle.py -x -q",
        )
        sealing = self.runner.test_command_for(["textforensics.sealing"], self.project_root)
        self.assertEqual(
            sealing,
            "python -m pytest tests/test_sealing.py "
            "tests/test_audit_w3_worker_b.py "
            "tests/test_audit_w3_worker_f_sealing.py -x -q",
        )
        sealed_bundle = self.runner.test_command_for(
            ["textforensics.sealed_bundle"], self.project_root
        )
        self.assertEqual(
            sealed_bundle,
            "python -m pytest tests/test_sealed_bundle.py "
            "tests/test_audit_w3_worker_c.py "
            "tests/test_audit_w3_worker_f_sealed_bundle.py "
            "tests/test_audit_w6_worker_f_sealed_bundle.py -x -q",
        )
        semantic = self.runner.test_command_for(["textforensics.semantic"], self.project_root)
        # Datasets gets its entry with the F4 re-proof (audit-w3-f4):
        # the W1 DetectRLX / Core-09 tests in test_w1_worker_d.py and
        # the F4 kill tests are part of the per-mutant command.
        datasets = self.runner.test_command_for(["textforensics.datasets"], self.project_root)
        self.assertEqual(
            datasets,
            "python -m pytest tests/test_datasets.py tests/test_w1_worker_d.py "
            "tests/test_audit_w3_worker_f4_datasets.py "
            "tests/test_audit_w4_worker_f_datasets.py "
            "tests/test_audit_w6_worker_f_datasets.py -x -q",
        )
        self.assertEqual(
            semantic,
            "python -m pytest tests/test_semantic.py tests/test_w2_worker_e_if12.py "
            "tests/test_audit_w2_worker_f_semantic.py -x -q",
        )
        explain = self.runner.test_command_for(["textforensics.explain"], self.project_root)
        self.assertEqual(
            explain,
            "python -m pytest tests/test_explain.py tests/test_w2_worker_e_if19.py "
            "tests/test_audit_w2_worker_f_explain.py -x -q",
        )
        # The W5 kill-test files are part of the per-mutant command for
        # the modules they cover (audit-w5-f): atomic_io,
        # bundle_consistency, diagnostics, mcp_server, ollama,
        # probe_corpus and rich_output each get a new map entry (the
        # files the W5 proof driver ran for the module, plus its W5
        # kill-test file); cli, probe_runs, report and result_codec
        # get their W5 file appended above.
        atomic_io = self.runner.test_command_for(["textforensics.atomic_io"], self.project_root)
        self.assertEqual(
            atomic_io,
            "python -m pytest tests/test_audit_w5_worker_d.py tests/test_model_card.py "
            "tests/test_drift.py tests/test_detector_health.py tests/test_probe_corpus.py "
            "tests/test_result_codec.py tests/test_probe_runs.py "
            "tests/test_audit_w5_worker_f_atomic_io.py -x -q",
        )
        bundle_consistency = self.runner.test_command_for(
            ["textforensics.bundle_consistency"], self.project_root
        )
        self.assertEqual(
            bundle_consistency,
            "python -m pytest tests/test_audit_w5_worker_a.py tests/test_bundle_consistency.py "
            "tests/test_bundle_consistency_properties.py "
            "tests/test_audit_w5_worker_f_bundle_consistency.py -x -q",
        )
        diagnostics = self.runner.test_command_for(["textforensics.diagnostics"], self.project_root)
        self.assertEqual(
            diagnostics,
            "python -m pytest tests/test_diagnostics.py tests/test_w5_worker_c_if17.py "
            "tests/test_audit_w5_worker_f_diagnostics.py -x -q",
        )
        mcp_server = self.runner.test_command_for(["textforensics.mcp_server"], self.project_root)
        self.assertEqual(
            mcp_server,
            "python -m pytest tests/test_emergency_stop.py tests/test_mcp.py "
            "tests/test_w1_consent_stop.py tests/test_w5_worker_c_if16.py "
            "tests/test_audit_w5_worker_f_mcp_server.py -x -q",
        )
        ollama = self.runner.test_command_for(["textforensics.ollama"], self.project_root)
        self.assertEqual(
            ollama,
            "python -m pytest tests/test_audit_w5_worker_b_ollama.py tests/test_casefile_v4.py "
            "tests/test_ollama.py tests/test_w1_ollama_transport.py "
            "tests/test_audit_w5_worker_f_ollama.py -x -q",
        )
        probe_corpus = self.runner.test_command_for(
            ["textforensics.probe_corpus"], self.project_root
        )
        self.assertEqual(
            probe_corpus,
            "python -m pytest tests/test_audit_w5_worker_d.py tests/test_probe_corpus.py "
            "tests/test_audit_w5_worker_f_probe_corpus.py -x -q",
        )
        rich_output = self.runner.test_command_for(["textforensics.rich_output"], self.project_root)
        self.assertEqual(
            rich_output,
            "python -m pytest tests/test_rich_output.py tests/test_w5_worker_c_if18.py "
            "tests/test_audit_w5_worker_f_rich_output.py -x -q",
        )
        # The W6 kill-test files are part of the per-mutant command for
        # the modules they cover (audit-w6-f): detectors gets its W6
        # Worker E file (CC-17) plus its W6 kill-test file, and
        # _build_info gets a new map entry (the files the W6 proof
        # driver ran for it, plus its W6 kill-test file).
        detectors = self.runner.test_command_for(["textforensics.detectors"], self.project_root)
        self.assertEqual(
            detectors,
            "python -m pytest tests/test_detectors.py tests/test_w1_consent_stop.py "
            "tests/test_audit_w6_worker_e.py "
            "tests/test_audit_w6_worker_f_detectors.py -x -q",
        )
        build_info = self.runner.test_command_for(["textforensics._build_info"], self.project_root)
        self.assertEqual(
            build_info,
            "python -m pytest tests/test_audit_w6_b_build_identity.py "
            "tests/test_schema_version.py tests/test_version_extra.py "
            "tests/test_w5_worker_c_if17.py "
            "tests/test_audit_w6_worker_f__build_info.py -x -q",
        )
        # web_ui.main is deliberately NOT in _MODULE_TEST_FILES: the W5
        # proof driver's command for it needs node-level scoping which
        # the map cannot express, so it still falls back to the full
        # suite (which collects its W5 kill-test file).
        web_ui_main = self.runner.test_command_for(["textforensics.web_ui.main"], self.project_root)
        self.assertEqual(web_ui_main, "python -m pytest tests/ -x -q --tb=short")
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

    #: The 1315 distinct start positions of the 6938 baseline entries,
    #: grouped by module (1319 grouped lines; 4 positions are shared
    #: across modules and collapse in the set). Re-derived from the
    #: resolved baseline; the W1 refresh (956 entries re-derived on
    #: audit-w1 head 0da6013) moved 137 of the 278 pre-W1 positions,
    #: and the W1 proof added 40 new ones (execution_policy is new;
    #: the rest are new annotation/runtime sites in the changed W1
    #: functions). The W2 refresh (1425 entries re-derived on
    #: audit-w2 head 739efc0) and the W2 proof (2179 appended) took
    #: the set to 669 positions over 25 modules; the F2 re-proof
    #: append (214 entries) took it to 810. The W2 defect-fix repair
    #: (421 entries re-derived by F2-anchored site pairing) and
    #: targeted-proof append (16 entries) took it to 812. The W3
    #: F2 refresh dropped 47 entries (4362 -> 4315) and the W3 F3
    #: re-proof appends (647 entries across the 10 W3 modules)
    #: took it to 983 positions over 31 modules. The W3 F4 refresh
    #: (204 entries re-derived on the rebased head f856cd0, 0
    #: dropped) and the F4 datasets re-proof append (31 entries)
    #: took it to 992 positions over 32 modules
    #: (datasets is new). The W4 refresh (1292 entries re-derived
    #: on the audit-w4 head 85d75d9, 42 dropped) and the F2
    #: re-proof append (1210 entries across the 11 W4 modules)
    #: took it to 1190 positions over 37 modules
    #: (cli, detection_cache, emergency_stop, retry and
    #: workspace_integrity are new). The W5 refresh (1097 entries
    #: re-derived on the audit-w5 head 068ecf8, 45 dropped) and the
    #: F re-proof append (464 entries across the 14 W5 modules)
    #: took it to 1259 positions over 43 modules
    #: (atomic_io, bundle_consistency, diagnostics, ollama,
    #: rich_output and web_ui.main are new). The W6 refresh (1616 entries
    #: re-derived on the audit-w6 head 5db75e1, 5 dropped) and the
    #: F re-proof append (363 entries across the 9 W6 modules)
    #: took it to 1315 positions over 44 modules
    #: (_build_info is new).
    EXPECTED_POSITIONS = {
        # textforensics._build_info (32 positions).
        (71, 33),
        (71, 56),
        (90, 45),
        (98, 20),
        (105, 41),
        (125, 30),
        (127, 11),
        (128, 26),
        (135, 20),
        (145, 20),
        (147, 48),
        (154, 49),
        (183, 45),
        (215, 76),
        (240, 39),
        (258, 39),
        (263, 43),
        (273, 40),
        (273, 52),
        (274, 7),
        (274, 12),
        (277, 7),
        (280, 20),
        (281, 15),
        (281, 45),
        (284, 15),
        (284, 43),
        (291, 50),
        (326, 45),
        (326, 78),
        (437, 47),
        (521, 41),
        # textforensics._standalone_verify (87 positions).
        (136, 24),
        (136, 72),
        (140, 21),
        (140, 38),
        (143, 24),
        (144, 20),
        (144, 68),
        (148, 17),
        (148, 34),
        (150, 17),
        (180, 23),
        (202, 73),
        (933, 27),
        (936, 37),
        (941, 43),
        (946, 57),
        (958, 16),
        (959, 20),
        (965, 28),
        (966, 25),
        (972, 27),
        (985, 32),
        (993, 54),
        (994, 55),
        (999, 27),
        (1003, 36),
        (1003, 39),
        (1008, 54),
        (1011, 12),
        (1011, 23),
        (1022, 22),
        (1026, 43),
        (1027, 11),
        (1030, 23),
        (1037, 20),
        (1039, 78),
        (1041, 20),
        (1042, 11),
        (1050, 15),
        (1052, 44),
        (1053, 34),
        (1064, 15),
        (1067, 36),
        (1067, 48),
        (1071, 25),
        (1079, 25),
        (1079, 41),
        (1082, 31),
        (1082, 33),
        (1084, 43),
        (1085, 39),
        (1638, 43),
        (1688, 30),
        (1707, 21),
        (1738, 32),
        (1738, 62),
        (1795, 13),
        (1808, 23),
        (1809, 73),
        (1818, 24),
        (1819, 85),
        (1830, 36),
        (1842, 35),
        (1844, 33),
        (1846, 34),
        (1847, 36),
        (1883, 34),
        (1888, 38),
        (1892, 46),
        (1893, 20),
        (1895, 74),
        (1895, 76),
        (1896, 52),
        (1909, 30),
        (1981, 32),
        (1982, 91),
        (1987, 22),
        (2101, 34),
        (2135, 30),
        (2230, 24),
        (2230, 36),
        (2335, 24),
        (2335, 36),
        (2382, 27),
        (2384, 29),
        (2386, 29),
        (2401, 86),
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
        # textforensics.atomic_io (6 positions).
        (50, 33),
        (86, 32),
        (92, 24),
        (105, 19),
        (109, 29),
        (122, 23),
        # textforensics.benchmark (47 positions).
        (35, 29),
        (38, 46),
        (38, 51),
        (38, 53),
        (44, 14),
        (77, 58),
        (92, 34),
        (96, 18),
        (103, 32),
        (104, 32),
        (105, 32),
        (106, 40),
        (107, 38),
        (126, 14),
        (149, 14),
        (158, 54),
        (159, 51),
        (178, 36),
        (179, 41),
        (245, 14),
        (250, 42),
        (304, 35),
        (305, 50),
        (322, 35),
        (359, 40),
        (402, 4),
        (452, 34),
        (463, 23),
        (464, 25),
        (465, 4),
        (540, 19),
        (540, 38),
        (643, 18),
        (708, 30),
        (716, 30),
        (730, 14),
        (734, 28),
        (778, 14),
        (826, 44),
        (831, 15),
        (833, 15),
        (926, 11),
        (930, 11),
        (949, 31),
        (960, 14),
        (980, 26),
        (982, 25),
        # textforensics.bundle (18 positions).
        (228, 36),
        (228, 61),
        (291, 76),
        (334, 12),
        (334, 23),
        (340, 33),
        (340, 45),
        (383, 21),
        (384, 25),
        (499, 19),
        (502, 35),
        (507, 24),
        (512, 24),
        (514, 21),
        (517, 38),
        (522, 24),
        (528, 16),
        (561, 26),
        # textforensics.bundle_consistency (6 positions).
        (394, 26),
        (394, 58),
        (395, 17),
        (395, 49),
        (397, 36),
        (397, 52),
        # textforensics.calibration (106 positions).
        (160, 13),
        (160, 16),
        (383, 32),
        (384, 24),
        (384, 62),
        (390, 23),
        (390, 64),
        (395, 32),
        (395, 59),
        (422, 27),
        (440, 25),
        (444, 25),
        (447, 47),
        (450, 17),
        (450, 30),
        (454, 25),
        (492, 23),
        (494, 43),
        (500, 23),
        (501, 36),
        (503, 69),
        (504, 27),
        (506, 27),
        (509, 23),
        (511, 23),
        (513, 23),
        (522, 17),
        (537, 31),
        (537, 56),
        (538, 31),
        (538, 56),
        (566, 18),
        (566, 52),
        (601, 20),
        (662, 54),
        (871, 54),
        (1068, 36),
        (1096, 36),
        (1132, 41),
        (1156, 62),
        (1171, 36),
        (1207, 28),
        (1208, 35),
        (1209, 46),
        (1210, 36),
        (1212, 38),
        (1213, 45),
        (1214, 40),
        (1215, 35),
        (1216, 26),
        (1217, 33),
        (1218, 24),
        (1219, 36),
        (1220, 22),
        (1221, 19),
        (1222, 25),
        (1223, 36),
        (1224, 20),
        (1302, 59),
        (1305, 79),
        (1317, 83),
        (1346, 37),
        (1398, 8),
        (1400, 15),
        (1419, 8),
        (1421, 27),
        (1439, 36),
        (1441, 15),
        (1468, 36),
        (1470, 27),
        (1491, 37),
        (1494, 17),
        (1494, 20),
        (1512, 83),
        (1516, 18),
        (1519, 53),
        (1521, 29),
        (1535, 17),
        (1536, 61),
        (1561, 49),
        (1565, 40),
        (1577, 71),
        (1751, 26),
        (1787, 54),
        (1788, 51),
        (1826, 39),
        (1827, 16),
        (1828, 43),
        (1829, 44),
        (1837, 65),
        (1837, 91),
        (1844, 19),
        (1847, 34),
        (1850, 42),
        (1926, 53),
        (1932, 35),
        (1933, 50),
        (1952, 35),
        (2003, 26),
        (2004, 19),
        (2067, 20),
        (2072, 15),
        (2082, 38),
        (2116, 21),
        (2133, 26),
        (2134, 25),
        # textforensics.casefile (98 positions).
        (246, 41),
        (319, 4),
        (320, 24),
        (321, 15),
        (322, 16),
        (323, 14),
        (337, 43),
        (338, 4),
        (339, 24),
        (340, 27),
        (341, 32),
        (342, 30),
        (343, 33),
        (344, 47),
        (345, 59),
        (346, 62),
        (347, 40),
        (461, 55),
        (475, 4),
        (479, 14),
        (536, 4),
        (537, 30),
        (538, 21),
        (539, 28),
        (540, 27),
        (541, 25),
        (542, 23),
        (620, 58),
        (639, 69),
        (662, 4),
        (663, 50),
        (771, 35),
        (772, 43),
        (827, 18),
        (828, 4),
        (829, 13),
        (884, 43),
        (886, 60),
        (932, 42),
        (933, 4),
        (934, 31),
        (1006, 37),
        (1110, 54),
        (1119, 15),
        (1167, 56),
        (1181, 29),
        (1198, 27),
        (1313, 25),
        (1316, 31),
        (1317, 41),
        (1318, 29),
        (1319, 34),
        (1320, 24),
        (1321, 30),
        (1322, 42),
        (1323, 35),
        (1324, 35),
        (1325, 43),
        (1389, 28),
        (1390, 19),
        (1404, 15),
        (1407, 15),
        (1512, 44),
        (1580, 32),
        (1580, 53),
        (1640, 60),
        (1687, 4),
        (1690, 16),
        (1691, 14),
        (1692, 24),
        (1693, 30),
        (1788, 14),
        (1791, 25),
        (1809, 73),
        (1816, 36),
        (1816, 44),
        (1816, 65),
        (1869, 48),
        (1870, 24),
        (1885, 61),
        (1999, 25),
        (1999, 56),
        (2049, 31),
        (2051, 29),
        (2095, 31),
        (2096, 4),
        (2097, 29),
        (2238, 14),
        (2239, 34),
        (2240, 31),
        (2241, 29),
        (2361, 16),
        (2363, 63),
        (2386, 14),
        (2388, 14),
        (2389, 34),
        (2390, 31),
        (2391, 29),
        # textforensics.cli (16 positions).
        (1614, 15),
        (1614, 46),
        (1617, 35),
        (1667, 41),
        (1689, 79),
        (1829, 33),
        (1864, 37),
        (1883, 33),
        (1953, 37),
        (2048, 72),
        (2054, 56),
        (2058, 68),
        (2093, 35),
        (2149, 67),
        (2161, 22),
        (2488, 41),
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
        # textforensics.datasets (19 positions).
        (1559, 41),
        (1561, 37),
        (1566, 20),
        (2053, 20),
        (2054, 22),
        (2055, 18),
        (2128, 20),
        (2129, 18),
        (2148, 36),
        (2300, 45),
        (2325, 21),
        (2344, 21),
        (2352, 35),
        (2352, 43),
        (2456, 25),
        (2466, 71),
        (2466, 73),
        (2509, 29),
        (2512, 19),
        # textforensics.detection_cache (21 positions).
        (89, 40),
        (305, 44),
        (343, 28),
        (344, 48),
        (345, 27),
        (446, 19),
        (446, 24),
        (446, 26),
        (532, 22),
        (534, 24),
        (550, 20),
        (584, 30),
        (658, 27),
        (659, 33),
        (723, 25),
        (724, 30),
        (725, 26),
        (743, 24),
        (999, 37),
        (1001, 24),
        (1005, 24),
        # textforensics.detectors (23 positions).
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
        (856, 76),
        (940, 23),
        (941, 21),
        (942, 16),
        (979, 32),
        (980, 23),
        (981, 21),
        (982, 16),
        (1138, 3),
        # textforensics.diagnostics (11 positions).
        (205, 31),
        (207, 33),
        (246, 73),
        (429, 23),
        (430, 34),
        (431, 55),
        (432, 54),
        (682, 19),
        (683, 30),
        (684, 51),
        (685, 50),
        # textforensics.emergency_stop (4 positions).
        (60, 30),
        (79, 14),
        (79, 33),
        (104, 25),
        # textforensics.engine (8 positions).
        (17, 81),
        (22, 22),
        (84, 16),
        (93, 8),
        (94, 12),
        (219, 21),
        (220, 24),
        (221, 16),
        # textforensics.evidence (71 positions).
        (1031, 23),
        (1033, 23),
        (1039, 24),
        (1105, 48),
        (1105, 68),
        (1107, 21),
        (1147, 36),
        (1148, 48),
        (1148, 68),
        (1149, 18),
        (1149, 24),
        (1164, 21),
        (1198, 31),
        (1202, 44),
        (1207, 39),
        (1207, 77),
        (1222, 14),
        (1449, 16),
        (1469, 26),
        (1479, 33),
        (1482, 47),
        (1485, 17),
        (1499, 17),
        (1502, 37),
        (1502, 63),
        (1503, 17),
        (1517, 17),
        (1518, 24),
        (1534, 37),
        (1534, 63),
        (1535, 17),
        (1550, 25),
        (1567, 37),
        (1567, 63),
        (1568, 17),
        (1589, 47),
        (1590, 41),
        (1590, 67),
        (1598, 17),
        (1598, 40),
        (1615, 41),
        (1615, 67),
        (1623, 17),
        (1623, 40),
        (1636, 24),
        (1662, 17),
        (1664, 34),
        (1718, 16),
        (1760, 74),
        (1761, 4),
        (1853, 19),
        (1854, 19),
        (1856, 31),
        (1857, 18),
        (1857, 24),
        (1860, 32),
        (1861, 36),
        (1862, 48),
        (1862, 68),
        (1903, 74),
        (1946, 29),
        (1981, 35),
        (1984, 33),
        (2065, 30),
        (2257, 4),
        (2258, 31),
        (2259, 18),
        (2259, 24),
        (2262, 36),
        (2263, 48),
        (2263, 68),
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
        # textforensics.ledger (24 positions).
        (353, 37),
        (435, 19),
        (436, 24),
        (437, 25),
        (438, 33),
        (480, 19),
        (481, 24),
        (482, 25),
        (483, 33),
        (545, 32),
        (598, 35),
        (996, 61),
        (1513, 49),
        (1547, 25),
        (1697, 19),
        (1698, 38),
        (1699, 33),
        (1743, 36),
        (1744, 19),
        (1745, 38),
        (1794, 29),
        (1974, 37),
        (2008, 29),
        (2030, 63),
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
        (268, 11),
        (272, 80),
        (280, 11),
        (288, 4),
        (291, 11),
        (300, 56),
        (300, 72),
        (475, 65),
        # textforensics.observatory (62 positions).
        (136, 53),
        (771, 49),
        (1171, 39),
        (1186, 18),
        (1189, 36),
        (1222, 37),
        (1232, 33),
        (1233, 32),
        (1975, 54),
        (2022, 27),
        (2048, 82),
        (2080, 91),
        (2084, 24),
        (2102, 71),
        (2140, 16),
        (2140, 21),
        (2140, 26),
        (2140, 31),
        (2140, 36),
        (2140, 41),
        (2140, 46),
        (2140, 51),
        (2140, 56),
        (2140, 61),
        (2140, 66),
        (2145, 25),
        (2148, 29),
        (2150, 17),
        (2150, 20),
        (2151, 19),
        (2151, 25),
        (2152, 46),
        (2154, 58),
        (2155, 61),
        (2159, 29),
        (2227, 54),
        (2266, 60),
        (2277, 69),
        (2316, 33),
        (2317, 23),
        (2317, 34),
        (2367, 23),
        (2367, 34),
        (2375, 23),
        (2375, 34),
        (2388, 23),
        (2388, 34),
        (2392, 62),
        (2392, 73),
        (2400, 29),
        (2412, 74),
        (2425, 72),
        (2431, 74),
        (2446, 29),
        (2494, 34),
        (2496, 36),
        (2499, 24),
        (2502, 26),
        (2503, 45),
        (2504, 27),
        (2505, 45),
        (2515, 44),
        # textforensics.ollama (3 positions).
        (826, 28),
        (879, 22),
        (880, 14),
        # textforensics.policy (60 positions).
        (120, 34),
        (120, 50),
        (139, 30),
        (139, 41),
        (139, 57),
        (153, 37),
        (173, 45),
        (173, 60),
        (173, 71),
        (193, 16),
        (193, 27),
        (194, 27),
        (230, 18),
        (232, 59),
        (281, 46),
        (316, 74),
        (332, 8),
        (333, 20),
        (333, 31),
        (334, 25),
        (354, 8),
        (355, 20),
        (355, 31),
        (364, 48),
        (370, 8),
        (371, 20),
        (371, 31),
        (453, 43),
        (453, 58),
        (453, 69),
        (468, 18),
        (469, 35),
        (487, 16),
        (487, 27),
        (548, 31),
        (549, 33),
        (682, 20),
        (682, 31),
        (713, 32),
        (715, 33),
        (725, 48),
        (725, 49),
        (728, 34),
        (728, 53),
        (955, 19),
        (1112, 29),
        (1163, 25),
        (1164, 19),
        (1165, 23),
        (1230, 39),
        (1322, 40),
        (1362, 29),
        (1374, 85),
        (1395, 32),
        (1523, 33),
        (1524, 35),
        (1534, 41),
        (1547, 43),
        (1554, 35),
        (1598, 15),
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
        # textforensics.probe_runs (90 positions).
        (124, 3),
        (444, 47),
        (509, 43),
        (511, 29),
        (517, 46),
        (533, 46),
        (534, 43),
        (601, 49),
        (674, 52),
        (742, 34),
        (745, 61),
        (746, 17),
        (775, 61),
        (776, 17),
        (798, 56),
        (824, 17),
        (850, 42),
        (878, 33),
        (892, 33),
        (933, 50),
        (935, 29),
        (939, 46),
        (940, 18),
        (1037, 69),
        (1045, 49),
        (1160, 57),
        (1188, 51),
        (1189, 25),
        (1191, 35),
        (1192, 50),
        (1193, 41),
        (1194, 16),
        (1283, 23),
        (1337, 32),
        (1343, 56),
        (1344, 62),
        (1347, 56),
        (1348, 85),
        (1408, 39),
        (1632, 37),
        (1639, 52),
        (1645, 36),
        (1691, 45),
        (1727, 23),
        (1792, 23),
        (1816, 23),
        (1867, 23),
        (1904, 41),
        (1905, 23),
        (2082, 53),
        (2082, 67),
        (2084, 63),
        (2085, 18),
        (2085, 41),
        (2085, 60),
        (2098, 16),
        (2099, 20),
        (2103, 32),
        (2106, 41),
        (2107, 18),
        (2108, 25),
        (2110, 26),
        (2111, 25),
        (2115, 41),
        (2116, 41),
        (2117, 41),
        (2118, 24),
        (2119, 50),
        (2120, 36),
        (2299, 29),
        (2370, 48),
        (2471, 20),
        (2558, 52),
        (2572, 71),
        (2613, 23),
        (2625, 36),
        (2653, 18),
        (2653, 25),
        (2654, 23),
        (2654, 30),
        (2655, 32),
        (2659, 21),
        (2660, 38),
        (2661, 36),
        (2731, 15),
        (2799, 26),
        (2888, 48),
        (2963, 23),
        (2980, 23),
        (2980, 33),
        # textforensics.report (18 positions).
        (412, 34),
        (413, 21),
        (414, 31),
        (415, 23),
        (416, 43),
        (418, 23),
        (420, 25),
        (422, 28),
        (423, 29),
        (424, 38),
        (425, 36),
        (426, 22),
        (427, 46),
        (521, 82),
        (566, 75),
        (571, 66),
        (581, 76),
        (611, 93),
        # textforensics.result_codec (25 positions).
        (177, 47),
        (245, 23),
        (284, 23),
        (318, 23),
        (352, 19),
        (352, 33),
        (352, 36),
        (357, 39),
        (360, 48),
        (363, 11),
        (365, 27),
        (373, 20),
        (376, 23),
        (416, 15),
        (464, 18),
        (467, 23),
        (493, 23),
        (535, 41),
        (535, 62),
        (536, 23),
        (546, 31),
        (546, 32),
        (555, 16),
        (555, 19),
        (558, 23),
        # textforensics.retry (18 positions).
        (136, 50),
        (145, 48),
        (181, 31),
        (203, 27),
        (213, 29),
        (216, 47),
        (216, 50),
        (227, 33),
        (257, 19),
        (258, 27),
        (297, 28),
        (310, 45),
        (310, 47),
        (314, 28),
        (324, 27),
        (330, 31),
        (343, 28),
        (389, 21),
        # textforensics.rich_output (9 positions).
        (412, 41),
        (448, 13),
        (467, 17),
        (471, 57),
        (480, 42),
        (481, 44),
        (488, 17),
        (498, 17),
        (506, 17),
        # textforensics.schema (6 positions).
        (94, 27),
        (94, 43),
        (357, 60),
        (383, 48),
        (403, 69),
        (461, 19),
        # textforensics.sealed_bundle (34 positions).
        (208, 4),
        (209, 24),
        (210, 27),
        (211, 27),
        (212, 17),
        (213, 39),
        (241, 30),
        (353, 43),
        (353, 45),
        (361, 4),
        (362, 25),
        (363, 22),
        (364, 32),
        (365, 14),
        (366, 29),
        (367, 29),
        (415, 42),
        (458, 62),
        (460, 28),
        (461, 32),
        (462, 46),
        (464, 42),
        (469, 33),
        (479, 19),
        (481, 32),
        (537, 35),
        (537, 38),
        (538, 38),
        (548, 19),
        (550, 38),
        (561, 37),
        (568, 21),
        (569, 26),
        (569, 33),
        # textforensics.sealing (30 positions).
        (251, 31),
        (281, 23),
        (292, 40),
        (349, 18),
        (350, 16),
        (351, 21),
        (352, 32),
        (353, 42),
        (354, 18),
        (355, 17),
        (356, 21),
        (357, 21),
        (358, 22),
        (422, 7),
        (427, 30),
        (429, 61),
        (431, 11),
        (444, 42),
        (445, 11),
        (445, 17),
        (445, 20),
        (451, 42),
        (457, 15),
        (457, 21),
        (457, 24),
        (617, 29),
        (643, 20),
        (656, 42),
        (736, 61),
        (752, 16),
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
        # textforensics.timestamp (8 positions).
        (887, 4),
        (890, 24),
        (945, 36),
        (956, 55),
        (957, 11),
        (993, 15),
        (996, 40),
        (1015, 25),
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
        # textforensics.verify (32 positions).
        (105, 64),
        (137, 24),
        (141, 20),
        (141, 67),
        (145, 17),
        (145, 34),
        (147, 17),
        (152, 67),
        (180, 20),
        (180, 67),
        (184, 17),
        (184, 34),
        (290, 31),
        (325, 26),
        (410, 29),
        (410, 50),
        (454, 11),
        (458, 21),
        (460, 29),
        (461, 34),
        (496, 14),
        (496, 22),
        (496, 43),
        (526, 38),
        (526, 59),
        (526, 71),
        (755, 33),
        (760, 33),
        (765, 33),
        (770, 33),
        (775, 33),
        (885, 36),
        # textforensics.watermarking (17 positions).
        (132, 4),
        (133, 4),
        (153, 60),
        (168, 48),
        (197, 29),
        (288, 28),
        (326, 34),
        (326, 69),
        (560, 32),
        (595, 44),
        (597, 39),
        (597, 74),
        (609, 36),
        (615, 59),
        (620, 64),
        (723, 39),
        (752, 17),
        # textforensics.web_ui.main (18 positions).
        (187, 28),
        (278, 45),
        (302, 49),
        (348, 45),
        (380, 79),
        (398, 43),
        (413, 62),
        (493, 38),
        (544, 36),
        (581, 21),
        (582, 22),
        (583, 21),
        (584, 20),
        (585, 25),
        (586, 25),
        (1163, 27),
        (1164, 65),
        (1165, 24),
        # textforensics.workspace_integrity (9 positions).
        (162, 33),
        (238, 46),
        (313, 23),
        (720, 63),
        (748, 47),
        (883, 58),
        (905, 30),
        (906, 27),
        (959, 30),
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

    def test_baseline_file_loads_with_6938_entries(self):
        """The baseline has exactly the 6938 verified equivalent mutants.

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
        plus the W3 re-proof appends (audit-w3-f, 2026-11-13,
        647 entries: watermarking 98, ledger 11, result_codec 2,
        timestamp 18, bundle 67, casefile 33, sealing 75, verify
        86, sealed_bundle 149, _standalone_verify 108) on top of
        the F2 refresh (4362 -> 4315, 47 entries dropped), taking
        the baseline 4315 -> 4962 with 0 unexplained and 0 stale.
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
        W2 defect fix (audit-w2-fix, 2026-11-12): the parent-caught
        duplicate InferenceIdentity / DisjointnessProof types were
        unified into evidence.py and sample-only proofs were refused
        for held-out support, shifting lines in evidence.py,
        calibration.py and benchmark.py. The first position refresh
        (line-text-anchored zip) mispaired 103 runtime entries in
        unchanged functions — false-OK entries and killed sites shift
        the zip by whole sites, which validation cannot see because
        the fingerprint pins the whole enclosing function — so the
        baseline was re-derived a second time from the F2 baseline
        by pairing live SITES F2<->current (function-start shift;
        occurrence order within a site): 421 entries corrected (98
        occurrence changes), 15 entries dropped (3 benchmark
        DisjointnessProof.__post_init__ + 12 runtime entries in the
        changed functions), taking the baseline 4361 -> 4346 with 0
        stale. The targeted cosmic-ray proof over the 683 live
        mutants in the 9 changed functions then killed 546 (535 by
        the owning F probes / DefectFixTypesTests / module test
        classes, 11 by the DefectFixKillTests follow-ups), left 121
        survivors already covered by existing annotation entries,
        and proved 16 equivalent with closed-domain reasons appended
        here, taking the baseline 4346 -> 4362 with 0 unexplained.
        The W3 F2 refresh then dropped 47 entries (4362 -> 4315)
        and the W3 F3 re-proof appends added 647 (4315 -> 4962).
        The W3 F4 refresh re-derived 204 entries on the rebased head
        f856cd0 (0 dropped) and the F4 datasets re-proof append added
        31 (4962 -> 4993). The W4 refresh re-derived 1292 entries on
        the audit-w4 head 85d75d9 and dropped 42 (4993 -> 4951), and
        the W4 F2 re-proof append added 1210 (4951 -> 6161): 1001
        postponed-evaluation annotations + 209 runtime equivalents
        across the 11 W4 modules, hand re-proved mutant by mutant
        with 0 gaps and 0 unexplained. The W5 refresh re-derived
        1097 entries on the audit-w5 head 068ecf8 and dropped 45
        (6161 -> 6116), and the W5 F re-proof append added 464
        (6116 -> 6580): 376 postponed-evaluation annotations + 88
        runtime equivalents across the 14 W5 modules, hand
        re-proved mutant by mutant with 0 gaps and 0 unexplained.
        The W6 refresh re-derived 1616 entries on the audit-w6 head
        5db75e1 and dropped 5 (6580 -> 6575), and the W6 F re-proof
        append added 363 (6575 -> 6938): 330 postponed-evaluation
        annotations + 33 runtime equivalents across the 9 W6 modules,
        hand re-proved mutant by mutant with 0 gaps and 0 unexplained.
        (The refresh also exposed 2 _metrics guard entries whose old
        position was re-occupied by a different-occurrence live mutant;
        their positions were corrected to the live (105, 32) sites —
        see hidden_files/audit-w6-f-proof-state.md section 5.)
        """
        self.assertEqual(self.baseline["version"], 1)
        self.assertEqual(self.baseline["source_run"], "42393966895")
        self.assertEqual(self.baseline["source_commit"], "153b5ab")
        entries = self.baseline["entries"]
        self.assertEqual(len(entries), 6938)
        self.assertEqual(len({e["id"] for e in entries}), 6938, "entry ids must be unique")
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
        self.assertEqual(len(keys), 6938, "match keys must be unique")
        from collections import Counter

        self.assertEqual(
            Counter(e["operator"] for e in entries),
            {
                "core/AddNot": 13,
                "core/ExceptionReplacer": 24,
                "core/NumberReplacer": 233,
                "core/ReplaceAndWithOr": 14,
                "core/ReplaceBinaryOperator_Add_BitOr": 14,
                "core/ReplaceBinaryOperator_Add_BitXor": 4,
                "core/ReplaceBinaryOperator_Add_FloorDiv": 1,
                "core/ReplaceBinaryOperator_Add_LShift": 12,
                "core/ReplaceBinaryOperator_Add_Mul": 1,
                "core/ReplaceBinaryOperator_Add_Pow": 1,
                "core/ReplaceBinaryOperator_BitOr_Add": 532,
                "core/ReplaceBinaryOperator_BitOr_BitAnd": 535,
                "core/ReplaceBinaryOperator_BitOr_BitXor": 541,
                "core/ReplaceBinaryOperator_BitOr_Div": 535,
                "core/ReplaceBinaryOperator_BitOr_FloorDiv": 538,
                "core/ReplaceBinaryOperator_BitOr_LShift": 533,
                "core/ReplaceBinaryOperator_BitOr_Mod": 534,
                "core/ReplaceBinaryOperator_BitOr_Mul": 534,
                "core/ReplaceBinaryOperator_BitOr_Pow": 534,
                "core/ReplaceBinaryOperator_BitOr_RShift": 535,
                "core/ReplaceBinaryOperator_BitOr_Sub": 535,
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
                "core/ReplaceBinaryOperator_FloorDiv_Add": 1,
                "core/ReplaceBinaryOperator_FloorDiv_BitAnd": 1,
                "core/ReplaceBinaryOperator_FloorDiv_BitOr": 1,
                "core/ReplaceBinaryOperator_FloorDiv_BitXor": 1,
                "core/ReplaceBinaryOperator_FloorDiv_LShift": 1,
                "core/ReplaceBinaryOperator_FloorDiv_Mod": 1,
                "core/ReplaceBinaryOperator_FloorDiv_Mul": 1,
                "core/ReplaceBinaryOperator_FloorDiv_Pow": 1,
                "core/ReplaceBinaryOperator_FloorDiv_RShift": 1,
                "core/ReplaceBinaryOperator_FloorDiv_Sub": 1,
                "core/ReplaceBinaryOperator_Mul_Add": 2,
                "core/ReplaceBinaryOperator_Mul_BitAnd": 2,
                "core/ReplaceBinaryOperator_Mul_BitOr": 2,
                "core/ReplaceBinaryOperator_Mul_BitXor": 1,
                "core/ReplaceBinaryOperator_Mul_Div": 71,
                "core/ReplaceBinaryOperator_Mul_FloorDiv": 3,
                "core/ReplaceBinaryOperator_Mul_LShift": 1,
                "core/ReplaceBinaryOperator_Mul_Mod": 1,
                "core/ReplaceBinaryOperator_Mul_RShift": 1,
                "core/ReplaceBinaryOperator_Mul_Sub": 1,
                "core/ReplaceBinaryOperator_Sub_Add": 3,
                "core/ReplaceBinaryOperator_Sub_BitAnd": 1,
                "core/ReplaceBinaryOperator_Sub_BitOr": 3,
                "core/ReplaceBinaryOperator_Sub_BitXor": 7,
                "core/ReplaceBinaryOperator_Sub_Div": 2,
                "core/ReplaceBinaryOperator_Sub_FloorDiv": 3,
                "core/ReplaceBinaryOperator_Sub_LShift": 2,
                "core/ReplaceBinaryOperator_Sub_Mod": 1,
                "core/ReplaceBinaryOperator_Sub_Mul": 3,
                "core/ReplaceBinaryOperator_Sub_Pow": 3,
                "core/ReplaceBinaryOperator_Sub_RShift": 3,
                "core/ReplaceBreakWithContinue": 4,
                "core/ReplaceComparisonOperator_Eq_Gt": 2,
                "core/ReplaceComparisonOperator_Eq_GtE": 114,
                "core/ReplaceComparisonOperator_Eq_Is": 32,
                "core/ReplaceComparisonOperator_Eq_IsNot": 5,
                "core/ReplaceComparisonOperator_Eq_Lt": 8,
                "core/ReplaceComparisonOperator_Eq_LtE": 135,
                "core/ReplaceComparisonOperator_Eq_NotEq": 1,
                "core/ReplaceComparisonOperator_GtE_Eq": 8,
                "core/ReplaceComparisonOperator_GtE_Gt": 8,
                "core/ReplaceComparisonOperator_GtE_Is": 2,
                "core/ReplaceComparisonOperator_GtE_IsNot": 1,
                "core/ReplaceComparisonOperator_GtE_Lt": 3,
                "core/ReplaceComparisonOperator_GtE_LtE": 4,
                "core/ReplaceComparisonOperator_GtE_NotEq": 4,
                "core/ReplaceComparisonOperator_Gt_GtE": 15,
                "core/ReplaceComparisonOperator_Gt_Is": 7,
                "core/ReplaceComparisonOperator_Gt_NotEq": 27,
                "core/ReplaceComparisonOperator_IsNot_Is": 2,
                "core/ReplaceComparisonOperator_IsNot_NotEq": 1,
                "core/ReplaceComparisonOperator_Is_Eq": 5,
                "core/ReplaceComparisonOperator_Is_IsNot": 1,
                "core/ReplaceComparisonOperator_LtE_Eq": 4,
                "core/ReplaceComparisonOperator_LtE_Lt": 3,
                "core/ReplaceComparisonOperator_Lt_Eq": 1,
                "core/ReplaceComparisonOperator_Lt_Gt": 3,
                "core/ReplaceComparisonOperator_Lt_Is": 1,
                "core/ReplaceComparisonOperator_Lt_IsNot": 3,
                "core/ReplaceComparisonOperator_Lt_LtE": 4,
                "core/ReplaceComparisonOperator_Lt_NotEq": 11,
                "core/ReplaceComparisonOperator_NotEq_Eq": 2,
                "core/ReplaceComparisonOperator_NotEq_Gt": 29,
                "core/ReplaceComparisonOperator_NotEq_GtE": 2,
                "core/ReplaceComparisonOperator_NotEq_Is": 1,
                "core/ReplaceComparisonOperator_NotEq_IsNot": 17,
                "core/ReplaceComparisonOperator_NotEq_Lt": 30,
                "core/ReplaceComparisonOperator_NotEq_LtE": 4,
                "core/ReplaceContinueWithBreak": 11,
                "core/ReplaceFalseWithTrue": 25,
                "core/ReplaceOrWithAnd": 13,
                "core/ReplaceTrueWithFalse": 30,
                "core/ReplaceUnaryOperator_Delete_Not": 2,
                "core/ReplaceUnaryOperator_Delete_USub": 3,
                "core/ReplaceUnaryOperator_USub_Invert": 2,
                "core/ReplaceUnaryOperator_USub_Not": 3,
                "core/ReplaceUnaryOperator_USub_UAdd": 3,
                "core/ZeroIterationForLoop": 2,
            },
        )
        self.assertEqual({tuple(e["start_pos"]) for e in entries}, self.EXPECTED_POSITIONS)
        for entry in entries:
            self.assertIn(
                entry["module"],
                {
                    "textforensics._build_info",
                    "textforensics._standalone_verify",
                    "textforensics.adversarial",
                    "textforensics.analyzers",
                    "textforensics.atomic_io",
                    "textforensics.benchmark",
                    "textforensics.bundle",
                    "textforensics.bundle_consistency",
                    "textforensics.calibration",
                    "textforensics.casefile",
                    "textforensics.cli",
                    "textforensics.consensus",
                    "textforensics.datasets",
                    "textforensics.detection_cache",
                    "textforensics.detectors",
                    "textforensics.diagnostics",
                    "textforensics.emergency_stop",
                    "textforensics.engine",
                    "textforensics.evidence",
                    "textforensics.execution_policy",
                    "textforensics.explain",
                    "textforensics.ledger",
                    "textforensics.mixed_origin",
                    "textforensics.model_card",
                    "textforensics.observatory",
                    "textforensics.ollama",
                    "textforensics.policy",
                    "textforensics.probe_metrics",
                    "textforensics.probe_runs",
                    "textforensics.report",
                    "textforensics.result_codec",
                    "textforensics.retry",
                    "textforensics.rich_output",
                    "textforensics.schema",
                    "textforensics.sealed_bundle",
                    "textforensics.sealing",
                    "textforensics.semantic",
                    "textforensics.timestamp",
                    "textforensics.trust",
                    "textforensics.validation",
                    "textforensics.verify",
                    "textforensics.watermarking",
                    "textforensics.web_ui.main",
                    "textforensics.workspace_integrity",
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
        """The 1068 runtime entries carry their equivalence proofs."""
        runtime = [
            e for e in self.baseline["entries"] if e["kind"] in self.runner.BASELINE_RUNTIME_KINDS
        ]
        self.assertEqual(len(runtime), 1068)
        unreachable = [e for e in runtime if e["kind"] == "unreachable-condition"]
        self.assertEqual(len(unreachable), 23)
        by_id = {e["id"]: e for e in runtime}
        self.assertEqual(
            {e["occurrence"] for e in unreachable},
            {0, 1, 2, 3, 4, 6, 7, 13, 14, 15, 16, 45, 95},
            "occurrences must match the W2 refresh plus the W3 sealing "
            "platform-gated entries (the W1 set was {12, 45, 48, 50, 51, "
            "95}; the trust entries 48/50/51 were DROPPED in the W2 "
            "refresh because W2 broke their recorded equivalence — see "
            "the baseline header note — and 12 was renumbered to 15 by "
            "the same refresh: it is the PolicyRevisionFloor."
            "_atomic_write_bytes missing_ok entry; the 16 sealing "
            "entries (occurrences 1, 2, 6, 7, 13, 14, 15, 16) are the "
            "Windows-only _restrict_to_owner_windows conditions, "
            "unreachable on POSIX — see the W3 sealing reasons; the W3 "
            "F4 refresh renumbered the sealing AddNot chain 12/13/14/15 "
            "-> 13/14/15/16 because the iterative "
            "find_forbidden_raw_text_keys added one AddNot mutant); the "
            "4 W4 detection_cache entries (occurrences 0, 1, 3, 4) are "
            "the unreachable loop-guard breaks/continues: the "
            "_ensure_capacity/_load_from_disk max-entries and size "
            "loops are entered only with a non-empty cache, so their "
            "`if not ...: break` guards never fire, and the "
            "invalidate detector-index loop never sees a None entry "
            "by the index/cache invariant — see the W4 "
            "detection_cache reasons",
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
        self.assertEqual(len(unobservable), 243)
        self.assertEqual(
            {e["occurrence"] for e in unobservable},
            {
                0,
                1,
                2,
                3,
                4,
                5,
                6,
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
                26,
                27,
                28,
                29,
                30,
                31,
                32,
                33,
                34,
                35,
                36,
                37,
                38,
                51,
                52,
                53,
                54,
                55,
                56,
                57,
                60,
                61,
                62,
                63,
                64,
                65,
                80,
                81,
                83,
                89,
                94,
                95,
                99,
                105,
                128,
                129,
                172,
                173,
                200,
                201,
                230,
                231,
                232,
                233,
                234,
                235,
                236,
                237,
                238,
                239,
                240,
                241,
                242,
                243,
                244,
                245,
                246,
                247,
                248,
                249,
                250,
                251,
                312,
                313,
                510,
                511,
                548,
                549,
                550,
                551,
                554,
                555,
            },
            "occurrences must match the W2 refresh + W2 proof + F2 "
            "re-proof append + W2 defect-fix repair + W3 re-proof "
            "appends + W4 refresh + W4 re-proof append (the W1 set was "
            "{0, 1, 2, 3, 4, 8, 9, 10, 19, 22, 23, 24, 25, 27, 36, 37, "
            "38, 48, 64, 65, 81, 95, 118}; W2 renumbered the calibration "
            "_coerce_label entries 9 -> 11 and 118 -> 128 and the "
            "casefile entry 48 -> 50, dropped the trust 95 entry, and "
            "added 80/81 (probe_runs abstention n), 105 (casefile), "
            "172/173 (probe_metrics holm_adjusted) and 486/487 "
            "(_standalone_verify exit_code); the defect-fix repair "
            "renumbered the calibration _coerce_label "
            "ReplaceFalseWithTrue entry 11 -> 12, because the "
            "unification added a False literal earlier in the "
            "function; the W3 appends added the sealing "
            "platform-gated values, the verify/sealed_bundle/"
            "_standalone_verify unobservable values, and the "
            "casefile/sealing/verify NumberReplacer sites; the W4 "
            "append added 62 (detection_cache), 94/95 (ledger "
            "DIRECTORY_HASH_VERSION), 127 (cli) and 230-251 plus "
            "312/313 (observatory NumberReplacer values); the W5 refresh "
            "dropped the cli 127 entry and the W5 re-proof append "
            "added 52/53/55 (web_ui.main query_history), 83 (cli "
            "_run) and 129 (web_ui.main websocket_analyze); the W6 refresh "
            "dropped 4 domain-equivalent entries (3 benchmark "
            "sort_keys + 1 datasets write_sample_cache IsNot) and 1 "
            "unobservable-value entry (casefile allow_nan), and the "
            "W6 re-proof append added 26 unobservable-value entries "
            "(20 _build_info, 3 benchmark sort_keys re-proven as "
            "unobservable, 1 casefile allow_nan, 1 ledger "
            "save_to_file, 1 detectors TYPE_CHECKING — occ 99 is "
            "the only new occurrence))",
        )
        self.assertEqual(
            {e["function"] for e in unobservable},
            {
                "<module>",
                "CalibrationChain.save_to_file",
                "CalibrationCurve._validate_parameters",
                "CapabilityPolicyEngine.evaluate",
                "DatasetReference.from_dict",
                "DetectorHealthMonitor.get_report",
                "ResultCodec._iter_encode_chunks",
                "ResultCodec.decode",
                "_ChunkedReader.read",
                "_analyze_text_internal",
                "_coerce_label",
                "_compare_scores",
                "_compute_content_hash",
                "_compute_contract_info",
                "_compute_sample_hashes",
                "_create_score_distribution_check.check",
                "_disagreement",
                "_family_vote",
                "_get_api_version",
                "_get_format_versions",
                "_get_source_commit",
                "_git_toplevel",
                "_load_enterprise_policy_schema",
                "_replay_trust_map_v3",
                "_restrict_to_owner_windows",
                "_run",
                "_slice_metrics",
                "_validate_entry_dict",
                "_verify_timestamp_token",
                "build_agreement_matrix",
                "build_forensic_bundle",
                "check_bundle_consistency",
                "cohens_kappa",
                "create_web_app",
                "create_web_app.query_history",
                "create_web_app.websocket_analyze",
                "dataset_sha256",
                "holm_adjusted",
                "iter_detectrl_x_rows",
                "percent_agreement",
                "perform_probe_run",
                "print_diff",
                "replay_case_file",
                "save_run",
                "save_sealing_key",
                "verify_bundle_bytes",
                "verify_case_file_combined",
                "verify_sealed_bundle",
                "write_case_file",
            },
        )
        self.assertEqual(
            {e["source_text"] for e in unobservable},
            {
                "!=",
                '"benchmark" in line.lower() and "schema" in line.lower()',
                '"calibration" in line.lower() and "schema" in line.lower()',
                "*",
                "+",
                "-",
                "//",
                "0",
                "0.0",
                "0.1",
                "0.2",
                "0.3",
                "0.4",
                "0.5",
                "0.6",
                "0.7",
                "0.8",
                "0.9",
                "0x00000004",
                "0x0008",
                "0x10000000",
                "0x80000000",
                "1",
                "1.0",
                "10",
                "1024",
                "2",
                "4",
                "422",
                "50",
                "<",
                "==",
                ">",
                ">=",
                "False",
                "IndexError",
                "OSError",
                "RecursionError",
                "SealedBundleError",
                "TYPE_CHECKING",
                "True",
                "ValueError",
                "_DerError",
                "and",
                "content.splitlines()",
                "continue",
                "engineering_toml.exists()",
                'hasattr(args, "deterministic") and args.deterministic',
                "infos",
                "is",
                "is not",
                "or",
                "root is None",
                "source_root is not None",
                "tail",
                "|",
            },
        )
        # The two lru_cache entries share one position and function.
        # (W2 moved the decorator L668:19 -> L821:19; W4 moved it
        # L821:19 -> L955:19 and renumbered the pair 22/23 -> 12/13.)
        at_955_19 = [e for e in unobservable if tuple(e["start_pos"]) == (955, 19)]
        self.assertEqual(len(at_955_19), 2)
        self.assertEqual({e["occurrence"] for e in at_955_19}, {12, 13})
        self.assertEqual(len({e["source_fingerprint"] for e in at_955_19}), 1)
        # The seven benchmark unobservable entries: the four chunk-size
        # entries share one function (dataset_sha256) across two positions,
        # plus the three sort_keys entries in _compute_content_hash /
        # _compute_sample_hashes (W6 re-proof, re-proven as
        # unobservable-value after the W6 refresh dropped them from
        # domain-equivalent; all seven positions moved +2 lines).
        bench = [e for e in unobservable if e["module"] == "textforensics.benchmark"]
        self.assertEqual(len(bench), 7)
        self.assertEqual({e["occurrence"] for e in bench}, {0, 1, 2, 3, 10, 12, 13})
        self.assertEqual(
            {tuple(e["start_pos"]) for e in bench},
            {(38, 46), (38, 53), (643, 18), (708, 30), (716, 30)},
        )
        self.assertEqual({e["source_text"] for e in bench}, {"1024", "True"})
        self.assertEqual(len({e["source_fingerprint"] for e in bench}), 3)
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
        # (W2 moved them L255:47 -> L461:47; the defect fix moved them
        # L461:47 -> L447:47 by deleting the duplicate InferenceIdentity
        # class from calibration.py.)
        at_447_47 = [e for e in unobservable if tuple(e["start_pos"]) == (447, 47)]
        self.assertEqual(len(at_447_47), 2)
        self.assertEqual({e["occurrence"] for e in at_447_47}, {36, 37})
        self.assertEqual({e["source_text"] for e in at_447_47}, {"0.0"})
        self.assertEqual(len({e["source_fingerprint"] for e in at_447_47}), 1)
        # The calibration _coerce_label False entry (remainder wave).
        coerce_false = [
            e
            for e in unobservable
            if e["source_text"] == "False" and e["module"] == "textforensics.calibration"
        ]
        self.assertEqual(len(coerce_false), 1)
        self.assertEqual({e["occurrence"] for e in coerce_false}, {12})
        self.assertEqual({e["function"] for e in coerce_false}, {"_coerce_label"})
        self.assertEqual({tuple(e["start_pos"]) for e in coerce_false}, {(1494, 20)})
        # The two _coerce_label entries share one function (and hence
        # one fingerprint) but sit at different positions in it.
        # (W2 renumbered 9 -> 11 and 118 -> 128 and moved the False
        # entry L942:20 -> L1479:20; the defect-fix repair renumbered
        # the False entry 11 -> 12 — see the occurrences assertion
        # message above.)
        coerce = [e for e in unobservable if e["function"] == "_coerce_label"]
        self.assertEqual(len(coerce), 2)
        self.assertEqual({e["occurrence"] for e in coerce}, {12, 128})
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
        # was lost, so the survivor set was re-derived structurally;
        # positions/occurrences re-derived again by the W3 F2 refresh):
        # occ 17 in write_case_file, occ 89 in _compare_scores,
        # occ 27/28 in _replay_trust_map_v3, occ 54/27 in replay_case_file.
        # (W6: the refresh moved all six positions — write_case_file +9
        # lines, the replay functions -9 lines; occ 17 was dropped and
        # re-appended as the same unobservable-value entry.)
        casefile_unobs = [e for e in unobservable if e["module"] == "textforensics.casefile"]
        self.assertEqual(len(casefile_unobs), 6)
        self.assertEqual({e["occurrence"] for e in casefile_unobs}, {17, 27, 28, 54, 89})
        self.assertEqual(
            {e["function"] for e in casefile_unobs},
            {"_compare_scores", "_replay_trust_map_v3", "replay_case_file", "write_case_file"},
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in casefile_unobs},
            {(1809, 73), (1870, 24), (1999, 25), (1999, 56), (2361, 16), (2363, 63)},
        )
        self.assertEqual(
            {e["source_text"] for e in casefile_unobs},
            {"!=", "1", "==", "False", "or"},
        )
        # Four functions, hence four fingerprints.
        self.assertEqual(len({e["source_fingerprint"] for e in casefile_unobs}), 4)
        # The fourteen datasets entries (F4 re-proof append
        # 2026-11-13): 11 Sub_* + 2 NumberReplacer in the dead
        # `if not expect_element` branch message at datasets.py:2466
        # (occ 7/200/201) and 1 ReplaceFalseWithTrue for the
        # write-only expect_element flag at datasets.py:2509 (occ 8),
        # all in iter_detectrl_x_rows, hence one fingerprint.
        # (W6: the refresh moved the sites +10 lines.)
        datasets_unobs = [e for e in unobservable if e["module"] == "textforensics.datasets"]
        self.assertEqual(len(datasets_unobs), 14)
        self.assertEqual({e["occurrence"] for e in datasets_unobs}, {7, 8, 200, 201})
        self.assertEqual({e["function"] for e in datasets_unobs}, {"iter_detectrl_x_rows"})
        self.assertEqual(
            {tuple(e["start_pos"]) for e in datasets_unobs},
            {(2466, 71), (2466, 73), (2509, 29)},
        )
        self.assertEqual({e["source_text"] for e in datasets_unobs}, {"-", "1", "False"})
        self.assertEqual(len({e["source_fingerprint"] for e in datasets_unobs}), 1)
        # The 562 domain-equivalent entries (151 from the pre-W2
        # waves — kind wave 2026-11-08 + casefile Phase 2 2026-11-09
        # + policy-298 2026-11-09 + the W1 proof 2026-11-11 — plus
        # 203 from the W2 proof append 2026-11-11, plus 208 from the
        # F2 re-proof append 2026-11-11, minus 1 dropped in the W2
        # refresh, minus 15 dropped in the W2 defect-fix re-derivation
        # 2026-11-12, plus 16 appended by the defect-fix targeted
        # proof 2026-11-12: 151 + 203 + 208 - 1 - 15 + 16 = 562).
        # Final per-module counts: _build_info 3,
        # _standalone_verify 95, adversarial 19, analyzers 4,
        # atomic_io 3, benchmark 34, bundle 12, bundle_consistency
        # 4, calibration 83, casefile 27, cli 3, consensus 11,
        # datasets 11, detection_cache 15, detectors 4, engine 1,
        # evidence 45, execution_policy 10, explain 11, ledger 6,
        # mixed_origin 6, model_card 5, observatory 36, policy 26,
        # probe_metrics 64, probe_runs 43, report 2, result_codec
        # 3, retry 20, rich_output 6, schema 4, sealed_bundle 18,
        # sealing 7, semantic 66, timestamp 7, trust 19,
        # validation 22, verify 27, watermarking 10, web_ui.main
        # 2, workspace_integrity 2.
        # (W3: _standalone_verify 43 -> 95 and verify 25 -> 27
        # after the F2 refresh dropped 29/3 domain entries there
        # and the W3 appends added 81/5; casefile and result_codec
        # kept their counts (11/2 dropped, 11/2 added).)
        # (W4: the refresh dropped the calibration
        # CalibrationArtifact.validation_issues entry (84 -> 83)
        # and renumbered policy entries; the F2 re-proof append
        # added cli 16, detection_cache 15, ledger 6,
        # observatory 36, retry 20 and workspace_integrity 2
        # (new modules), datasets 6 -> 8, policy 20 -> 26 and
        # probe_runs 25 -> 49.)
        # (W5: the refresh dropped 15 cli, 11 probe_runs, 6 report
        # and 4 result_codec domain entries; the F re-proof append
        # added atomic_io 3, bundle_consistency 4, rich_output 6
        # and web_ui.main 2 (new modules), cli 2, probe_runs 5,
        # report 2 and result_codec 3.)
        # (W6: the refresh dropped the 3 benchmark sort_keys domain
        # entries (re-proven as unobservable-value) and the datasets
        # write_sample_cache IsNot entry (its W4 justification was
        # wrong — see the datasets note below); the F re-proof append
        # added _build_info 3 (new module) and datasets 4 (_map_mage).)
        domain = [e for e in runtime if e["kind"] == "domain-equivalent"]
        self.assertEqual(len(domain), 796)
        self.assertEqual(
            {e["module"] for e in domain},
            {
                "textforensics._build_info",
                "textforensics._standalone_verify",
                "textforensics.adversarial",
                "textforensics.analyzers",
                "textforensics.atomic_io",
                "textforensics.benchmark",
                "textforensics.bundle",
                "textforensics.bundle_consistency",
                "textforensics.calibration",
                "textforensics.casefile",
                "textforensics.cli",
                "textforensics.consensus",
                "textforensics.datasets",
                "textforensics.detection_cache",
                "textforensics.detectors",
                "textforensics.engine",
                "textforensics.evidence",
                "textforensics.execution_policy",
                "textforensics.explain",
                "textforensics.ledger",
                "textforensics.mixed_origin",
                "textforensics.model_card",
                "textforensics.observatory",
                "textforensics.policy",
                "textforensics.probe_metrics",
                "textforensics.probe_runs",
                "textforensics.report",
                "textforensics.result_codec",
                "textforensics.retry",
                "textforensics.rich_output",
                "textforensics.schema",
                "textforensics.sealed_bundle",
                "textforensics.sealing",
                "textforensics.semantic",
                "textforensics.timestamp",
                "textforensics.trust",
                "textforensics.validation",
                "textforensics.verify",
                "textforensics.watermarking",
                "textforensics.web_ui.main",
                "textforensics.workspace_integrity",
            },
        )
        self.assertTrue(all("ulp_bound_ulps" not in e for e in domain))
        # Datasets' 8 (F4 re-proof append 2026-11-13: 2 Mul_Div
        # `*,` markers (occ 18/19), Eq_LtE (occ 18), Gt_GtE (occ 3),
        # Gt_NotEq (occ 5) and ReplaceAndWithOr (occ 21) — all
        # source-verified domain-equivalent, see
        # hidden_files/audit-w3-worker-f4.md section 6; plus the
        # W4 re-proof append 2026-11-15: 2 NotEq_IsNot filename
        # checks (occ 6/7) in write/read_sample_cache — the W4
        # refresh moved the F4 sites (2184 -> 2290, 2209 -> 2315,
        # 2228 -> 2334, 2236 -> 2342, 2340 -> 2446, 2396 -> 2502)
        # and renumbered the ReplaceAndWithOr entry 21 -> 24
        # (the W4 sample-cache code added `or` sites above it)).
        # (W6 CORRECTION: the W4 justification for the write_sample_cache
        # NotEq_IsNot entry (occ 6) was WRONG — `Path(x).name is x` is
        # not identity-stable (CPython interning); a join-built filename
        # is rejected by the mutant and accepted by the original, so the
        # entry was dropped in the W6 refresh and the mutant is now killed
        # by tests/test_audit_w6_worker_f_datasets.py. The read_sample_cache
        # twin (occ 7) carries the same justification and is flagged for
        # a parent decision — see hidden_files/audit-w6-f-proof-state.md
        # section 4. The W6 append added 4 _map_mage entries (occ 6/7)
        # and the refresh moved the F4 sites +10 lines: 8 - 1 + 4 = 11.)
        datasets_domain = [e for e in domain if e["module"] == "textforensics.datasets"]
        self.assertEqual(len(datasets_domain), 11)
        self.assertEqual({e["occurrence"] for e in datasets_domain}, {3, 5, 6, 7, 18, 19, 24})
        self.assertEqual(
            {e["function"] for e in datasets_domain},
            {
                "_check_raw_json_nesting_depth",
                "_json_value_depth",
                "_map_mage",
                "iter_detectrl_x_rows",
                "read_sample_cache",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in datasets_domain},
            {
                (1559, 41),
                (1561, 37),
                (1566, 20),
                (2148, 36),
                (2300, 45),
                (2325, 21),
                (2344, 21),
                (2352, 43),
                (2456, 25),
                (2512, 19),
            },
        )
        self.assertEqual(
            {e["source_text"] for e in datasets_domain}, {"!=", "*", "-", "==", ">", "and"}
        )
        self.assertEqual(len({e["source_fingerprint"] for e in datasets_domain}), 5)
        # Benchmark's 37 (27 from the full 909-item session — 13
        # round-1 + 14 round-2 genuinely-equivalent survivors — plus
        # 9 from the W2 proof and 3 from the F2 re-proof append, minus
        # 3 DisjointnessProof.__post_init__ entries — the class moved
        # to evidence.py in the W2 defect fix and is re-proven there
        # as new evidence entries — minus 2 benchmark_with_calibration_
        # jsonl entries in the changed function, plus 3 appended by
        # the defect-fix targeted proof: 27 + 9 + 3 - 3 - 2 + 3 = 37).
        # (W6: the refresh dropped the 3 sort_keys domain entries
        # (_compute_content_hash/_compute_sample_hashes, re-proven as
        # unobservable-value) and moved the rest +2 lines: 37 - 3 = 34.)
        bench_domain = [e for e in domain if e["module"] == "textforensics.benchmark"]
        self.assertEqual(len(bench_domain), 34)
        self.assertEqual(
            {e["occurrence"] for e in bench_domain},
            {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13},
            "occurrences must match the benchmark full-session dump "
            "(13 round-1 + 14 round-2 genuinely-equivalent survivors) "
            "plus the W2 proof and F2 re-proof appends, as re-derived "
            "by the W2 defect fix: occurrences 14-17 leave the set "
            "(the 3 moved DisjointnessProof.__post_init__ entries and "
            "the 2 dropped benchmark_with_calibration_jsonl entries), "
            "the surviving later entries were renumbered by the repair "
            "(ReplaceTrueWithFalse 14/15 -> 12/13, Eq_LtE 15/16/17 -> "
            "11/12/13) after the duplicate class's removal, and the 3 "
            "targeted-proof appends reuse occurrences 8/9/10",
        )
        self.assertEqual(
            {e["function"] for e in bench_domain},
            {
                "_load_scores",
                "_metrics",
                "_sample_and_group_hashes",
                "benchmark_with_calibration_jsonl",
                "calibrate_threshold_jsonl",
                "check_disjointness",
                "dataset_sha256",
                "prove_disjointness",
                "verify_fingerprint",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in bench_domain},
            {
                (38, 51),
                (77, 58),
                (92, 34),
                (96, 18),
                (103, 32),
                (104, 32),
                (105, 32),
                (106, 40),
                (107, 38),
                (158, 54),
                (159, 51),
                (178, 36),
                (179, 41),
                (304, 35),
                (305, 50),
                (322, 35),
                (402, 4),
                (452, 34),
                (465, 4),
                (540, 19),
                (540, 38),
                (826, 44),
                (926, 11),
                (930, 11),
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
        self.assertEqual({tuple(e["start_pos"]) for e in mul}, {(38, 51), (402, 4), (465, 4)})
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
            {(103, 32), (104, 32), (105, 32), (106, 40), (107, 38)},
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
        # Calibration's 84: the 56 domain equivalents from the full
        # 1937-item calibration session, plus 22 from the W2 proof
        # and 5 from the F2 re-proof append, minus 3 evaluate_threshold
        # entries in the changed function, plus 4 appended by the
        # defect-fix targeted proof: 56 + 22 + 5 - 3 + 4 = 84.
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
                40,
                43,
            },
            "occurrences must match the calibration full-session dump (1937/1539/397/335/62) "
            "plus the W2 proof and F2 re-proof appends, as re-derived by the W2 defect fix: "
            "the targeted-proof appends added occurrence 40 (the new Eq_LtE site in "
            "evaluate_threshold) and renumbered the later validate_no_contamination Eq_LtE "
            "entry 42 -> 43, while the repair renumbered the _save_artifact ReplaceTrueWithFalse "
            "entry 13 -> 11 (and _probability_metrics 17/18/19 -> 15/16/17) when the duplicate "
            "InferenceIdentity class's @dataclass(frozen=True, slots=True) decorator — two True "
            "sites — was deleted; the other three targeted-proof appends reuse occurrences "
            "37/38/39; the W4 refresh dropped the CalibrationArtifact.validation_issues "
            "domain entry (84 -> 83) because worker C rewrote validation_issues for the "
            "CORE-04 content-hash tamper check",
        )
        self.assertEqual(
            {e["function"] for e in calib_domain},
            {
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
        self.assertEqual(len(policy_domain), 26)
        self.assertEqual(
            {e["occurrence"] for e in policy_domain},
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 13, 14, 17},
            "occurrences must match the policy-298 full-session dump "
            "as renumbered by the W2 refresh plus the W1 Mul_Div 0/1 "
            "and the W2 proof Mul_Div 2-7, as re-derived by the W4 "
            "refresh (which dropped the Mul_Div 1/6/7, Eq_LtE 12 "
            "and USub_Invert 1 entries — the old "
            "PolicyRevisionFloor.check_policy/advance_floor sites, "
            "rewritten by worker D as _advanced_state/_check_against/"
            "_persist) "
            "plus the W4 re-proof append (ExceptionReplacer 11, "
            "NumberReplacer 1/6/7, Eq_LtE 10/14, ReplaceTrueWithFalse "
            "17, Delete_USub 0, USub_Not 0, USub_UAdd 0, and the new "
            "USub_Invert 0 at (725, 48) in "
            "CapabilityPolicyEngine.evaluate)",
        )
        self.assertEqual(
            {e["function"] for e in policy_domain},
            {
                "CapabilityLedger.enforce",
                "CapabilityLedger.get",
                "CapabilityLedger.is_validated",
                "CapabilityPolicyEngine.evaluate",
                "EnterprisePolicyEngine.load_policy",
                "PolicyRevisionFloor._advanced_state",
                "PolicyRevisionFloor._check_against",
                "PolicyRevisionFloor._persist",
                "_claim_is_effective",
                "_policy_floor_lock",
                "claim_is_expired",
                "ledger_to_trust_dimension",
                "validate_claim",
            },
        )
        self.assertEqual(
            {tuple(e["start_pos"]) for e in policy_domain},
            {
                (173, 45),
                (230, 18),
                (232, 59),
                (332, 8),
                (354, 8),
                (364, 48),
                (370, 8),
                (453, 43),
                (468, 18),
                (469, 35),
                (548, 31),
                (549, 33),
                (713, 32),
                (725, 48),
                (725, 49),
                (728, 34),
                (728, 53),
                (1112, 29),
                (1322, 40),
                (1362, 29),
                (1395, 32),
                (1598, 15),
            },
        )
        self.assertEqual(
            {e["source_text"] for e in policy_domain},
            {"!=", "*", "-", "0", "1", "==", "True", "ValueError"},
        )
        self.assertEqual(
            {e["operator"] for e in policy_domain},
            {
                "core/ExceptionReplacer",
                "core/NumberReplacer",
                "core/ReplaceBinaryOperator_Mul_Div",
                "core/ReplaceComparisonOperator_Eq_Is",
                "core/ReplaceComparisonOperator_Eq_LtE",
                "core/ReplaceComparisonOperator_NotEq_IsNot",
                "core/ReplaceTrueWithFalse",
                "core/ReplaceUnaryOperator_Delete_USub",
                "core/ReplaceUnaryOperator_USub_Invert",
                "core/ReplaceUnaryOperator_USub_Not",
                "core/ReplaceUnaryOperator_USub_UAdd",
            },
        )
        self.assertEqual(
            {e["id"] for e in policy_domain},
            {
                "textforensics.policy:core/ExceptionReplacer:11",
                "textforensics.policy:core/NumberReplacer:1",
                "textforensics.policy:core/NumberReplacer:6",
                "textforensics.policy:core/NumberReplacer:7",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:0",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:2",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:3",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:4",
                "textforensics.policy:core/ReplaceBinaryOperator_Mul_Div:5",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:0",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:2",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:3",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:4",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:5",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_Is:6",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:7",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:8",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:10",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:13",
                "textforensics.policy:core/ReplaceComparisonOperator_Eq_LtE:14",
                "textforensics.policy:core/ReplaceComparisonOperator_NotEq_IsNot:0",
                "textforensics.policy:core/ReplaceTrueWithFalse:17",
                "textforensics.policy:core/ReplaceUnaryOperator_Delete_USub:0",
                "textforensics.policy:core/ReplaceUnaryOperator_USub_Invert:0",
                "textforensics.policy:core/ReplaceUnaryOperator_USub_Not:0",
                "textforensics.policy:core/ReplaceUnaryOperator_USub_UAdd:0",
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
        self.assertEqual(summary["baseline_entries"], 6938)
        self.assertEqual(summary["equivalent"], 2)
        # The other 6936 entries matched no live survivor in this run.
        self.assertEqual(summary["equivalent_dormant"], 6936)
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
        self.assertEqual(summary["equivalent_dormant"], 6936)
        self.assertEqual(summary["unexplained_surviving"], 0)
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_module_level_runtime_entry_validates(self):
        """A runtime entry on a module-level statement (no enclosing
        function) validates against the enclosing top-level
        statement's fingerprint, and goes stale when the statement
        changes. (W3: the watermarking ``_WINDOWS_RESERVED_NAMES``
        ``BitOr_BitXor`` mutants — ``|`` -> ``^`` is equivalent
        because the three sets are pairwise disjoint, but the
        assignment sits at module level, so no function fingerprint
        exists to pin it.)"""
        import ast

        runner = self.runner
        source_path = self.project_root / "src" / "textforensics" / "watermarking.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        # The top-level Assign statement containing line 132.
        assign = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and (node.lineno, node.col_offset)
            <= (132, 4)
            < (node.end_lineno or node.lineno, node.end_col_offset or 0)
        )
        fingerprint = runner._function_fingerprint(source, assign)
        entry = {
            "id": "textforensics.watermarking:core/ReplaceBinaryOperator_BitOr_BitXor:0",
            "module": "textforensics.watermarking",
            "operator": "core/ReplaceBinaryOperator_BitOr_BitXor",
            "occurrence": 0,
            "start_pos": [132, 4],
            "end_pos": [132, 5],
            "function": "<module>",
            "kind": "domain-equivalent",
            "source_text": "|",
            "source_fingerprint": fingerprint,
            "reason": (
                "The three sets are pairwise disjoint (literal reserved "
                "names, COM1-9, LPT1-9), so union and symmetric difference "
                "coincide on every input."
            ),
        }
        ok, reason = runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, reason)
        # A stale statement fingerprint must fail loudly.
        tampered = dict(entry, source_fingerprint="0" * 64)
        ok, reason = runner.validate_baseline_entry(tampered, self.project_root)
        self.assertFalse(ok, "changed statement fingerprint must not validate")
        self.assertIn("fingerprint mismatch", reason)
        # A module-level entry naming a real function must fail.
        wrong_fn = dict(entry, function="_is_valid_key_id")
        ok, reason = runner.validate_baseline_entry(wrong_fn, self.project_root)
        self.assertFalse(ok, "module-level entry with a function must not validate")
        self.assertIn("enclosing function changed", reason)

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
        of the 6938 entries. The per-module context cache must parse
        each of the 44 modules once, and a second full classify must
        parse nothing. (The cache cap in scripts/run_mutation.py is
        64: at the W3 cap of 32 the 37-module W4 baseline evicted
        policy and parsed it twice.)
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
            self.assertEqual(summary["baseline_entries"], 6938)
            self.assertEqual(len(summary["stale_baseline_entries"]), 0)
            self.assertEqual(calls["n"], 44, "one parse per distinct module")
            # A second full classify hits the cache: no further parses,
            # and the result is identical.
            summary2 = runner.classify_baseline([], self.baseline, self.project_root)
            self.assertEqual(summary2, summary)
            self.assertEqual(calls["n"], 44, "second classify must parse nothing")
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
        self.assertEqual(len(runtime), 23)
        records = [self._record_for_entry(e, "survived") for e in runtime]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["total"], 23)
        self.assertEqual(summary["surviving"], 23)
        self.assertEqual(summary["equivalent"], 23)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_domain_equivalent_mutants_accepted(self):
        """Survivors matching re-validated domain-equivalent entries are accepted (exit 0)."""
        runtime = [e for e in self.baseline["entries"] if e["kind"] == "domain-equivalent"]
        self.assertEqual(len(runtime), 796)
        self.assertEqual(
            {e["module"] for e in runtime},
            {
                "textforensics._build_info",
                "textforensics._standalone_verify",
                "textforensics.adversarial",
                "textforensics.analyzers",
                "textforensics.atomic_io",
                "textforensics.benchmark",
                "textforensics.bundle",
                "textforensics.bundle_consistency",
                "textforensics.calibration",
                "textforensics.casefile",
                "textforensics.cli",
                "textforensics.consensus",
                "textforensics.datasets",
                "textforensics.detection_cache",
                "textforensics.detectors",
                "textforensics.engine",
                "textforensics.evidence",
                "textforensics.execution_policy",
                "textforensics.explain",
                "textforensics.ledger",
                "textforensics.mixed_origin",
                "textforensics.model_card",
                "textforensics.observatory",
                "textforensics.policy",
                "textforensics.probe_metrics",
                "textforensics.probe_runs",
                "textforensics.report",
                "textforensics.result_codec",
                "textforensics.retry",
                "textforensics.rich_output",
                "textforensics.schema",
                "textforensics.sealed_bundle",
                "textforensics.sealing",
                "textforensics.semantic",
                "textforensics.timestamp",
                "textforensics.trust",
                "textforensics.validation",
                "textforensics.verify",
                "textforensics.watermarking",
                "textforensics.web_ui.main",
                "textforensics.workspace_integrity",
            },
        )
        records = [self._record_for_entry(e, "survived") for e in runtime]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["total"], 796)
        self.assertEqual(summary["surviving"], 796)
        self.assertEqual(summary["equivalent"], 796)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_unobservable_value_mutants_accepted(self):
        """Survivors matching re-validated unobservable-value entries are accepted (exit 0)."""
        runtime = [e for e in self.baseline["entries"] if e["kind"] == "unobservable-value"]
        self.assertEqual(len(runtime), 243)
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
            "textforensics.sealing": str(
                self.project_root / "src" / "textforensics" / "sealing.py"
            ),
            "textforensics.sealed_bundle": str(
                self.project_root / "src" / "textforensics" / "sealed_bundle.py"
            ),
            "textforensics.verify": str(self.project_root / "src" / "textforensics" / "verify.py"),
            "textforensics.probe_runs": str(
                self.project_root / "src" / "textforensics" / "probe_runs.py"
            ),
            "textforensics.probe_metrics": str(
                self.project_root / "src" / "textforensics" / "probe_metrics.py"
            ),
            "textforensics.datasets": str(
                self.project_root / "src" / "textforensics" / "datasets.py"
            ),
            "textforensics.cli": str(self.project_root / "src" / "textforensics" / "cli.py"),
            "textforensics.detection_cache": str(
                self.project_root / "src" / "textforensics" / "detection_cache.py"
            ),
            "textforensics.ledger": str(self.project_root / "src" / "textforensics" / "ledger.py"),
            "textforensics.observatory": str(
                self.project_root / "src" / "textforensics" / "observatory.py"
            ),
            "textforensics.detectors": str(
                self.project_root / "src" / "textforensics" / "detectors.py"
            ),
            "textforensics._build_info": str(
                self.project_root / "src" / "textforensics" / "_build_info.py"
            ),
            "textforensics.web_ui.main": str(
                self.project_root / "src" / "textforensics" / "web_ui/main.py"
            ),
            "textforensics.report": str(self.project_root / "src" / "textforensics" / "report.py"),
            "textforensics.rich_output": str(
                self.project_root / "src" / "textforensics" / "rich_output.py"
            ),
            "textforensics.result_codec": str(
                self.project_root / "src" / "textforensics" / "result_codec.py"
            ),
            "textforensics.bundle_consistency": str(
                self.project_root / "src" / "textforensics" / "bundle_consistency.py"
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
        self.assertEqual(summary["total"], 243)
        self.assertEqual(summary["surviving"], 243)
        self.assertEqual(summary["equivalent"], 243)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_occurrence_disambiguates_same_position_mutants(self):
        """Two entries at one position differ only by occurrence — and match only their own mutant.

        L1707:21 in verify_bundle_bytes carries occurrences 510 (`2` ->
        `3`, unobservable-value) and 511 (`2` -> `1`, unobservable-value)
        — the report dict's initial exit_code, overwritten on every path
        before return. A survivor with an occurrence that matches neither
        entry (e.g. a hypothetical `2` -> `0`) must stay unexplained
        even though its position matches both entries.
        (The W1 pair at L628:76, occurrences 50/51, is gone: those trust
        entries were dropped in the W2 refresh, so the test moved to the
        F2 re-proof pair; that pair is gone too — the W3 F2 refresh
        re-derived the exit_code position 1365 -> 1686 and renumbered
        the occurrences 486/487 -> 510/511 — so the test moved again;
        the W3 F4 refresh re-derived the exit_code position 1686 -> 1707
        with occurrences unchanged — so the test moved again.)
        """
        runtime = {
            e["occurrence"]: e
            for e in self.baseline["entries"]
            if e["kind"] == "unobservable-value"
            and e["module"] == "textforensics._standalone_verify"
            and tuple(e["start_pos"]) == (1707, 21)
        }
        entry_510 = runtime[510]
        entry_511 = runtime[511]
        self.assertEqual(tuple(entry_510["start_pos"]), tuple(entry_511["start_pos"]))
        self.assertEqual(tuple(entry_510["end_pos"]), tuple(entry_511["end_pos"]))

        records = [
            self._record_for_entry(entry_510, "survived"),
            self._record_for_entry(entry_511, "survived"),
            self._record(
                operator="core/NumberReplacer",
                occurrence=99,
                start_pos=(1707, 21),
                end_pos=(1707, 22),
                outcome="survived",
                module_path=str(
                    self.project_root / "src" / "textforensics" / "_standalone_verify.py"
                ),
            ),
        ]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["surviving"], 3)
        self.assertEqual(summary["equivalent"], 2)
        self.assertEqual(summary["equivalent_mutants"], [entry_510["id"], entry_511["id"]])
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
        (CapabilityPolicyEngine.evaluate, L715:33) — the dispatch for
        the new runtime kind must accept it exactly like an
        unreachable-condition entry.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 715, 33)
        self.assertEqual(name, "CapabilityPolicyEngine.evaluate")
        entry = {
            "id": "test:unobservable-value",
            "module": "textforensics.policy",
            "operator": "core/NumberReplacer",
            "occurrence": 4,
            "start_pos": [715, 33],
            "end_pos": [715, 34],
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
        L715:33); the reason names the proof shape (closed-domain value
        identity), as the kind requires.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 715, 33)
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
            "start_pos": [715, 33],
            "end_pos": [715, 34],
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

        The `4` in `@lru_cache(maxsize=4)` (L955:19) sits on the
        decorator line, above the `def` line: the enclosing-function
        lookup and the function fingerprint must both cover the
        decorator, or the entry for it could never validate.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 955, 19)
        self.assertEqual(name, "_load_enterprise_policy_schema")
        entry = {
            "id": "test:decorator-position",
            "module": "textforensics.policy",
            "operator": "core/NumberReplacer",
            "occurrence": 12,
            "start_pos": [955, 19],
            "end_pos": [955, 20],
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
        _, changed_node = self.runner._enclosing_function(changed_tree, 955, 19)
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
