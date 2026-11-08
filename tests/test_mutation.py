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
        # Policy tests live in test_enterprise_policy.py, not test_policy.py;
        # the override map scopes them instead of falling back to the full
        # suite (whose ~3-minute runtime exceeds the per-test-run timeout
        # and fails the cosmic-ray baseline before any mutant runs).
        policy = self.runner.test_command_for(["textforensics.policy"], self.project_root)
        self.assertEqual(policy, "python -m pytest tests/test_enterprise_policy.py -x -q")
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


class EquivalentBaselineTests(unittest.TestCase):
    """Tests for the equivalent-mutant baseline (mutation-baseline.toml).

    The baseline accepts only mutants verified equivalent (see the baseline
    file's header for the proof); the gate still fails on any unexplained
    survivor (exit 2) and on any stale entry (exit 1).
    """

    #: The annotation positions the 69 annotation baseline entries cover,
    #: verified against CI run 42393966895 (dump + AST + tokenize +
    #: empirical probe), plus the 3 runtime positions of the 4
    #: unreachable-condition entries — and the 9 annotation positions +
    #: 3 runtime positions of the 82 policy entries (wave 4E, local
    #: budget-200 repro run on 6159552: dump + AST + 85/85 probe).
    EXPECTED_POSITIONS = {
        (141, 53),
        (189, 28),
        (337, 31),
        (340, 28),
        (341, 18),
        (341, 24),
        (344, 28),
        (345, 26),
        (430, 32),
        (431, 31),
        (432, 28),
        (433, 18),
        (433, 24),
        (436, 28),
        (437, 26),
        (448, 24),
        (553, 54),
        (553, 76),
        # Policy annotation positions.
        (126, 72),
        (670, 25),
        (671, 19),
        (672, 23),
        # +5: the strip fix (284b118) added five lines inside
        # _load_or_generate_key above these positions.
        (912, 33),
        (913, 35),
        (919, 41),
        (927, 43),
        (934, 35),
        # Policy runtime positions.
        (376, 33),
        (381, 78),
        (540, 19),
        # Benchmark annotation positions (15) + runtime positions (2).
        (32, 29),
        (41, 14),
        (123, 14),
        (146, 14),
        (242, 14),
        (272, 40),
        (442, 14),
        (446, 28),
        (490, 14),
        (543, 15),
        (545, 15),
        (619, 31),
        (630, 14),
        (643, 26),
        (645, 25),
        (35, 46),
        (35, 53),
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

    def test_baseline_file_loads_with_324_entries(self):
        """The baseline has exactly the 324 verified equivalent mutants.

        69 annotation BitOr mutants + 4 unreachable-condition
        NumberReplacer mutants for trust (see the baseline file's header
        for both proofs), plus 78 annotation BitOr mutants + 4
        unobservable-value NumberReplacer mutants for policy (wave 4E),
        plus 165 annotation BitOr mutants + 4 unobservable-value
        NumberReplacer mutants for benchmark (Phase 5 survivors wave,
        full 909-item session at 8e6ffd1).
        Match keys include occurrence: two entries share the
        (module, operator, start_pos, end_pos) of L553:76 and differ
        only by occurrence (44 vs 45).
        """
        self.assertEqual(self.baseline["version"], 1)
        self.assertEqual(self.baseline["source_run"], "42393966895")
        self.assertEqual(self.baseline["source_commit"], "153b5ab")
        entries = self.baseline["entries"]
        self.assertEqual(len(entries), 324)
        self.assertEqual(len({e["id"] for e in entries}), 324, "entry ids must be unique")
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
        self.assertEqual(len(keys), 324, "match keys must be unique")
        from collections import Counter

        self.assertEqual(
            Counter(e["operator"] for e in entries),
            {
                "core/ReplaceBinaryOperator_BitOr_Add": 39,
                "core/ReplaceBinaryOperator_BitOr_BitAnd": 39,
                "core/ReplaceBinaryOperator_BitOr_BitXor": 39,
                "core/ReplaceBinaryOperator_BitOr_Div": 39,
                "core/ReplaceBinaryOperator_BitOr_FloorDiv": 33,
                "core/ReplaceBinaryOperator_BitOr_LShift": 24,
                "core/ReplaceBinaryOperator_BitOr_Mod": 24,
                "core/ReplaceBinaryOperator_BitOr_Mul": 24,
                "core/ReplaceBinaryOperator_BitOr_Pow": 21,
                "core/ReplaceBinaryOperator_BitOr_RShift": 15,
                "core/ReplaceBinaryOperator_BitOr_Sub": 15,
                "core/NumberReplacer": 12,
            },
        )
        self.assertEqual({tuple(e["start_pos"]) for e in entries}, self.EXPECTED_POSITIONS)
        for entry in entries:
            self.assertIn(
                entry["module"],
                {"textforensics.trust", "textforensics.policy", "textforensics.benchmark"},
            )
            self.assertTrue(entry["reason"], f"entry {entry['id']} needs a reason")
            self.assertIn(entry["function"], entry["reason"])
            if entry["kind"] in self.runner.BASELINE_ANNOTATION_KINDS:
                self.assertIn(entry["annotation"], entry["reason"])
            else:
                self.assertIn(
                    entry["kind"],
                    {"unreachable-condition", "unobservable-value"},
                )
                self.assertIn(entry["source_text"], entry["reason"])
                self.assertEqual(len(entry["source_fingerprint"]), 64)

    def test_runtime_entries(self):
        """The 12 runtime entries carry their equivalence proofs."""
        runtime = [
            e for e in self.baseline["entries"] if e["kind"] in self.runner.BASELINE_RUNTIME_KINDS
        ]
        self.assertEqual(len(runtime), 12)
        unreachable = [e for e in runtime if e["kind"] == "unreachable-condition"]
        self.assertEqual(len(unreachable), 4)
        by_id = {e["id"]: e for e in runtime}
        self.assertEqual(
            {e["occurrence"] for e in unreachable},
            {39, 42, 44, 45},
            "occurrences must match the CI dump (survivor indices 41/44/46/47)",
        )
        # Two entries share one position and differ only by occurrence.
        at_542_76 = [e for e in unreachable if tuple(e["start_pos"]) == (553, 76)]
        self.assertEqual(len(at_542_76), 2)
        self.assertEqual({e["occurrence"] for e in at_542_76}, {44, 45})
        self.assertEqual({e["source_text"] for e in at_542_76}, {"2"})
        # Same enclosing function, hence the same fingerprint.
        self.assertEqual(len({e["source_fingerprint"] for e in at_542_76}), 1)
        self.assertEqual(
            by_id["textforensics.trust:core/NumberReplacer:39"]["function"],
            "build_trust_map",
        )
        self.assertEqual(by_id["textforensics.trust:core/NumberReplacer:39"]["source_text"], "0")
        unobservable = [e for e in runtime if e["kind"] == "unobservable-value"]
        self.assertEqual(len(unobservable), 8)
        self.assertEqual(
            {e["occurrence"] for e in unobservable},
            {0, 1, 2, 3, 4, 8, 22, 23},
            "occurrences must match the policy budget-200 dump + the "
            "benchmark full-session dump",
        )
        self.assertEqual(
            {e["function"] for e in unobservable},
            {"CapabilityPolicyEngine.evaluate", "_load_enterprise_policy_schema", "dataset_sha256"},
        )
        self.assertEqual(
            {e["source_text"] for e in unobservable},
            {"2", "1", "4", "1024"},
        )
        # The two lru_cache entries share one position and function.
        at_540_19 = [e for e in unobservable if tuple(e["start_pos"]) == (540, 19)]
        self.assertEqual(len(at_540_19), 2)
        self.assertEqual({e["occurrence"] for e in at_540_19}, {22, 23})
        self.assertEqual(len({e["source_fingerprint"] for e in at_540_19}), 1)
        # The four benchmark chunk-size entries share one function (and
        # hence one fingerprint) across two positions.
        bench = [e for e in unobservable if e["module"] == "textforensics.benchmark"]
        self.assertEqual(len(bench), 4)
        self.assertEqual({e["occurrence"] for e in bench}, {0, 1, 2, 3})
        self.assertEqual({tuple(e["start_pos"]) for e in bench}, {(35, 46), (35, 53)})
        self.assertEqual({e["source_text"] for e in bench}, {"1024"})
        self.assertEqual(len({e["source_fingerprint"] for e in bench}), 1)
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
        self.assertEqual(summary["baseline_entries"], 324)
        self.assertEqual(summary["equivalent"], 2)
        # The other 322 entries matched no live survivor in this run.
        self.assertEqual(summary["equivalent_dormant"], 322)
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
        self.assertEqual(summary["equivalent_dormant"], 322)
        self.assertEqual(summary["unexplained_surviving"], 0)
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_stale_baseline_entry_fails_loudly(self):
        """An entry whose position moved out of an annotation fails (exit 1)."""
        import copy

        entry = copy.deepcopy(self.baseline["entries"][0])
        # Move the entry onto runtime code (L311 is `if supported == 0 ...`).
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

    def test_unreachable_condition_mutants_accepted(self):
        """Survivors matching re-validated runtime entries are accepted (exit 0)."""
        runtime = [e for e in self.baseline["entries"] if e["kind"] == "unreachable-condition"]
        self.assertEqual(len(runtime), 4)
        records = [self._record_for_entry(e, "survived") for e in runtime]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["surviving"], 4)
        self.assertEqual(summary["equivalent"], 4)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_unobservable_value_mutants_accepted(self):
        """Survivors matching re-validated unobservable-value entries are accepted (exit 0)."""
        runtime = [e for e in self.baseline["entries"] if e["kind"] == "unobservable-value"]
        self.assertEqual(len(runtime), 8)
        module_paths = {
            "textforensics.policy": str(self.project_root / "src" / "textforensics" / "policy.py"),
            "textforensics.benchmark": str(
                self.project_root / "src" / "textforensics" / "benchmark.py"
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
        self.assertEqual(summary["total"], 8)
        self.assertEqual(summary["surviving"], 8)
        self.assertEqual(summary["equivalent"], 8)
        self.assertEqual(summary["unexplained_surviving"], 0)
        self.assertEqual(summary["equivalent_mutants"], [e["id"] for e in runtime])
        result = self._check_summary(summary)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("accepted as equivalent", result.stdout)

    def test_occurrence_disambiguates_same_position_mutants(self):
        """Two entries at one position differ only by occurrence — and match only their own mutant.

        L553:76 carries occurrences 44 (`2` -> `3`, equivalent) and 45
        (`2` -> `1`, equivalent). A survivor with an occurrence that
        matches neither entry (e.g. a hypothetical `2` -> `0`) must stay
        unexplained even though its position matches both entries.
        """
        runtime = {
            e["occurrence"]: e
            for e in self.baseline["entries"]
            if e["kind"] == "unreachable-condition"
        }
        entry_44 = runtime[44]
        entry_45 = runtime[45]
        self.assertEqual(tuple(entry_44["start_pos"]), tuple(entry_45["start_pos"]))
        self.assertEqual(tuple(entry_44["end_pos"]), tuple(entry_45["end_pos"]))

        records = [
            self._record_for_entry(entry_44, "survived"),
            self._record_for_entry(entry_45, "survived"),
            self._record(
                operator="core/NumberReplacer",
                occurrence=99,
                start_pos=(553, 76),
                end_pos=(553, 77),
                outcome="survived",
            ),
        ]
        summary = self.runner.parse_results(records, self.baseline, self.project_root)
        self.assertEqual(summary["surviving"], 3)
        self.assertEqual(summary["equivalent"], 2)
        self.assertEqual(summary["equivalent_mutants"], [entry_44["id"], entry_45["id"]])
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
        (CapabilityPolicyEngine.evaluate, L376:33) — the dispatch for
        the new runtime kind must accept it exactly like an
        unreachable-condition entry.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 376, 33)
        self.assertEqual(name, "CapabilityPolicyEngine.evaluate")
        entry = {
            "id": "test:unobservable-value",
            "module": "textforensics.policy",
            "operator": "core/NumberReplacer",
            "occurrence": 4,
            "start_pos": [376, 33],
            "end_pos": [376, 34],
            "function": name,
            "kind": "unobservable-value",
            "reason": "synthetic test entry",
            "source_text": "2",
            "source_fingerprint": self.runner._function_fingerprint(source, node),
        }
        ok, reason = self.runner.validate_baseline_entry(entry, self.project_root)
        self.assertTrue(ok, f"unobservable-value entry must validate: {reason}")

    def test_decorator_position_entry_validates(self):
        """A runtime entry on a decorator line re-validates.

        The `4` in `@lru_cache(maxsize=4)` (L540:19) sits on the
        decorator line, above the `def` line: the enclosing-function
        lookup and the function fingerprint must both cover the
        decorator, or the entry for it could never validate.
        """
        import ast

        source = (self.project_root / "src" / "textforensics" / "policy.py").read_text()
        tree = ast.parse(source)
        name, node = self.runner._enclosing_function(tree, 540, 19)
        self.assertEqual(name, "_load_enterprise_policy_schema")
        entry = {
            "id": "test:decorator-position",
            "module": "textforensics.policy",
            "operator": "core/NumberReplacer",
            "occurrence": 22,
            "start_pos": [540, 19],
            "end_pos": [540, 20],
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
        _, changed_node = self.runner._enclosing_function(changed_tree, 540, 19)
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
