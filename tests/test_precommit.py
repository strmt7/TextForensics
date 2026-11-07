#!/usr/bin/env python3
"""
Tests for pre-commit hooks and validation scripts.

These tests verify that the custom pre-commit validation scripts work correctly.
"""

import json
import sys
from pathlib import Path

import pytest


class TestValidateSchemas:
    """Tests for validate_schemas.py script."""

    def test_valid_schema_passes(self, tmp_path: Path):
        """Test that a valid JSON schema passes validation."""
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
        schema_file = tmp_path / "test.schema.json"
        schema_file.write_text(json.dumps(schema))

        # Import and run the validation
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_schemas import validate_schema_file

        ok, msg = validate_schema_file(schema_file)
        assert ok, f"Valid schema should pass: {msg}"
        assert "OK" in msg

    def test_invalid_json_fails(self, tmp_path: Path):
        """Test that invalid JSON fails validation."""
        schema_file = tmp_path / "invalid.json"
        schema_file.write_text("{ invalid json }")

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_schemas import validate_schema_file

        ok, msg = validate_schema_file(schema_file)
        assert not ok
        assert "Invalid JSON" in msg

    def test_missing_schema_field_fails(self, tmp_path: Path):
        """Test that missing $schema field fails validation."""
        schema = {"type": "object", "properties": {}}
        schema_file = tmp_path / "missing_schema.json"
        schema_file.write_text(json.dumps(schema))

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_schemas import validate_schema_file

        ok, msg = validate_schema_file(schema_file)
        assert not ok
        assert "Missing" in msg and "$schema" in msg

    def test_invalid_schema_fails(self, tmp_path: Path):
        """Test that an invalid JSON schema fails validation."""
        # This schema has an invalid 'type' value
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "invalid_type"}
        schema_file = tmp_path / "invalid_schema.json"
        schema_file.write_text(json.dumps(schema))

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_schemas import validate_schema_file

        ok, msg = validate_schema_file(schema_file)
        assert not ok
        assert "Schema validation error" in msg

    def test_packaged_schemas_are_the_single_source(self):
        """No top-level schemas/ duplicate may exist.

        Regression test for the diverged duplicate: the golden case file
        validated against the packaged schema but was rejected by the
        stale top-level copy.
        """
        repo_root = Path(__file__).parent.parent
        assert not (repo_root / "schemas").exists(), (
            "top-level schemas/ must not exist; src/textforensics/schemas/ is the single source"
        )
        packaged = repo_root / "src" / "textforensics" / "schemas"
        names = sorted(p.name for p in packaged.glob("*.json"))
        assert names == [
            "case-file.schema.json",
            "detector-result.schema.json",
            "enterprise-policy.schema.json",
            "evidence-record.schema.json",
            "evidence-registry.schema.json",
            "forensic-bundle.schema.json",
            "mixed-origin-report.schema.json",
            "probe-run.schema.json",
            "run-artifact.schema.json",
            "sealed-bundle-manifest.schema.json",
            "trust-map.schema.json",
            "validation-registry.schema.json",
        ]


class TestValidateAgentsRules:
    """Tests for validate_agents_rules.py script."""

    def test_no_claims_passes(self, tmp_path: Path):
        """Test that README with no numeric claims passes."""
        readme = tmp_path / "README.md"
        readme.write_text("# Project\n\nThis is a description without numbers.")

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_agents_rules import extract_numeric_claims

        claims = extract_numeric_claims(readme)
        assert len(claims) == 0

    def test_percentage_claims_detected(self, tmp_path: Path):
        """Test that percentage claims are detected."""
        readme = tmp_path / "README.md"
        readme.write_text("# Project\n\nAchieves 95% accuracy on benchmarks.")

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_agents_rules import extract_numeric_claims

        claims = extract_numeric_claims(readme)
        assert len(claims) == 1
        assert "95%" in claims[0][0]

    def test_auroc_claims_detected(self, tmp_path: Path):
        """Test that AUROC claims are detected."""
        readme = tmp_path / "README.md"
        readme.write_text("# Project\n\nAUROC: 0.92 on test set.")

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_agents_rules import extract_numeric_claims

        claims = extract_numeric_claims(readme)
        assert len(claims) == 1
        assert "0.92" in claims[0][0]

    def test_performance_claims_detected(self, tmp_path: Path):
        """Test that performance claims are detected."""
        readme = tmp_path / "README.md"
        readme.write_text("# Project\n\n2x faster than baseline.")

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_agents_rules import extract_numeric_claims

        claims = extract_numeric_claims(readme)
        assert len(claims) == 1
        assert "2x faster" in claims[0][0]

    def test_f1_claims_detected(self, tmp_path: Path):
        """Test that F1 score claims are detected."""
        readme = tmp_path / "README.md"
        readme.write_text("# Project\n\nF1 score of 0.87 achieved.")

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_agents_rules import extract_numeric_claims

        claims = extract_numeric_claims(readme)
        assert len(claims) == 1
        assert "0.87" in claims[0][0]


class TestValidatePyprojectDeps:
    """Tests for validate_pyproject_deps.py script."""

    def test_sorted_dependencies_pass(self, tmp_path: Path):
        """Test that alphabetically sorted dependencies pass."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""
[project]
dependencies = [
    "httpx>=0.27,<1",
    "pytest>=8,<9",
    "ruff>=0.8,<1",
]

[project.optional-dependencies]
dev = [
    "build>=1.2,<2",
    "coverage>=7.5,<8",
    "pytest-cov>=5,<6",
]
""")

        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        # Read and parse
        import tomllib

        from validate_pyproject_deps import check_sorted

        with pyproject.open("rb") as f:
            data = tomllib.load(f)

        # Check main deps
        issues = check_sorted(data["project"]["dependencies"], "project.dependencies")
        assert len(issues) == 0

        # Check optional deps
        for group, deps in data["project"]["optional-dependencies"].items():
            issues = check_sorted(deps, f"project.optional-dependencies.{group}")
            assert len(issues) == 0

    def test_unsorted_dependencies_fail(self, tmp_path: Path):
        """Test that unsorted dependencies fail."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_pyproject_deps import check_sorted

        # Unsorted: ruff comes before pytest alphabetically
        deps = ["ruff>=0.8,<1", "httpx>=0.27,<1", "pytest>=8,<9"]
        issues = check_sorted(deps, "test")
        assert len(issues) == 1
        assert "not sorted alphabetically" in issues[0]

    def test_case_insensitive_sorting(self, tmp_path: Path):
        """Test that sorting is case-insensitive."""
        sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
        from validate_pyproject_deps import check_sorted

        # Already sorted case-insensitively: httpx < pytest < ruff
        deps = ["httpx>=0.27,<1", "Pytest>=8,<9", "Ruff>=0.8,<1"]
        issues = check_sorted(deps, "test")
        assert len(issues) == 0  # Should pass when sorted case-insensitively


class TestPrecommitConfig:
    """Tests for .pre-commit-config.yaml validity."""

    def test_precommit_config_exists(self):
        """Test that .pre-commit-config.yaml exists."""
        config_path = Path(__file__).parent.parent / ".pre-commit-config.yaml"
        assert config_path.exists(), ".pre-commit-config.yaml should exist"

    def test_precommit_config_valid_yaml(self):
        """Test that .pre-commit-config.yaml is valid YAML."""
        import yaml

        config_path = Path(__file__).parent.parent / ".pre-commit-config.yaml"
        with config_path.open() as f:
            config = yaml.safe_load(f)

        assert "repos" in config
        assert isinstance(config["repos"], list)
        assert len(config["repos"]) > 0

    def test_required_hooks_present(self):
        """Test that all required hooks are configured."""
        import yaml

        config_path = Path(__file__).parent.parent / ".pre-commit-config.yaml"
        with config_path.open() as f:
            config = yaml.safe_load(f)

        # Collect all hook IDs
        hook_ids = []
        for repo in config["repos"]:
            for hook in repo.get("hooks", []):
                hook_ids.append(hook["id"])

        # Required hooks from the task
        required_hooks = [
            "ruff",
            "ruff-format",
            "check-yaml",
            "check-json",
            "check-toml",
            "detect-secrets",
            "check-merge-conflict",
            "end-of-file-fixer",
            "trailing-whitespace",
            "mixed-line-ending",
            "json-schema-validator",  # Custom local hook
            "agents-md-rule-validation",  # Custom local hook
            "validate-pyproject-deps",  # Custom local hook
        ]

        for required in required_hooks:
            assert required in hook_ids, (
                f"Required hook '{required}' not found in pre-commit config"
            )


class TestRenovateConfig:
    """Tests for renovate.json validity."""

    def test_renovate_config_exists(self):
        """Test that renovate.json exists."""
        config_path = Path(__file__).parent.parent / "renovate.json"
        assert config_path.exists(), "renovate.json should exist"

    def test_renovate_config_valid_json(self):
        """Test that renovate.json is valid JSON."""
        config_path = Path(__file__).parent.parent / "renovate.json"
        with config_path.open() as f:
            config = json.load(f)

        assert "$schema" in config
        assert "schedule" in config
        assert "packageRules" in config

    def test_schedule_is_weekly_monday(self):
        """Test that schedule is weekly on Monday 9 AM UTC."""
        config_path = Path(__file__).parent.parent / "renovate.json"
        with config_path.open() as f:
            config = json.load(f)

        # Check schedule contains Monday 9 AM
        schedule = config.get("schedule", [])
        assert any("Monday" in s and "09:00" in s for s in schedule), (
            "Schedule should be Monday 09:00 UTC"
        )

    def test_automerge_patch_minor(self):
        """Test that patch/minor updates have automerge enabled."""
        config_path = Path(__file__).parent.parent / "renovate.json"
        with config_path.open() as f:
            config = json.load(f)

        package_rules = config.get("packageRules", [])
        patch_minor_rule = None
        for rule in package_rules:
            if rule.get("matchUpdateTypes") == ["patch", "minor"]:
                patch_minor_rule = rule
                break

        assert patch_minor_rule is not None, "Should have rule for patch/minor updates"
        assert patch_minor_rule.get("automerge") is True, (
            "Patch/minor should have automerge enabled"
        )

    def test_major_updates_needs_review(self):
        """Test that major updates create PRs with needs-review label."""
        config_path = Path(__file__).parent.parent / "renovate.json"
        with config_path.open() as f:
            config = json.load(f)

        package_rules = config.get("packageRules", [])
        major_rule = None
        for rule in package_rules:
            if rule.get("matchUpdateTypes") == ["major"]:
                major_rule = rule
                break

        assert major_rule is not None, "Should have rule for major updates"
        assert major_rule.get("automerge") is False, "Major should not automerge"
        labels = major_rule.get("labels", [])
        assert "needs-review" in labels, "Major updates should have needs-review label"

    def test_security_vulnerability_alerts(self):
        """Test that security vulnerability alerts create high-priority PRs."""
        config_path = Path(__file__).parent.parent / "renovate.json"
        with config_path.open() as f:
            config = json.load(f)

        vuln_alerts = config.get("vulnerabilityAlerts", {})
        assert vuln_alerts.get("enabled") is True
        labels = vuln_alerts.get("labels", [])
        assert "high-priority" in labels, "Vulnerability alerts should have high-priority label"
        assert vuln_alerts.get("minimumSeverity") == "moderate"

    def test_agpl_ignored(self):
        """Test that AGPL-3.0 license changes are ignored (require manual review)."""
        config_path = Path(__file__).parent.parent / "renovate.json"
        with config_path.open() as f:
            config = json.load(f)

        license_policy = config.get("licensePolicy", {})
        ignored = license_policy.get("ignore", [])
        assert "AGPL-3.0" in ignored or "AGPL-3.0-or-later" in ignored, (
            "AGPL-3.0 should be in ignore list"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
