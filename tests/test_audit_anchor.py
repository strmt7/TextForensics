"""Tests for the audit anchor system (rollback detection)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from textforensics.constants import EXIT_ERROR
from textforensics.ledger import (
    SCHEMA_VERSION,
    AuditAnchor,
    CalibrationChain,
    RollbackError,
    export_audit_anchor,
    verify_audit_anchor,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_file(path: Path, content: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Create a fake workspace with calibrations/ and benchmarks/ directories."""
    base = tmp_path / "workspace"
    (base / "calibrations").mkdir(parents=True)
    (base / "benchmarks").mkdir(parents=True)
    _make_file(base / "calibrations" / "det-a.json", '{"threshold": 0.5}')
    _make_file(base / "benchmarks" / "run1.json", '{"auroc": 0.9}')
    return base


# ---------------------------------------------------------------------------
# AuditAnchor serialization
# ---------------------------------------------------------------------------


class TestAuditAnchor:
    def test_to_dict_roundtrip(self):
        anchor = AuditAnchor(
            calibration_artifacts_sha256="a" * 64,
            benchmark_results_sha256="b" * 64,
            detector_versions={"alpha": "1.0"},
            calibration_chain=["c" * 64],
            exported_at="2026-01-01T00:00:00+00:00",
            schema_version=SCHEMA_VERSION,
        )
        data = anchor.to_dict()
        restored = AuditAnchor.from_dict(data)
        assert restored == anchor

    def test_from_dict_defaults(self):
        anchor = AuditAnchor.from_dict(
            {
                "calibration_artifacts_sha256": "a" * 64,
                "benchmark_results_sha256": "b" * 64,
            }
        )
        assert anchor.detector_versions == {}
        assert anchor.calibration_chain == []
        assert anchor.schema_version == SCHEMA_VERSION


# ---------------------------------------------------------------------------
# export_audit_anchor
# ---------------------------------------------------------------------------


class TestExportAuditAnchor:
    def test_export_computes_hashes(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert anchor.calibration_artifacts_sha256 != ""
        assert anchor.benchmark_results_sha256 != ""
        assert anchor.schema_version == SCHEMA_VERSION
        assert anchor.exported_at  # ISO timestamp set

    def test_export_is_deterministic(self, workspace: Path):
        a1 = export_audit_anchor(base_dir=workspace, detector_versions={})
        a2 = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert a1.calibration_artifacts_sha256 == a2.calibration_artifacts_sha256
        assert a1.benchmark_results_sha256 == a2.benchmark_results_sha256

    def test_export_changes_when_content_changes(self, workspace: Path):
        a1 = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.6}')
        a2 = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert a1.calibration_artifacts_sha256 != a2.calibration_artifacts_sha256

    def test_export_changes_when_file_renamed(self, workspace: Path):
        a1 = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-b.json", '{"threshold": 0.5}')
        a2 = export_audit_anchor(base_dir=workspace, detector_versions={})
        assert a1.calibration_artifacts_sha256 != a2.calibration_artifacts_sha256

    def test_export_empty_directories(self, tmp_path: Path):
        base = tmp_path / "empty"
        base.mkdir()
        anchor = export_audit_anchor(base_dir=base, detector_versions={})
        assert anchor.calibration_artifacts_sha256 == ""
        assert anchor.benchmark_results_sha256 == ""

    def test_export_missing_directories(self, tmp_path: Path):
        anchor = export_audit_anchor(base_dir=tmp_path / "nope", detector_versions={})
        assert anchor.calibration_artifacts_sha256 == ""
        assert anchor.benchmark_results_sha256 == ""

    def test_export_with_chain(self, workspace: Path):
        chain = CalibrationChain()
        chain.append("c" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=chain.hashes,
        )
        assert anchor.calibration_chain == ["c" * 64]

    def test_export_auto_detects_detectors(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace)
        # Auto-detection must produce a dict (possibly empty on failure)
        assert isinstance(anchor.detector_versions, dict)


# ---------------------------------------------------------------------------
# verify_audit_anchor
# ---------------------------------------------------------------------------


class TestVerifyAuditAnchor:
    def test_no_changes(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        status = verify_audit_anchor(anchor, base_dir=workspace)
        assert status == "no_changes"

    def test_calibration_rollback_raises(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.1}')
        with pytest.raises(RollbackError, match="Calibration artifacts rolled back"):
            verify_audit_anchor(anchor, base_dir=workspace)

    def test_benchmark_rollback_raises(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "benchmarks" / "run1.json", '{"auroc": 0.5}')
        with pytest.raises(RollbackError, match="Benchmark results rolled back"):
            verify_audit_anchor(anchor, base_dir=workspace)

    def test_both_rollback_raises(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        _make_file(workspace / "calibrations" / "det-a.json", "changed")
        _make_file(workspace / "benchmarks" / "run1.json", "changed")
        with pytest.raises(RollbackError) as exc_info:
            verify_audit_anchor(anchor, base_dir=workspace)
        msg = str(exc_info.value)
        assert "Calibration artifacts rolled back" in msg
        assert "Benchmark results rolled back" in msg

    def test_chain_valid_when_chain_extends(self, workspace: Path):
        anchor_chain = CalibrationChain()
        anchor_chain.append("c" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=anchor_chain.hashes,
        )
        # Now change calibration state (hash mismatch) but current chain extends
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.7}')
        current_chain = CalibrationChain()
        current_chain.append("c" * 64)
        current_chain.append("d" * 64)
        status = verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)
        assert status == "chain_valid"

    def test_chain_too_short_rollback(self, workspace: Path):
        anchor_chain = CalibrationChain()
        anchor_chain.append("c" * 64)
        anchor_chain.append("d" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=anchor_chain.hashes,
        )
        _make_file(workspace / "calibrations" / "det-a.json", "changed")
        current_chain = CalibrationChain()
        current_chain.append("c" * 64)
        with pytest.raises(RollbackError, match="Calibration artifacts rolled back"):
            verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)

    def test_chain_prefix_mismatch_rollback(self, workspace: Path):
        anchor_chain = CalibrationChain()
        anchor_chain.append("c" * 64)
        anchor = export_audit_anchor(
            base_dir=workspace,
            detector_versions={},
            calibration_chain=anchor_chain.hashes,
        )
        _make_file(workspace / "calibrations" / "det-a.json", "changed")
        # Current chain has wrong prefix
        current_chain = CalibrationChain()
        current_chain.append("e" * 64)
        current_chain.append("c" * 64)
        with pytest.raises(RollbackError):
            verify_audit_anchor(anchor, current_chain=current_chain, base_dir=workspace)

    def test_no_changes_takes_precedence_over_chain(self, workspace: Path):
        anchor = export_audit_anchor(base_dir=workspace, detector_versions={})
        chain = CalibrationChain()
        chain.append("c" * 64)
        status = verify_audit_anchor(anchor, current_chain=chain, base_dir=workspace)
        assert status == "no_changes"


# ---------------------------------------------------------------------------
# CalibrationChain
# ---------------------------------------------------------------------------


class TestCalibrationChain:
    def test_append_and_hashes(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.append("b" * 64)
        assert chain.hashes == ["a" * 64, "b" * 64]
        assert chain.length == 2

    def test_hashes_returns_copy(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        h = chain.hashes
        h.append("mutated")
        assert chain.hashes == ["a" * 64]

    def test_serialization_roundtrip(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.append("b" * 64)
        data = chain.to_dict()
        restored = CalibrationChain.from_dict(data)
        assert restored.hashes == chain.hashes

    def test_verify_integrity_ok(self):
        chain = CalibrationChain()
        chain.append(hashlib.sha256(b"one").hexdigest())
        chain.append(hashlib.sha256(b"two").hexdigest())
        assert chain.verify_integrity() == []

    def test_verify_integrity_bad_length(self):
        # Malformed entries can no longer be added via append() (it
        # validates), so build the chain through the lenient load path
        # that verify_integrity() exists to guard.
        chain = CalibrationChain.from_dict({"chain": ["short"], "length": 1})
        errors = chain.verify_integrity()
        assert any("length" in e for e in errors)

    def test_verify_integrity_bad_hex(self):
        chain = CalibrationChain.from_dict({"chain": ["z" * 64], "length": 1})
        errors = chain.verify_integrity()
        assert len(errors) == 1
        assert "hex" in errors[0]

    def test_append_rejects_short_entry(self):
        """Test that append fails loudly on a too-short hash."""
        chain = CalibrationChain()
        with pytest.raises(ValueError, match="64-character"):
            chain.append("short")
        assert chain.hashes == []

    def test_append_rejects_non_hex_entry(self):
        """Test that append fails loudly on a tampered non-hex hash."""
        chain = CalibrationChain()
        with pytest.raises(ValueError, match="hexadecimal"):
            chain.append("z" * 64)
        assert chain.hashes == []

    def test_append_rejects_empty_and_non_string_entries(self):
        """Test that append fails loudly on empty/non-string entries."""
        chain = CalibrationChain()
        with pytest.raises(ValueError, match="64-character"):
            chain.append("")
        with pytest.raises(ValueError, match="64-character"):
            chain.append(123)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="64-character"):
            chain.append(None)  # type: ignore[arg-type]
        assert chain.hashes == []

    def test_append_rejected_entry_leaves_chain_unchanged(self):
        """Test that a rejected append does not disturb valid entries."""
        chain = CalibrationChain()
        chain.append("a" * 64)
        with pytest.raises(ValueError, match="64-character"):
            chain.append("tampered")
        assert chain.hashes == ["a" * 64]
        assert chain.verify_integrity() == []

    def test_append_accepts_uppercase_hex(self):
        """Test that uppercase hex digests are valid entries."""
        chain = CalibrationChain()
        chain.append("A" * 64)
        assert chain.hashes == ["A" * 64]
        assert chain.verify_integrity() == []

    def test_extends_anchor_same_chain(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=["a" * 64],
        )
        assert chain.extends_anchor(anchor) is True

    def test_extends_anchor_extended(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.append("b" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=["a" * 64],
        )
        assert chain.extends_anchor(anchor) is True

    def test_not_extends_shorter_chain(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=["a" * 64, "b" * 64],
        )
        assert chain.extends_anchor(anchor) is False

    def test_extends_anchor_empty_anchor_chain(self):
        chain = CalibrationChain()
        chain.append("a" * 64)
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=[],
        )
        assert chain.extends_anchor(anchor) is True

    def test_extends_anchor_empty_current_chain(self):
        chain = CalibrationChain()
        anchor = AuditAnchor(
            calibration_artifacts_sha256="",
            benchmark_results_sha256="",
            detector_versions={},
            calibration_chain=[],
        )
        assert chain.extends_anchor(anchor) is False

    def test_save_and_load(self, tmp_path: Path):
        path = tmp_path / "chain.json"
        chain = CalibrationChain()
        chain.append("a" * 64)
        chain.save_to_file(path)
        assert path.exists()
        loaded = CalibrationChain()
        loaded.load_from_file(path)
        assert loaded.hashes == ["a" * 64]

    def test_load_missing_file(self, tmp_path: Path):
        chain = CalibrationChain()
        chain.load_from_file(tmp_path / "missing.json")
        assert chain.hashes == []


# ---------------------------------------------------------------------------
# RollbackError
# ---------------------------------------------------------------------------


class TestRollbackError:
    def test_is_exception(self):
        assert issubclass(RollbackError, Exception)

    def test_message_preserved(self):
        exc = RollbackError("Calibration artifacts rolled back")
        assert "rolled back" in str(exc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestAuditAnchorCli:
    """CLI integration tests for `textforensics audit export/verify`."""

    def _run_main(self, argv: list[str]) -> tuple[int, str, str]:
        import io
        import sys

        from textforensics.cli import main

        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.argv = ["textforensics", *argv]
            sys.stdin = io.StringIO("")
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            exit_code = main()
            return exit_code, sys.stdout.getvalue(), sys.stderr.getvalue()
        except SystemExit as e:
            code = e.code
            if isinstance(code, str):
                code = int(code) if code.isdigit() else 1
            return code or 0, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def test_cli_export_and_verify(self, workspace: Path, capsys=None):
        anchor_path = workspace.parent / "anchor.json"
        code, out, err = self._run_main(
            [
                "audit",
                "export",
                str(anchor_path),
                "--base-dir",
                str(workspace),
            ]
        )
        assert code == 0, err
        assert anchor_path.exists()
        data = json.loads(anchor_path.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        assert "calibration_artifacts_sha256" in data
        assert "benchmark_results_sha256" in data

        # Verify with no changes
        code, out, err = self._run_main(
            [
                "audit",
                "verify",
                str(anchor_path),
                "--base-dir",
                str(workspace),
            ]
        )
        assert code == 0, err
        payload = json.loads(out)
        assert payload["valid"] is True
        assert payload["status"] == "no_changes"

    def test_cli_verify_detects_rollback(self, workspace: Path):
        anchor_path = workspace.parent / "anchor.json"
        code, out, err = self._run_main(
            ["audit", "export", str(anchor_path), "--base-dir", str(workspace)]
        )
        assert code == 0, err

        # Modify calibrations (rollback simulation)
        _make_file(workspace / "calibrations" / "det-a.json", '{"threshold": 0.05}')

        code, out, err = self._run_main(
            ["audit", "verify", str(anchor_path), "--base-dir", str(workspace)]
        )
        assert code == EXIT_ERROR
        assert "rollback" in err.lower()
        payload = json.loads(out)
        assert payload["valid"] is False
        assert "rolled back" in payload["error"]

    def test_cli_verify_with_chain(self, workspace: Path):
        chain_path = workspace.parent / "chain.json"
        chain = CalibrationChain()
        chain.append("c" * 64)
        chain.save_to_file(chain_path)

        anchor_path = workspace.parent / "anchor.json"
        code, out, err = self._run_main(
            [
                "audit",
                "export",
                str(anchor_path),
                "--base-dir",
                str(workspace),
                "--chain",
                str(chain_path),
            ]
        )
        assert code == 0, err
        data = json.loads(anchor_path.read_text(encoding="utf-8"))
        assert data["calibration_chain"] == ["c" * 64]

    def test_cli_verify_missing_anchor_file(self, tmp_path: Path):
        code, out, err = self._run_main(["audit", "verify", str(tmp_path / "missing.json")])
        assert code == EXIT_ERROR
        assert "failed to read anchor file" in err

    def test_cli_export_without_output(self, workspace: Path):
        code, out, err = self._run_main(["audit", "export", "--base-dir", str(workspace)])
        assert code == EXIT_ERROR
        assert "requires an output path" in err

    def test_cli_verify_without_anchor(self, workspace: Path):
        code, out, err = self._run_main(["audit", "verify", "--base-dir", str(workspace)])
        assert code == EXIT_ERROR
        assert "requires an anchor file path" in err

    def test_cli_legacy_naturalness_still_works(self):
        # Backward compatibility: `audit` without subcommand = naturalness audit
        import io
        import sys

        from textforensics.cli import main

        old_argv = sys.argv
        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        try:
            sys.argv = ["textforensics", "audit"]
            sys.stdin = io.StringIO(
                "Furthermore, it is important to note that this robust "
                "solution seamlessly unlocks the potential."
            )
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            code = main()
            out = sys.stdout.getvalue()
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        assert code == 0
        issues = json.loads(out)
        assert isinstance(issues, list)
