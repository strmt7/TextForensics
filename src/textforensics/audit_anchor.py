"""Audit anchor system for rollback detection.

Rejection-rejector pattern:
- External audit anchors (stored outside the workspace) provide hash checkpoints
  for calibration artifacts and benchmark results directories.
- A ``CalibrationChain`` tracks a monotonic chain of calibration artifact hashes,
  preventing whole-database rollback detection.
- ``verify_audit_anchor`` raises ``RollbackError`` when the current state does
  not extend the anchor chain.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = [
    "AuditAnchor",
    "CalibrationChain",
    "RollbackError",
    "export_audit_anchor",
    "verify_audit_anchor",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RollbackError(Exception):
    """Raised when a rollback of calibration or benchmark artifacts is detected.

    An anchor was previously exported (and stored externally), but the current
    state of calibration or benchmark artifacts does not match the anchor and
    does not extend the calibration chain. This indicates either:
    - A deliberate rollback of artifacts to an earlier state, or
    - Corruption or tampering of the artifact store.
    """

    pass


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AuditAnchor:
    """An exported audit point for rollback detection.

    Attributes:
        calibration_artifacts_sha256: SHA-256 of the calibrations directory tree.
        benchmark_results_sha256: SHA-256 of the benchmarks directory tree.
        detector_versions: Mapping of detector_id to version string.
        calibration_chain: Ordered list of calibration artifact hashes.
        exported_at: ISO 8601 timestamp of export.
        schema_version: Schema version for forward compatibility.
    """

    calibration_artifacts_sha256: str
    benchmark_results_sha256: str
    detector_versions: dict[str, str]
    calibration_chain: list[str] = field(default_factory=list)
    exported_at: str = ""
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "calibration_artifacts_sha256": self.calibration_artifacts_sha256,
            "benchmark_results_sha256": self.benchmark_results_sha256,
            "detector_versions": dict(self.detector_versions),
            "calibration_chain": list(self.calibration_chain),
            "exported_at": self.exported_at,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditAnchor:
        return cls(
            calibration_artifacts_sha256=str(data["calibration_artifacts_sha256"]),
            benchmark_results_sha256=str(data["benchmark_results_sha256"]),
            detector_versions=dict(data.get("detector_versions", {})),
            calibration_chain=list(data.get("calibration_chain", [])),
            exported_at=str(data.get("exported_at", "")),
            schema_version=int(data.get("schema_version", 1)),
        )


# ---------------------------------------------------------------------------
# Directory hashing
# ---------------------------------------------------------------------------


def _hash_directory(dir_path: Path) -> str:
    """Compute a deterministic SHA-256 hash of a directory tree.

    Files are sorted by relative path and hashed sequentially. Directories
    without files produce the empty-string hash. A missing directory also
    produces the empty-string hash.
    """
    if not dir_path.is_dir():
        return ""

    hasher = hashlib.sha256()
    for file_path in sorted(dir_path.rglob("*")):
        if file_path.is_file():
            # Include relative path in hash so renaming files changes the result
            rel = str(file_path.relative_to(dir_path))
            hasher.update(rel.encode("utf-8"))
            hasher.update(b"\x00")
            hasher.update(file_path.read_bytes())
            hasher.update(b"\n")
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------


def _resolve_base_dir() -> Path:
    """Resolve the project base directory (parent of src/textforensics)."""
    return Path(__file__).resolve().parent.parent.parent


def export_audit_anchor(
    base_dir: Path | None = None,
    detector_versions: dict[str, str] | None = None,
    calibration_chain: list[str] | None = None,
) -> AuditAnchor:
    """Export an audit anchor for rollback detection.

    The anchor captures the current state of calibration artifacts, benchmark
    results, and detector versions. Store the returned anchor externally (e.g.
    in a secure vault, a signed commit, or an out-of-band file) and use
    ``verify_audit_anchor`` to detect rollbacks.

    Args:
        base_dir: Override the project root (default: auto-detected).
        detector_versions: Override detector versions (default: auto-discovered).
        calibration_chain: Override the calibration chain (default: empty).

    Returns:
        An ``AuditAnchor`` with current hashes and metadata.
    """
    if base_dir is None:
        base_dir = _resolve_base_dir()

    cal_dir = base_dir / "calibrations"
    bench_dir = base_dir / "benchmarks"

    cal_hash = _hash_directory(cal_dir)
    bench_hash = _hash_directory(bench_dir)

    if detector_versions is None:
        try:
            from .detectors import list_detector_metadata

            detector_versions = {
                item["detector_id"]: item.get("detector_version", "unknown")
                for item in list_detector_metadata()
            }
        except Exception:
            detector_versions = {}

    if calibration_chain is None:
        calibration_chain = []

    return AuditAnchor(
        calibration_artifacts_sha256=cal_hash,
        benchmark_results_sha256=bench_hash,
        detector_versions=detector_versions,
        calibration_chain=calibration_chain,
        exported_at=datetime.now(UTC).isoformat(),
        schema_version=SCHEMA_VERSION,
    )


def verify_audit_anchor(
    anchor: AuditAnchor,
    current_chain: CalibrationChain | None = None,
    base_dir: Path | None = None,
) -> str:
    """Verify that the current state has not rolled back relative to *anchor*.

    Checks (in order of specificity):
    1. If calibration and benchmark hashes match the anchor exactly, return
       "no_changes".
    2. If a ``CalibrationChain`` is provided and the current chain extends the
       anchor's chain, return "chain_valid".
    3. Otherwise raise ``RollbackError``.

    Args:
        anchor: The previously exported audit anchor to verify against.
        current_chain: The current calibration chain for chain verification.
        base_dir: Override the project root (default: auto-detected).

    Returns:
        A status string: ``"no_changes"``, ``"chain_valid"``, or raises.

    Raises:
        RollbackError: When a rollback is detected.
    """
    if base_dir is None:
        base_dir = _resolve_base_dir()

    cal_dir = base_dir / "calibrations"
    bench_dir = base_dir / "benchmarks"

    current_cal_hash = _hash_directory(cal_dir)
    current_bench_hash = _hash_directory(bench_dir)

    # Check 1: Exact match – no changes since anchor
    if (
        current_cal_hash == anchor.calibration_artifacts_sha256
        and current_bench_hash == anchor.benchmark_results_sha256
    ):
        return "no_changes"

    # Check 2: Chain verification – current chain extends anchor chain
    if current_chain is not None and current_chain.extends_anchor(anchor):
        return "chain_valid"

    # Determine which artifact(s) changed
    reasons: list[str] = []
    if current_cal_hash != anchor.calibration_artifacts_sha256:
        reasons.append(
            f"Calibration artifacts rolled back "
            f"(expected {anchor.calibration_artifacts_sha256[:16]}..., "
            f"got {current_cal_hash[:16]}...)"
        )
    if current_bench_hash != anchor.benchmark_results_sha256:
        reasons.append(
            f"Benchmark results rolled back "
            f"(expected {anchor.benchmark_results_sha256[:16]}..., "
            f"got {current_bench_hash[:16]}...)"
        )

    if reasons:
        raise RollbackError("; ".join(reasons))

    # Edge case: both empty – nothing to verify
    return "no_changes"


# ---------------------------------------------------------------------------
# Calibration chain
# ---------------------------------------------------------------------------


class CalibrationChain:
    """Tracks a monotonic chain of calibration artifact hashes.

    Each new calibration artifact appends its SHA-256 hash to the chain.
    Verification ensures the chain is contiguous and extends from a known
    anchor point.

    The chain is external to the workspace by convention: it is stored and
    verified using externally managed checkpoints so that a whole-database
    rollback is detectable.
    """

    def __init__(self) -> None:
        self._hashes: list[str] = []

    @property
    def hashes(self) -> list[str]:
        """Return a copy of the current chain hashes."""
        return list(self._hashes)

    @property
    def length(self) -> int:
        return len(self._hashes)

    def append(self, artifact_hash: str) -> None:
        """Append a new calibration artifact hash to the chain."""
        self._hashes.append(artifact_hash)

    def to_dict(self) -> dict[str, Any]:
        return {"chain": list(self._hashes), "length": self.length}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationChain:
        chain = cls()
        chain._hashes = list(data.get("chain", []))
        return chain

    def verify_integrity(self) -> list[str]:
        """Verify that all chain hashes are valid SHA-256 hex strings.

        Returns a list of errors (empty if valid).
        """
        errors: list[str] = []
        for i, h in enumerate(self._hashes):
            if not h or len(h) != 64:
                errors.append(f"Entry {i}: hash length {len(h)} != 64")
            try:
                int(h, 16)
            except ValueError:
                errors.append(f"Entry {i}: not valid hex")
        return errors

    def extends_anchor(self, anchor: AuditAnchor) -> bool:
        """Check if the current chain extends the anchor's chain.

        The current chain must contain all hashes from the anchor's chain
        in the same order, followed by zero or more additional hashes.
        """
        anchor_chain = anchor.calibration_chain
        if not anchor_chain:
            # Empty anchor chain: any non-empty current chain extends it,
            # or if both are empty that means the artifacts themselves
            # changed (handled by the caller's hash check).
            return len(self._hashes) > 0

        # Current chain must be at least as long as anchor chain
        if len(self._hashes) < len(anchor_chain):
            return False

        # Check that the prefix matches
        return self._hashes[: len(anchor_chain)] == anchor_chain

    def load_from_file(self, path: Path) -> None:
        """Load a persisted chain from a JSON file."""
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self._hashes = list(data.get("chain", []))

    def save_to_file(self, path: Path) -> None:
        """Persist the chain to a JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
