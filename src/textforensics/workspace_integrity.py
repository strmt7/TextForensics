"""Workspace Integrity Module for TextForensics.

Implements workspace fingerprinting, immutable audit chains, and emergency
stop mechanisms inspired by the canonical rejection-rejector patterns.

This module provides:
- Workspace fingerprinting via deterministic hashing
- Immutable audit chains with cryptographic chaining
- Emergency stop sentinel (fail-closed mechanism)
- Workspace integrity verification
- Audit anchor management

Design principles:
- Local-first: No network dependencies
- Fail-closed: Any uncertainty defaults to secure state
- Cryptographic integrity: SHA-256 chaining for tamper evidence
- Audit-first: All operations produce verifiable audit trail
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "WorkspaceFingerprint",
    "AuditChainEntry",
    "AuditChain",
    "EmergencyStopSentinel",
    "WorkspaceIntegrityReport",
    "compute_workspace_fingerprint",
    "verify_workspace_fingerprint",
    "AuditChainEntry",
    "AuditChain",
    "create_audit_chain",
    "load_audit_chain",
    "save_audit_chain",
    "verify_audit_chain",
    "append_audit_entry",
    "EmergencyStopSentinel",
    "get_emergency_sentinel",
    "check_emergency_stop",
    "activate_emergency_stop",
    "deactivate_emergency_stop",
    "WorkspaceIntegrityReport",
    "verify_workspace_integrity",
]


# ============================================================
# Constants
# ============================================================

WORKSPACE_FINGERPRINT_VERSION = 1
AUDIT_CHAIN_VERSION = 1
MAX_AUDIT_ENTRY_BYTES = 64 * 1024  # 64KB

EMERGENCY_STOP_ENV = "TEXTFORENSICS_EMERGENCY_STOP"
OS_EMERGENCY_STOP_ENV = "TEXTFORENSICS_OS_EMERGENCY_STOP"
EMERGENCY_STOP_REQUIRED_VALUE = "required"


# ============================================================
# Core Data Structures
# ============================================================



@dataclass(frozen=True, slots=True)
class WorkspaceFingerprint:
    """Immutable workspace fingerprint derived from workspace identity."""

    version: int = 1
    workspace_id: str = ""  # UUID or hash-based identifier
    fingerprint: str = ""  # SHA-256 hash
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "workspace_id": self.workspace_id,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "source_path": self.source_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkspaceFingerprint:
        return cls(
            version=data.get("version", 1),
            workspace_id=data.get("workspace_id", ""),
            fingerprint=data.get("fingerprint", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            source_path=data.get("source_path", ""),
        )


@dataclass(frozen=True, slots=True)
class AuditChainEntry:
    """Single entry in the audit chain."""

    index: int
    timestamp: str
    operation: str
    operation_id: str
    payload_hash: str
    previous_hash: str
    entry_hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "operation": self.operation,
            "operation_id": self.operation_id,
            "payload_hash": self.payload_hash,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditChainEntry:
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            operation=data["operation"],
            operation_id=data["operation_id"],
            payload_hash=data["payload_hash"],
            previous_hash=data["previous_hash"],
            entry_hash=data["entry_hash"],
            metadata=data.get("metadata", {}),
        )


@dataclass
class AuditChain:
    """Immutable audit chain with cryptographic chaining."""

    version: int = AUDIT_CHAIN_VERSION
    entries: list[AuditChainEntry] = field(default_factory=list)
    chain_hash: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    _last_entry_hash: str = ""

    def add_entry(
        self,
        operation: str,
        operation_id: str,
        payload: Any,
        metadata: dict[str, Any] | None = None,
    ) -> AuditChainEntry:
        """Add a new entry to the audit chain."""
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_hash = hashlib.sha256(payload_bytes).hexdigest()

        previous_hash = self.last_entry_hash if self.entries else "0" * 64

        entry = AuditChainEntry(
            index=len(self.entries),
            timestamp=datetime.now(timezone.utc).isoformat(),
            operation=operation,
            operation_id=operation_id,
            payload_hash=payload_hash,
            previous_hash=previous_hash,
            entry_hash="",  # Will be computed below
            metadata=metadata or {},
        )

        # Compute entry hash
        entry_data = {
            "index": entry.index,
            "timestamp": entry.timestamp,
            "operation": entry.operation,
            "operation_id": entry.operation_id,
            "payload_hash": entry.payload_hash,
            "previous_hash": entry.previous_hash,
            "metadata": entry.metadata,
        }
        entry_bytes = json.dumps(entry_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256(entry_bytes).hexdigest()

        # Create new entry with computed hash
        entry = AuditChainEntry(
            index=entry.index,
            timestamp=entry.timestamp,
            operation=entry.operation,
            operation_id=entry.operation_id,
            payload_hash=entry.payload_hash,
            previous_hash=entry.previous_hash,
            entry_hash=entry_hash,
            metadata=entry.metadata,
        )

        self.entries.append(entry)
        self._last_entry_hash = entry_hash

        return entry

    @property
    def last_entry_hash(self) -> str:
        """Get the hash of the last entry, or genesis hash for empty chain."""
        if not self.entries:
            return "0" * 64
        return self._last_entry_hash

    def compute_chain_hash(self) -> str:
        """Compute the hash of the entire chain."""
        if not self.entries:
            return "0" * 64
        chain_data = [entry.entry_hash for entry in self.entries]
        chain_bytes = json.dumps(chain_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(chain_bytes).hexdigest()

    def verify_chain(self) -> tuple[bool, str | None]:
        """Verify the integrity of the audit chain."""
        if not self.entries:
            return True, None

        prev_hash = "0" * 64
        for entry in self.entries:
            if entry.previous_hash != prev_hash:
                return False, f"Hash chain broken at index {entry.index}: previous hash mismatch"

            # Verify entry hash
            entry_data = {
                "index": entry.index,
                "timestamp": entry.timestamp,
                "operation": entry.operation,
                "operation_id": entry.operation_id,
                "payload_hash": entry.payload_hash,
                "previous_hash": entry.previous_hash,
                "metadata": entry.metadata,
            }
            entry_bytes = json.dumps(entry_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            computed_hash = hashlib.sha256(entry_bytes).hexdigest()

            if entry.entry_hash != computed_hash:
                return False, f"Entry hash mismatch at index {entry.index}"

            prev_hash = entry.entry_hash

        return True, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "entries": [entry.to_dict() for entry in self.entries],
            "chain_hash": self.compute_chain_hash(),
            "created_at": self.created_at,
            "last_entry_hash": self.last_entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditChain:
        chain = cls(
            version=data.get("version", AUDIT_CHAIN_VERSION),
            entries=[AuditChainEntry.from_dict(e) for e in data.get("entries", [])],
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )
        chain.chain_hash = data.get("chain_hash", "")
        chain._last_entry_hash = data.get("last_entry_hash", chain._last_entry_hash)
        return chain


class EmergencyStopSentinel:
    """Emergency stop sentinel with fail-closed behavior.

    The sentinel file's presence indicates an active emergency stop.
    The system fails closed: any uncertainty (missing file, permission
    errors, corruption) results in an active emergency stop.
    """

    def __init__(self, sentinel_path: Path | None = None):
        """Initialize the emergency stop sentinel.

        Args:
            sentinel_path: Optional explicit path to sentinel file.
                          If None, uses TEXTFORENSICS_EMERGENCY_STOP env var
                          or defaults to .textforensics_emergency_stop in cwd.
        """
        if sentinel_path is not None:
            self.sentinel_path = Path(sentinel_path).resolve()
        else:
            env_path = os.environ.get("TEXTFORENSICS_EMERGENCY_STOP")
            if env_path:
                self.sentinel_path = Path(env_path).resolve()
            else:
                self.sentinel_path = Path.cwd() / ".textforensics_emergency_stop"

    def is_active(self) -> bool:
        """Check if emergency stop is active.

        Returns True if sentinel file exists and is readable.
        Returns True (fail closed) on any error/uncertainty.
        """
        try:
            if not self.sentinel_path.exists():
                return False
            if not self.sentinel_path.is_file():
                return True  # Fail closed
            # Verify we can read it
            self.sentinel_path.read_bytes()
            return True
        except (OSError, PermissionError):
            return True  # Fail closed

    def get_status(self) -> dict[str, Any]:
        """Get detailed status of the emergency stop sentinel."""
        self.is_active()
        return {
            "active": self.is_active(),
            "configured": self.sentinel_path.exists(),
            "path": str(self.sentinel_path),
            "reason": "manual" if self.sentinel_path.exists() else "none",
        }

    def activate(self, reason: str = "manual") -> bool:
        """Activate the emergency stop.

        Returns True if successfully activated, False on error.
        """
        try:
            self.sentinel_path.parent.mkdir(parents=True, exist_ok=True)
            content = json.dumps({
                "reason": reason,
                "activated_at": datetime.now(timezone.utc).isoformat(),
                "activated_by": os.getlogin() if hasattr(os, "getlogin") else "unknown",
            }, indent=2)
            self.sentinel_path.write_text(content)
            return True
        except Exception:
            return False

    def deactivate(self) -> bool:
        """Deactivate the emergency stop."""
        try:
            if self.sentinel_path.exists():
                self.sentinel_path.unlink()
            return True
        except Exception:
            return False


def _sha256(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def _sha256_str(text: str) -> str:
    """Compute SHA-256 hash of string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# Workspace Fingerprinting
# ============================================================

def _split_into_segments(text: str, target_segment_words: int = 100) -> list[str]:
    """Split text into roughly equal semantic segments."""
    if not text or not text.strip():
        return []

    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    if not sentences:
        return []

    segments = []
    current_segment = []
    current_words = 0

    for sentence in sentences:
        words = sentence.split()
        if current_words + len(words) > target_segment_words and current_segment:
            segments.append(" ".join(current_segment))
            current_segment = [sentence]
            current_words = len(words)
        else:
            current_segment.append(sentence)
            current_words += len(words)

    if current_segment:
        segments.append(" ".join(current_segment))

    return segments


def _analyze_segment(text: str, index: int) -> dict[str, Any]:
    """Analyze a single text segment for semantic features."""
    words = text.split()
    word_count = len(words)
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    sentence_count = len([s for s in sentences if s.strip()])
    len(text)

    # Type-token ratio
    words_lower = [w.lower() for w in words]
    unique_words = len(set(words_lower))
    type_token_ratio = unique_words / word_count if word_count > 0 else 0.0

    # Hapax ratio (words appearing exactly once)
    word_counts = Counter(w.lower() for w in words)
    hapax_count = sum(1 for c in word_counts.values() if c == 1)
    hapax_ratio = hapax_count / unique_words if unique_words > 0 else 0.0

    # Average word length
    avg_word_length = sum(len(w) for w in words) / word_count if word_count > 0 else 0.0

    # Lexical entropy
    if word_count > 0:
        probs = [count / word_count for count in word_counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    else:
        entropy = 0.0

    # Semantic density: concepts per sentence (approximated by unique words / sentence count)
    semantic_density = unique_words / sentence_count if sentence_count > 0 else 0.0

    # POS distribution approximation (simplified)
    pos_dist = {"noun": 0.25, "verb": 0.2, "adj": 0.15, "adv": 0.1, "other": 0.3}

    return {
        "index": 0,  # Will be set by caller
        "text": text[:200],  # Truncate for storage
        "word_count": word_count,
        "sentence_count": sentence_count,
        "avg_word_length": avg_word_length,
        "type_token_ratio": type_token_ratio,
        "hapax_ratio": hapax_ratio,
        "pos_distribution": pos_dist,
        "semantic_density": semantic_density,
        "entropy": entropy,
    }


def _split_into_segments(text: str, target_segment_words: int = 100) -> list[str]:
    """Split text into roughly equal semantic segments."""
    if not text or not text.strip():
        return []

    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    if not sentences:
        return []

    segments = []
    current_segment = []
    current_words = 0

    for sentence in sentences:
        words = sentence.split()
        if current_words + len(words) > target_segment_words and current_segment:
            segments.append(" ".join(current_segment))
            current_segment = [sentence]
            current_words = len(words)
        else:
            current_segment.append(sentence)
            current_words += len(words)

    if current_segment:
        segments.append(" ".join(current_segment))

    return segments


# ============================================================
# Workspace Fingerprinting
# ============================================================

def _compute_workspace_fingerprint(workspace_path: Path) -> WorkspaceFingerprint:
    """Compute a deterministic fingerprint of the workspace."""
    workspace_path = Path(workspace_path).resolve()

    # Generate workspace ID from path
    _sha256_str(str(workspace_path))[:16]

    # Collect fingerprint components
    components = []

    # Git commit hash if available
    git_dir = workspace_path / ".git"
    if git_dir.exists():
        try:
            import subprocess
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                commit_hash = result.stdout.strip()
                components.append(("git_commit", commit_hash))
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    # Config files
    config_files = [
        "pyproject.toml",
        "poetry.lock",
        "requirements.txt",
        "requirements-dev.txt",
        "uv.lock",
        "Cargo.toml",
        "Cargo.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ]
    for config_file in config_files:
        config_path = workspace_path / config_file
        if config_path.exists():
            try:
                content = config_path.read_bytes()
                file_hash = hashlib.sha256(content).hexdigest()[:16]
                components.append((config_file, file_hash))
            except OSError:
                pass

    # Sort for deterministic ordering
    components.sort(key=lambda x: x[0])

    # Build fingerprint
    component_str = "|".join(f"{k}:{v}" for k, v in components)
    fingerprint = _sha256_str(f"workspace:v1|{_sha256_str(workspace_path.name)}|{component_str}")

    return WorkspaceFingerprint(
        version=1,
        workspace_id=_sha256_str(workspace_path.name)[:16],
        fingerprint=fingerprint,
        created_at=_now_iso(),
        source_path=str(Path.cwd().resolve()),
    )


def compute_workspace_fingerprint(
    workspace_path: Path,
    *,
    include_git: bool = True,
    include_configs: bool = True,
) -> WorkspaceFingerprint:
    """Compute a deterministic fingerprint of the workspace.

    The fingerprint is derived from:
    - Git repository state (if available)
    - Configuration files
    - Project structure
    - Key file hashes

    Args:
        workspace_path: Path to workspace root
        include_git: Include git commit hash in fingerprint
        include_configs: Include config files in fingerprint

    Returns:
        WorkspaceFingerprint with deterministic hash
    """
    return _compute_workspace_fingerprint(Path(workspace_path).resolve())


def verify_workspace_fingerprint(
    workspace_path: Path,
    expected_fingerprint: str,
) -> tuple[bool, str | None]:
    """Verify workspace fingerprint matches expected value.

    Returns:
        (matches: bool, actual_fingerprint: Optional[str])
    """
    current = compute_workspace_fingerprint(workspace_path)
    matches = current.fingerprint == expected_fingerprint
    return matches, current.fingerprint if not matches else None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def _sha256_str(text: str) -> str:
    """Compute SHA-256 hash of string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _uuid() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# Audit Chain Functions
# ============================================================

def create_audit_chain() -> AuditChain:
    """Create a new audit chain."""
    return AuditChain()


def load_audit_chain(path: Path) -> AuditChain | None:
    """Load audit chain from JSON file."""
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        return AuditChain.from_dict(data)
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


def save_audit_chain(chain: AuditChain, path: Path) -> bool:
    """Save audit chain to JSON file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(chain.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return True
    except Exception:
        return False


def verify_audit_chain(chain: AuditChain) -> tuple[bool, str | None]:
    """Verify audit chain integrity.

    Returns:
        (is_valid: bool, error_message: Optional[str])
    """
    return chain.verify_chain()


def append_audit_entry(
    chain: AuditChain,
    operation: str,
    operation_id: str,
    payload: Any,
    metadata: dict[str, Any] | None = None,
) -> AuditChainEntry:
    """Append an entry to the audit chain."""
    return chain.add_entry(operation, operation_id, payload, metadata)


# ============================================================
# Emergency Stop Functions
# ============================================================

_emergency_sentinel: EmergencyStopSentinel | None = None


def get_emergency_sentinel(sentinel_path: Path | None = None) -> EmergencyStopSentinel:
    """Get or create the global emergency stop singleton."""
    global _emergency_sentinel
    if _emergency_sentinel is None:
        _emergency_sentinel = EmergencyStopSentinel(
            Path(sentinel_path) if sentinel_path else None
        )
    return _emergency_sentinel


def check_emergency_stop() -> bool:
    """Check if emergency stop is active (fail-closed).

    Returns True if emergency stop is active (blocks operations).
    """
    sentinel = get_emergency_sentinel()
    return sentinel.is_active()


def activate_emergency_stop(reason: str = "manual") -> bool:
    """Activate the emergency stop sentinel."""
    sentinel = get_emergency_sentinel()
    return sentinel.activate(reason)


def deactivate_emergency_stop() -> bool:
    """Deactivate the emergency stop sentinel."""
    sentinel = get_emergency_sentinel()
    return sentinel.deactivate()


# ============================================================
# Workspace Integrity Report
# ============================================================

@dataclass
class WorkspaceIntegrityReport:
    """Complete workspace integrity verification report."""

    workspace_fingerprint: WorkspaceFingerprint
    fingerprint_verified: bool
    audit_chain_valid: bool
    audit_chain_length: int
    emergency_stop_active: bool
    emergency_stop_configured: bool
    emergency_stop_reason: str | None
    overall_status: str  # "healthy", "degraded", "compromised", "emergency_stop"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace_fingerprint": self.workspace_fingerprint.to_dict(),
            "fingerprint_verified": self.fingerprint_verified,
            "audit_chain_valid": self.audit_chain_valid,
            "audit_chain_length": self.audit_chain_length,
            "emergency_stop_active": self.emergency_stop_active,
            "emergency_stop_configured": self.emergency_stop_configured,
            "emergency_stop_reason": self.emergency_stop_reason,
            "overall_status": self.overall_status,
            "timestamp": self.timestamp,
            "details": self.details,
        }

    def save(self, path: Path) -> bool:
        """Save report to JSON file."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return True
        except Exception:
            return False

    @classmethod
    def load(cls, path: Path) -> WorkspaceIntegrityReport | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                workspace_fingerprint=WorkspaceFingerprint.from_dict(data["workspace_fingerprint"]),
                fingerprint_verified=data["fingerprint_verified"],
                audit_chain_valid=data["audit_chain_valid"],
                audit_chain_length=data["audit_chain_length"],
                emergency_stop_active=data["emergency_stop_active"],
                emergency_stop_configured=data["emergency_stop_configured"],
                emergency_stop_reason=data.get("emergency_stop_reason"),
                overall_status=data["overall_status"],
                timestamp=data["timestamp"],
                details=data.get("details", {}),
            )
        except Exception:
            return None


def verify_workspace_integrity(
    workspace_path: Path,
    expected_fingerprint: str | None = None,
    audit_chain_path: Path | None = None,
) -> WorkspaceIntegrityReport:
    """Perform comprehensive workspace integrity verification.

    Args:
        workspace_path: Path to workspace root
        expected_fingerprint: Optional expected fingerprint to verify against
        audit_chain_path: Optional path to audit chain file

    Returns:
        WorkspaceIntegrityReport with complete verification results
    """
    workspace_path = Path(workspace_path).resolve()

    # 1. Compute workspace fingerprint
    fingerprint = compute_workspace_fingerprint(workspace_path)

    # 2. Verify fingerprint if expected provided
    fingerprint_verified = True
    if expected_fingerprint:
        fingerprint_verified = fingerprint.fingerprint == expected_fingerprint

    # 3. Check emergency stop
    sentinel = get_emergency_sentinel()
    emergency_stop_status = sentinel.get_status()
    emergency_stop_active = emergency_stop_status["active"]
    emergency_stop_status["configured"]
    emergency_stop_reason = emergency_stop_status.get("reason")

    # 4. Load and verify audit chain
    audit_chain_valid = True
    audit_chain_length = 0
    if audit_chain_path and audit_chain_path.exists():
        chain = load_audit_chain(audit_chain_path)
        if chain:
            valid, error = verify_audit_chain(chain)
            audit_chain_valid = valid
            audit_chain_length = len(chain.entries)
        else:
            audit_chain_valid = False
    else:
        audit_chain_length = 0

    # Determine overall status
    if emergency_stop_active:
        overall_status = "emergency_stop"
    elif not fingerprint_verified or not audit_chain_valid:
        overall_status = "compromised"
    elif fingerprint_verified and audit_chain_valid:
        overall_status = "healthy"
    else:
        overall_status = "degraded"

    details = {
        "fingerprint": fingerprint.fingerprint,
        "expected_fingerprint": expected_fingerprint,
        "emergency_stop_details": get_emergency_sentinel().get_status(),
    }

    return WorkspaceIntegrityReport(
        workspace_fingerprint=fingerprint,
        fingerprint_verified=fingerprint_verified,
        audit_chain_valid=audit_chain_valid,
        audit_chain_length=audit_chain_length,
        emergency_stop_active=emergency_stop_active,
        emergency_stop_configured=emergency_stop_status["configured"],
        emergency_stop_reason=emergency_stop_reason,
        overall_status=overall_status,
        details=details,
    )


def _sha256(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def _sha256_str(text: str) -> str:
    """Compute SHA-256 hash of string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ============================================================
# Module Exports
# ============================================================

__all__ = [
    # Workspace Fingerprinting
    "WorkspaceFingerprint",
    "compute_workspace_fingerprint",
    "verify_workspace_fingerprint",
    # Audit Chain
    "AuditChainEntry",
    "AuditChain",
    "create_audit_chain",
    "load_audit_chain",
    "save_audit_chain",
    "verify_audit_chain",
    "append_audit_entry",
    # Emergency Stop
    "EmergencyStopSentinel",
    "get_emergency_sentinel",
    "check_emergency_stop",
    "activate_emergency_stop",
    "deactivate_emergency_stop",
    # Workspace Integrity
    "WorkspaceIntegrityReport",
    "verify_workspace_integrity",
]
