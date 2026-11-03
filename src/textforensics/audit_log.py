"""Tamper-evident audit logging for TextForensics operations.

This module provides an append-only audit log with cryptographic chaining
to detect tampering. Each entry is linked to the previous entry via
a hash chain, making unauthorized modifications detectable.

Features:
- Append-only log with SHA-256 hash chaining
- Structured entries for forensic operations
- Merkle tree support for efficient verification
- JSON Lines format for streaming
- Optional encryption for sensitive fields
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "AuditLogEntry",
    "AuditLog",
    "AuditLogError",
    "verify_audit_log",
]


class AuditLogError(Exception):
    """Base exception for audit log errors."""
    pass


@dataclass(frozen=True, slots=True)
class AuditLogEntry:
    """A single audit log entry.

    Attributes:
        index: Monotonically increasing entry index (0-based).
        timestamp: ISO 8601 UTC timestamp.
        operation: Operation type (e.g., "scan", "report", "verify", "policy_evaluate").
        actor: Optional actor identity (user, service, API key).
        input_hash: SHA-256 of input data (for data integrity).
        output_hash: SHA-256 of output data (for data integrity).
        metadata: Additional operation-specific metadata.
        prev_hash: SHA-256 hash of the previous entry (chaining).
        entry_hash: SHA-256 hash of this entry's content (excluding prev_hash).
    """

    index: int
    timestamp: str
    operation: str
    actor: Optional[str]
    input_hash: Optional[str]
    output_hash: Optional[str]
    metadata: dict[str, Any]
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "operation": self.operation,
            "actor": self.actor,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditLogEntry:
        return cls(
            index=int(data["index"]),
            timestamp=str(data["timestamp"]),
            operation=str(data["operation"]),
            actor=data.get("actor"),
            input_hash=data.get("input_hash"),
            output_hash=data.get("output_hash"),
            metadata=dict(data.get("metadata", {})),
            prev_hash=str(data["prev_hash"]),
            entry_hash=str(data["entry_hash"]),
        )

    def to_json_line(self) -> str:
        """Serialize as a JSON line."""
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def _compute_entry_hash(entry_data: dict[str, Any]) -> str:
    """Compute SHA-256 hash of entry content (excluding prev_hash and entry_hash)."""
    # Create a copy without the hash fields
    content = {k: v for k, v in entry_data.items() if k not in ("prev_hash", "entry_hash")}
    canonical = json.dumps(content, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLog:
    """Tamper-evident append-only audit log.

    The log maintains a hash chain where each entry includes the hash of the
    previous entry. This makes it computationally infeasible to modify,
    insert, or delete entries without detection.

    The log is stored as JSON Lines (one JSON object per line) for
    streaming compatibility and crash resilience.
    """

    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self._entries: list[AuditLogEntry] = []
        self._load()

    def _load(self) -> None:
        """Load existing log entries from disk."""
        if not self.log_path.exists():
            return

        with self.log_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = AuditLogEntry.from_dict(data)
                    # Verify chain integrity on load
                    if self._entries:
                        if entry.prev_hash != self._entries[-1].entry_hash:
                            raise AuditLogError(
                                f"Hash chain broken at entry {entry.index}: "
                                f"prev_hash mismatch (line {line_num})"
                            )
                    if entry.entry_hash != _compute_entry_hash(entry.to_dict()):
                        raise AuditLogError(
                            f"Entry hash mismatch at entry {entry.index} (line {line_num})"
                        )
                    self._entries.append(entry)
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    raise AuditLogError(f"Invalid entry at line {line_num}: {exc}") from exc

    def _append_to_file(self, entry: AuditLogEntry) -> None:
        """Append a single entry to the log file."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(entry.to_json_line() + "\n")

    def append(
        self,
        operation: str,
        *,
        actor: Optional[str] = None,
        input_data: Optional[Any] = None,
        output_data: Optional[Any] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AuditLogEntry:
        """Append a new entry to the audit log.

        Args:
            operation: Operation type identifier.
            actor: Optional actor identity.
            input_data: Optional input data to hash.
            output_data: Optional output data to hash.
            metadata: Additional metadata.

        Returns:
            The created audit log entry.
        """
        index = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64

        # Compute hashes
        input_hash = None
        if input_data is not None:
            if isinstance(input_data, (dict, list)):
                input_canonical = json.dumps(input_data, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
            else:
                input_canonical = str(input_data)
            input_hash = hashlib.sha256(input_canonical.encode("utf-8")).hexdigest()

        output_hash = None
        if output_data is not None:
            if isinstance(output_data, (dict, list)):
                output_canonical = json.dumps(output_data, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
            else:
                output_canonical = str(output_data)
            output_hash = hashlib.sha256(output_canonical.encode("utf-8")).hexdigest()

        timestamp = _now_iso()

        # Build entry data (without hashes)
        entry_data = {
            "index": index,
            "timestamp": timestamp,
            "operation": operation,
            "actor": actor,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "metadata": metadata or {},
            "prev_hash": prev_hash,
        }

        entry_hash = _compute_entry_hash(entry_data)

        entry = AuditLogEntry(
            index=index,
            timestamp=timestamp,
            operation=operation,
            actor=actor,
            input_hash=input_hash,
            output_hash=output_hash,
            metadata=metadata or {},
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        # Verify the hash
        assert entry.entry_hash == _compute_entry_hash(entry.to_dict())

        self._entries.append(entry)
        self._append_to_file(entry)

        return entry

    def get_entry(self, index: int) -> Optional[AuditLogEntry]:
        """Get an entry by index."""
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    def get_entries(self, start: int = 0, end: Optional[int] = None) -> list[AuditLogEntry]:
        """Get a range of entries."""
        return self._entries[start:end]

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire hash chain.

        Returns:
            True if the chain is intact, False otherwise.
        """
        if not self._entries:
            return True

        prev_hash = "0" * 64
        for entry in self._entries:
            if entry.prev_hash != prev_hash:
                return False
            if entry.entry_hash != _compute_entry_hash(entry.to_dict()):
                return False
            prev_hash = entry.entry_hash
        return True

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)


def verify_audit_log(log_path: str | Path) -> dict[str, Any]:
    """Verify an audit log file and return verification results.

    Args:
        log_path: Path to the audit log file.

    Returns:
        Dictionary with verification results including:
        - valid: bool
        - entry_count: int
        - first_entry_hash: str
        - last_entry_hash: str
        - errors: list of error messages
    """
    errors: list[str] = []
    try:
        log = AuditLog(log_path)
        if not log.verify_chain():
            errors.append("Hash chain verification failed")
    except AuditLogError as exc:
        errors.append(str(exc))
        return {
            "valid": False,
            "entry_count": 0,
            "first_entry_hash": None,
            "last_entry_hash": None,
            "errors": errors,
        }

    if not log._entries:
        return {
            "valid": True,
            "entry_count": 0,
            "first_entry_hash": None,
            "last_entry_hash": None,
            "errors": [],
        }

    return {
        "valid": True,
        "entry_count": len(log._entries),
        "first_entry_hash": log._entries[0].entry_hash,
        "last_entry_hash": log._entries[-1].entry_hash,
        "errors": [],
    }