"""Detection Result Cache with Intelligent Invalidation for TextForensics.

Provides a sophisticated caching layer for detection results with:
- Content-addressable storage using input content hashes
- Intelligent invalidation based on model version changes
- TTL-based expiration with configurable policies
- Cache warming and pre-computation
- Statistics and monitoring
- Thread-safe operations
- Integration with Pipeline Orchestrator

Design principles:
- Local-first: No network dependencies
- Observable: Full metrics and audit trail
- Extensible: Plugin architecture for custom invalidation policies
- Fail-safe: Cache misses gracefully fall back to fresh computation
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

__all__ = [
    "CachePolicy",
    "CacheEntry",
    "CacheStats",
    "InvalidationPolicy",
    "DetectionCache",
    "create_detection_cache",
]


class CacheEntryStatus(StrEnum):
    """Status of a cache entry."""

    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    MISSING = "missing"


class InvalidationReason(StrEnum):
    """Reason for cache invalidation."""

    TTL_EXPIRED = "ttl_expired"
    MODEL_VERSION_CHANGED = "model_version_changed"
    CONFIG_CHANGED = "config_changed"
    MANUAL = "manual"
    EVICTION = "eviction"
    CONTENT_HASH_MISMATCH = "content_hash_mismatch"


@dataclass(frozen=True, slots=True)
class CachePolicy:
    """Configuration for cache behavior."""

    ttl_seconds: float = 3600.0  # 1 hour default TTL
    max_entries: int = 10000
    max_size_bytes: int = 100 * 1024 * 1024  # 100 MB
    check_interval_seconds: float = 60.0  # How often to check for expired entries
    enable_compression: bool = True
    compress_threshold_bytes: int = 1024  # Compress entries larger than 1KB

    def __post_init__(self):
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if self.max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if self.max_size_bytes <= 0:
            raise ValueError("max_size_bytes must be positive")


@dataclass(frozen=True, slots=True)
class InvalidationPolicy:
    """Policy for cache invalidation."""

    invalidate_on_model_version_change: bool = True
    invalidate_on_config_change: bool = True
    max_age_seconds: float | None = None  # Override TTL for specific entries
    custom_invalidator: Callable[[Any, Any], bool] | None = None  # Custom invalidation function


@dataclass
class CacheEntry:
    """A single cached detection result."""

    content_hash: str
    detector_id: str
    detector_version: str
    result: dict[str, Any]
    created_at: str
    expires_at: str
    access_count: int = 0
    last_accessed: str = ""
    size_bytes: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "result": self.result,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed,
            "size_bytes": self.size_bytes,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheEntry:
        return cls(
            content_hash=data["content_hash"],
            detector_id=data["detector_id"],
            detector_version=data["detector_version"],
            result=data["result"],
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            access_count=data.get("access_count", 0),
            last_accessed=data.get("last_accessed", ""),
            size_bytes=data.get("size_bytes", 0),
            metadata=data.get("metadata", {}),
        )

    def is_expired(self) -> bool:
        """Check if entry is expired."""
        expires_at = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return datetime.now(UTC) >= expires_at

    def touch(self) -> CacheEntry:
        """Update access metadata."""
        datetime.now(UTC).isoformat()
        return CacheEntry(
            content_hash=self.content_hash,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            result=self.result,
            created_at=self.created_at,
            expires_at=self.expires_at,
            access_count=self.access_count + 1,
            last_accessed=datetime.now(UTC).isoformat(),
            size_bytes=self.size_bytes,
            metadata=self.metadata,
        )


@dataclass
class CacheStats:
    """Cache statistics."""

    total_entries: int = 0
    total_size_bytes: int = 0
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    invalidations: int = 0
    expired_entries: int = 0
    total_size_bytes_ever: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entries": self.total_entries,
            "total_size_bytes": self.total_size_bytes,
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "invalidations": self.invalidations,
            "expired_entries": self.expired_entries,
            "total_size_bytes_ever": self.total_size_bytes_ever,
            "hit_rate": self.hit_rate,
        }


class DetectionCache:
    """High-performance detection result cache with intelligent invalidation."""

    def __init__(
        self,
        policy: CachePolicy | None = None,
        invalidation_policy: InvalidationPolicy | None = None,
        storage_path: Path | None = None,
    ):
        self.policy = policy or CachePolicy()
        self.invalidation_policy = invalidation_policy or InvalidationPolicy()
        self.storage_path = storage_path

        # Main cache storage - OrderedDict for LRU eviction
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Index by detector for invalidation
        self._detector_index: dict[str, set[str]] = defaultdict(set)

        # Statistics
        self.stats = CacheStats()

        # Current model versions for invalidation
        self._model_versions: dict[str, str] = {}
        self._config_hashes: dict[str, str] = {}

        # Background cleanup task
        self._cleanup_task: asyncio.Task | None = None
        self._running = False

        # Load from disk if path provided
        if storage_path and storage_path.exists():
            self._load_from_disk()

    def _generate_key(self, content_hash: str, detector_id: str, detector_version: str) -> str:
        """Generate cache key from content hash and detector info."""
        return f"{detector_id}:{detector_version}:{content_hash}"

    def _compute_content_hash(self, text: str) -> str:
        """Compute SHA-256 hash of input text."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _serialize_result(self, result: dict[str, Any]) -> bytes:
        """Serialize result to bytes."""
        data = json.dumps(result, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
        if len(data) > self.policy.compress_threshold_bytes and self.policy.enable_compression:
            import zlib

            return zlib.compress(data)
        return data

    def _deserialize_result(self, data: bytes) -> dict[str, Any]:
        """Deserialize result from bytes."""
        # Try to decompress first
        try:
            import zlib

            data = zlib.decompress(data)
        except zlib.error:
            pass  # Not compressed
        return json.loads(data.decode("utf-8"))

    def _calculate_size(self, result: dict[str, Any]) -> int:
        """Calculate approximate size of result in bytes."""
        return len(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    async def start(self) -> None:
        """Start background cleanup task."""
        if self._running:
            return
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        """Stop background cleanup task."""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task

    async def _cleanup_loop(self) -> None:
        """Background task to clean expired entries."""
        while self._running:
            try:
                await asyncio.sleep(self.policy.check_interval_seconds)
                self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                pass  # Log error in production

    def _cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        now = datetime.now(UTC)
        expired_keys = []

        for key, entry in self._cache.items():
            datetime.fromisoformat(entry.expires_at.replace("Z", "+00:00"))
            if datetime.fromisoformat(entry.expires_at.replace("Z", "+00:00")) <= now:
                expired_keys.append(key)

        for key in expired_keys:
            self._remove_entry(key, InvalidationReason.TTL_EXPIRED)

        return len(expired_keys)

    def _evict_lru(self) -> bool:
        """Evict least recently used entry. Returns True if evicted."""
        if not self._cache:
            return False

        # Find LRU entry (first in OrderedDict)
        lru_key = next(iter(self._cache))
        self._remove_entry(lru_key, InvalidationReason.EVICTION)
        return True

    def _remove_entry(self, key: str, reason: InvalidationReason) -> bool:
        """Remove an entry from cache."""
        if key not in self._cache:
            return False

        entry = self._cache.pop(key)
        self._detector_index[entry.detector_id].discard(key)
        if not self._detector_index[entry.detector_id]:
            del self._detector_index[entry.detector_id]

        self.stats.total_entries -= 1
        self.stats.total_size_bytes -= entry.size_bytes

        if reason == InvalidationReason.EVICTION:
            self.stats.evictions += 1
        elif reason == InvalidationReason.TTL_EXPIRED:
            self.stats.expired_entries += 1
        else:
            self.stats.invalidations += 1

        return True

    def _ensure_capacity(self) -> None:
        """Ensure cache doesn't exceed capacity limits."""
        # Check entry count
        while len(self._cache) >= self.policy.max_entries:
            if not self._evict_lru():
                break

        # Check size limit
        while self.stats.total_size_bytes >= self.policy.max_size_bytes:
            if not self._evict_lru():
                break

    def get(
        self,
        text: str,
        detector_id: str,
        detector_version: str,
    ) -> tuple[dict[str, Any] | None, CacheEntryStatus]:
        """Get cached result for text and detector."""
        content_hash = self._compute_content_hash(text)
        key = self._generate_key(content_hash, detector_id, detector_version)

        if key not in self._cache:
            self.stats.misses += 1
            return None, CacheEntryStatus.MISSING

        entry = self._cache[key]

        # Check for model version mismatch
        if self.invalidation_policy.invalidate_on_model_version_change:
            current_version = self._model_versions.get(detector_id)
            if current_version and current_version != entry.detector_version:
                self._remove_entry(key, InvalidationReason.MODEL_VERSION_CHANGED)
                self.stats.misses += 1
                return None, CacheEntryStatus.INVALIDATED

        # Check for config change
        if self.invalidation_policy.invalidate_on_config_change:
            current_config = self._config_hashes.get(detector_id)
            entry_config = entry.metadata.get("config_hash")
            if current_config and entry_config and current_config != entry_config:
                self._remove_entry(key, InvalidationReason.CONFIG_CHANGED)
                self.stats.misses += 1
                return None, CacheEntryStatus.INVALIDATED

        # Check expiration
        if entry.is_expired():
            self._remove_entry(key, InvalidationReason.TTL_EXPIRED)
            self.stats.misses += 1
            return None, CacheEntryStatus.EXPIRED

        # Custom invalidator
        if (
            self.invalidation_policy.custom_invalidator
            and self.invalidation_policy.custom_invalidator(entry.result, None)
        ):
            self._remove_entry(key, InvalidationReason.MANUAL)
            self.stats.misses += 1
            return None, CacheEntryStatus.INVALIDATED

        # Hit! Update access metadata
        self._cache[key] = entry.touch()
        self.stats.hits += 1

        # Move to end (most recently used)
        self._cache.move_to_end(key)

        return entry.result, CacheEntryStatus.FRESH

    async def put(
        self,
        text: str,
        detector_id: str,
        detector_version: str,
        result: dict[str, Any],
        ttl_seconds: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Store a result in cache."""
        content_hash = self._compute_content_hash(text)
        key = self._generate_key(content_hash, detector_id, detector_version)

        datetime.now(UTC)
        ttl = ttl_seconds or self.policy.ttl_seconds
        expires_at = datetime.now(UTC).timestamp() + ttl
        expires_at_str = datetime.fromtimestamp(expires_at, UTC).isoformat()

        # Serialize to calculate size
        serialized = self._serialize_result(result)
        size_bytes = len(serialized)

        entry = CacheEntry(
            content_hash=content_hash,
            detector_id=detector_id,
            detector_version=detector_version,
            result=result,
            created_at=datetime.now(UTC).isoformat(),
            expires_at=expires_at_str,
            size_bytes=size_bytes,
            metadata=metadata or {},
        )

        # Ensure capacity
        self._ensure_capacity()

        # Store
        self._cache[key] = entry
        self._detector_index[detector_id].add(key)

        self.stats.total_entries += 1
        self.stats.total_size_bytes += size_bytes
        self.stats.total_size_bytes_ever += size_bytes

        return True

    def invalidate(
        self,
        detector_id: str | None = None,
        detector_version: str | None = None,
        content_hash: str | None = None,
        reason: InvalidationReason = InvalidationReason.MANUAL,
    ) -> int:
        """Invalidate cache entries matching criteria."""
        if content_hash and detector_id and detector_version:
            key = self._generate_key(content_hash, detector_id, detector_version)
            if key in self._cache:
                self._remove_entry(key, reason)
                return 1
            return 0

        # Match by detector
        keys_to_remove = []
        if detector_id:
            for key in self._detector_index.get(detector_id, set()):
                entry = self._cache[key]
                if (detector_version is None or entry.detector_version == detector_version) and (
                    content_hash is None or entry.content_hash == content_hash
                ):
                    keys_to_remove.append(key)
        elif content_hash:
            # Search all entries for matching content hash
            for key, entry in self._cache.items():
                if entry.content_hash == content_hash and (
                    detector_version is None or entry.detector_version == detector_version
                ):
                    keys_to_remove.append(key)

        count = 0
        for key in keys_to_remove:
            if self._remove_entry(key, reason):
                count += 1

        return count

    def invalidate_model_version(self, detector_id: str, new_version: str) -> int:
        """Invalidate all entries for a detector when model version changes."""
        old_version = self._model_versions.get(detector_id)
        self._model_versions[detector_id] = new_version

        if not old_version or old_version == new_version:
            return 0

        return self.invalidate(
            detector_id=detector_id, reason=InvalidationReason.MODEL_VERSION_CHANGED
        )

    def invalidate_config(self, detector_id: str, new_config_hash: str) -> int:
        """Invalidate all entries for a detector when config changes."""
        self._config_hashes[detector_id] = new_config_hash
        return self.invalidate(detector_id=detector_id, reason=InvalidationReason.CONFIG_CHANGED)

    def set_model_version(self, detector_id: str, version: str) -> None:
        """Set current model version for a detector."""
        self._model_versions[detector_id] = version

    def set_config_hash(self, detector_id: str, config_hash: str) -> None:
        """Set current config hash for a detector."""
        self._config_hashes[detector_id] = config_hash

    def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        return self.stats

    def get_entry_status(
        self, text: str, detector_id: str, detector_version: str
    ) -> CacheEntryStatus:
        """Get status of a cache entry without modifying it."""
        self._compute_content_hash(text)
        key = self._generate_key(self._compute_content_hash(text), detector_id, detector_version)

        if key not in self._cache:
            return CacheEntryStatus.MISSING

        entry = self._cache[key]

        if entry.is_expired():
            return CacheEntryStatus.EXPIRED

        # Check invalidation conditions without removing
        if self.invalidation_policy.invalidate_on_model_version_change:
            current_version = self._model_versions.get(detector_id)
            if current_version and current_version != self._cache[key].detector_version:
                return CacheEntryStatus.INVALIDATED

        if self.invalidation_policy.invalidate_on_config_change:
            current_config = self._config_hashes.get(detector_id)
            entry_config = self._cache[key].metadata.get("config_hash")
            if current_config and entry_config and current_config != entry_config:
                return CacheEntryStatus.INVALIDATED

        return CacheEntryStatus.FRESH

    def get_all_entries(self) -> list[CacheEntry]:
        """Get all cache entries (for inspection/debugging)."""
        return list(self._cache.values())

    def clear(self) -> int:
        """Clear all cache entries."""
        count = len(self._cache)
        self._cache.clear()
        self._detector_index.clear()
        self.stats.total_entries = 0
        self.stats.total_size_bytes = 0
        return count

    def _save_to_disk(self) -> bool:
        """Save cache to disk."""
        if not self.storage_path:
            return False

        try:
            data = {
                "version": 1,
                "entries": [entry.to_dict() for entry in self._cache.values()],
                "model_versions": self._model_versions,
                "config_hashes": self._config_hashes,
            }
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            self.storage_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return True
        except Exception:
            return False

    def _load_from_disk(self) -> bool:
        """Load cache from disk."""
        try:
            data = json.loads(self.storage_path.read_text(encoding="utf-8"))
            for entry_data in data.get("entries", []):
                entry = CacheEntry.from_dict(entry_data)
                key = self._generate_key(
                    entry.content_hash, entry.detector_id, entry.detector_version
                )
                self._cache[key] = entry
                self._detector_index[entry.detector_id].add(key)
                self.stats.total_entries += 1
                self.stats.total_size_bytes += entry.size_bytes

            self._model_versions = data.get("model_versions", {})
            self._config_hashes = data.get("config_hashes", {})

            # Clean expired entries on load
            self._cleanup_expired()
            return True
        except Exception:
            return False

    async def __aenter__(self) -> DetectionCache:
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.stop()


def create_detection_cache(
    ttl_seconds: float = 3600.0,
    max_entries: int = 10000,
    max_size_mb: int = 100,
    storage_path: Path | None = None,
) -> DetectionCache:
    """Create a detection cache with common defaults."""
    policy = CachePolicy(
        ttl_seconds=ttl_seconds,
        max_entries=max_entries,
        max_size_bytes=max_size_mb * 1024 * 1024,
    )
    cache = DetectionCache(policy=policy, storage_path=storage_path)
    return cache
