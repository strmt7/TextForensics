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

Thread safety (audit W4/S13): every compound cache/index/statistics
transaction runs under one re-entrant lock (``self._lock``). The custom
invalidator is invoked while that lock is held, receives a deep copy of
the result, and must be short and non-blocking; an exception from it
invalidates the entry (fail closed) instead of propagating. A concurrent
``clear`` therefore cannot resurrect an entry outside the index or the
statistics: it either runs before the read (the read then misses) or
after it (the read entry is removed by the clear).

Capacity (audit W4/S11): the budget is the RESIDENT size of an entry —
the uncompressed JSON encoding of its result plus metadata — never the
compressed serialization length. A single entry larger than the budget
is refused; replacement subtracts the old entry before admission; disk
loads recompute sizes and admit through the same capacity rules.

Invalidation (audit W4/S12): config invalidation fails closed — when a
current config hash is known, an entry without an exactly matching
``metadata.config_hash`` is invalid, not fresh. ``max_age_seconds`` is
enforced against ``created_at``. Explicit TTL overrides must be finite
and positive. Results and metadata are deep-copied on put and on every
return, so callers cannot mutate cached evidence.

Persistence (audit W4/S14): persistence is part of the lifecycle.
``stop()`` (and therefore ``__aexit__``) saves when a ``storage_path``
is configured; ``save()``/``load()`` are the explicit operations.
Saves are atomic (temp file in the same directory, flush, fsync,
``os.replace``); a failed save leaves the previous durable file
untouched and records ``last_persistence_error`` instead of claiming
success. Loads are validated into temporary structures first and only
published when the whole file is valid, so a malformed load never
leaves poisoned partial state: the prior in-memory state is kept and
``load()`` returns False.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import json
import math
import os
import tempfile
import threading
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

# Hard cap on the decompressed size of a single cached result. Results are
# JSON dicts derived from at most 2 MB of input text; anything larger is a
# decompression bomb, not a legitimate cache entry.
MAX_DECOMPRESSED_RESULT_BYTES = 10 * 1024 * 1024


def _parse_time(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp, requiring timezone awareness.

    Returns None for anything unparseable or naive: callers treat that
    as invalid/expired (fail closed) instead of raising.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


def _reject_json_constant(value: str) -> Any:
    """``parse_constant`` hook: strict JSON forbids NaN/Infinity."""
    raise ValueError(f"non-finite JSON constant {value!r} is not allowed")


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
    MAX_AGE_EXCEEDED = "max_age_exceeded"


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
        if not math.isfinite(self.ttl_seconds) or self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if self.max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if self.max_size_bytes <= 0:
            raise ValueError("max_size_bytes must be positive")
        if not math.isfinite(self.check_interval_seconds) or self.check_interval_seconds <= 0:
            raise ValueError("check_interval_seconds must be positive")
        if self.compress_threshold_bytes < 0:
            raise ValueError("compress_threshold_bytes must be non-negative")


@dataclass(frozen=True, slots=True)
class InvalidationPolicy:
    """Policy for cache invalidation."""

    invalidate_on_model_version_change: bool = True
    invalidate_on_config_change: bool = True
    max_age_seconds: float | None = None  # Override TTL for specific entries
    custom_invalidator: Callable[[Any, Any], bool] | None = None  # Custom invalidation function

    def __post_init__(self):
        if self.max_age_seconds is not None and (
            not math.isfinite(self.max_age_seconds) or self.max_age_seconds <= 0
        ):
            raise ValueError("max_age_seconds must be positive")


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
        # Deep copies: serializing an entry must never hand out the
        # resident result/metadata objects to a caller.
        return {
            "content_hash": self.content_hash,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "result": copy.deepcopy(self.result),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed,
            "size_bytes": self.size_bytes,
            "metadata": copy.deepcopy(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CacheEntry:
        return cls(
            content_hash=data["content_hash"],
            detector_id=data["detector_id"],
            detector_version=data["detector_version"],
            result=copy.deepcopy(data["result"]),
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            access_count=data.get("access_count", 0),
            last_accessed=data.get("last_accessed", ""),
            size_bytes=data.get("size_bytes", 0),
            metadata=copy.deepcopy(data.get("metadata", {})),
        )

    def is_expired(self) -> bool:
        """Check if entry is expired.

        Fail closed: an unparseable or naive expiry counts as expired
        instead of raising, so a corrupt entry can never crash a read.
        """
        expires_at = _parse_time(self.expires_at)
        if expires_at is None:
            return True
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


def _validate_entry_dict(data: Any) -> CacheEntry:
    """Strictly validate one persisted entry dict; raise ValueError if bad.

    Used by the disk loader before anything is published: a malformed
    entry rejects the whole load instead of poisoning the cache.
    """
    if not isinstance(data, dict):
        raise ValueError("cache entry must be an object")
    for key in (
        "content_hash",
        "detector_id",
        "detector_version",
        "result",
        "created_at",
        "expires_at",
    ):
        if key not in data:
            raise ValueError(f"cache entry is missing {key!r}")
    for key in ("content_hash", "detector_id", "detector_version"):
        if not isinstance(data[key], str) or not data[key]:
            raise ValueError(f"cache entry {key!r} must be a non-empty string")
    if not isinstance(data["result"], dict):
        raise ValueError("cache entry 'result' must be an object")
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("cache entry 'metadata' must be an object")
    access_count = data.get("access_count", 0)
    if isinstance(access_count, bool) or not isinstance(access_count, int) or access_count < 0:
        raise ValueError("cache entry 'access_count' must be a non-negative integer")
    last_accessed = data.get("last_accessed", "")
    if not isinstance(last_accessed, str):
        raise ValueError("cache entry 'last_accessed' must be a string")
    if "size_bytes" in data:
        size = data["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValueError("cache entry 'size_bytes' must be a non-negative integer")
    if _parse_time(data["created_at"]) is None:
        raise ValueError("cache entry 'created_at' must be an aware ISO-8601 timestamp")
    if _parse_time(data["expires_at"]) is None:
        raise ValueError("cache entry 'expires_at' must be an aware ISO-8601 timestamp")
    return CacheEntry.from_dict(data)


def _validate_str_map(data: Any, name: str) -> dict[str, str]:
    if not isinstance(data, dict):
        raise ValueError(f"cache file {name!r} must be an object")
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(f"cache file {name!r} must map strings to strings")
    return dict(data)


class DetectionCache:
    """High-performance detection result cache with intelligent invalidation.

    Persistence lifecycle: the constructor loads ``storage_path`` when
    it exists; :meth:`stop` (and therefore async-context exit) saves
    when a path is configured; :meth:`save` and :meth:`load` are the
    explicit operations. A failed save/load never claims success: it
    returns False and records :attr:`last_persistence_error`.
    """

    def __init__(
        self,
        policy: CachePolicy | None = None,
        invalidation_policy: InvalidationPolicy | None = None,
        storage_path: Path | None = None,
    ):
        self.policy = policy or CachePolicy()
        self.invalidation_policy = invalidation_policy or InvalidationPolicy()
        self.storage_path = storage_path

        # One re-entrant lock serializes every compound cache/index/
        # statistics transaction (see the module docstring).
        self._lock = threading.RLock()

        # Last persistence failure, if any; None after a successful
        # save/load. Never silently claim persistence that did not happen.
        self.last_persistence_error: str | None = None

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
        # Try to decompress first, with a hard cap on the decompressed size
        # so a small compressed blob cannot expand without bound (zip bomb).
        try:
            import zlib

            decompressor = zlib.decompressobj()
            data = decompressor.decompress(data, MAX_DECOMPRESSED_RESULT_BYTES + 1)
            if len(data) > MAX_DECOMPRESSED_RESULT_BYTES:
                raise ValueError(
                    "Cached result exceeds the "
                    f"{MAX_DECOMPRESSED_RESULT_BYTES}-byte decompression cap"
                )
            if decompressor.unconsumed_tail:
                raise ValueError(
                    "Cached result exceeds the "
                    f"{MAX_DECOMPRESSED_RESULT_BYTES}-byte decompression cap"
                )
            if not decompressor.eof:
                # Not a complete zlib stream; fall through to the plain-JSON
                # path exactly as a zlib error would.
                raise zlib.error("incomplete zlib stream")
        except zlib.error:
            pass  # Not compressed
        return json.loads(data.decode("utf-8"))

    def _calculate_size(self, result: dict[str, Any]) -> int:
        """Calculate approximate size of result in bytes."""
        return len(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    def _resident_size(self, result: dict[str, Any], metadata: dict[str, Any]) -> int:
        """Resident size of an entry: uncompressed JSON of result+metadata.

        This is the size the capacity budget enforces. Compression only
        affects a serialization, never what is resident in memory.
        """
        return self._calculate_size(result) + len(
            json.dumps(metadata, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )

    def _max_persisted_bytes(self) -> int:
        """Budget for a persisted cache file, derived from the policy.

        Persisted entries cannot legitimately exceed the resident budget
        by more than JSON overhead; anything larger is rejected on load.
        """
        return max(1024 * 1024, 2 * self.policy.max_size_bytes + 1024 * 1024)

    async def start(self) -> None:
        """Start background cleanup task."""
        if self._running:
            return
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self) -> None:
        """Stop background cleanup task and persist, if configured.

        Persistence is part of the lifecycle: a cache with a
        ``storage_path`` is saved here (and therefore on async-context
        exit). A failed save is recorded, never silently claimed.
        """
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            self._cleanup_task = None
        if self.storage_path:
            self._save_to_disk()

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
        with self._lock:
            now = datetime.now(UTC)
            expired_keys = []

            for key, entry in self._cache.items():
                expires_at = _parse_time(entry.expires_at)
                if expires_at is None or expires_at <= now:
                    expired_keys.append(key)

            for key in expired_keys:
                self._remove_entry(key, InvalidationReason.TTL_EXPIRED)

            return len(expired_keys)

    def _evict_lru(self) -> bool:
        """Evict least recently used entry. Returns True if evicted."""
        with self._lock:
            if not self._cache:
                return False

            # Find LRU entry (first in OrderedDict)
            lru_key = next(iter(self._cache))
            self._remove_entry(lru_key, InvalidationReason.EVICTION)
            return True

    def _drop_entry(self, key: str) -> bool:
        """Remove an entry, fixing index and totals, without counters.

        Replacement accounting: a replaced entry is dropped, not counted
        as an eviction or an invalidation.
        """
        with self._lock:
            if key not in self._cache:
                return False
            entry = self._cache.pop(key)
            self._detector_index[entry.detector_id].discard(key)
            if not self._detector_index[entry.detector_id]:
                del self._detector_index[entry.detector_id]
            self.stats.total_entries -= 1
            self.stats.total_size_bytes -= entry.size_bytes
            return True

    def _remove_entry(self, key: str, reason: InvalidationReason) -> bool:
        """Remove an entry from cache."""
        with self._lock:
            if not self._drop_entry(key):
                return False

            if reason == InvalidationReason.EVICTION:
                self.stats.evictions += 1
            elif reason == InvalidationReason.TTL_EXPIRED:
                self.stats.expired_entries += 1
            else:
                self.stats.invalidations += 1

            return True

    def _ensure_capacity(self, incoming_size: int) -> None:
        """Evict LRU entries until the incoming entry fits.

        Admission is checked against the incoming entry's resident cost,
        not only against the state before it arrives.
        """
        with self._lock:
            while len(self._cache) >= self.policy.max_entries:
                if not self._evict_lru():
                    break
            while self.stats.total_size_bytes + incoming_size > self.policy.max_size_bytes:
                if not self._evict_lru():
                    break

    def _check_config(self, entry: CacheEntry, detector_id: str) -> bool:
        """Fail-closed config check: True only if the entry is usable.

        When a current config hash is known, the entry must carry exactly
        that hash. A missing or mismatched hash is invalid, never fresh.
        With no current config recorded, nothing is known to be wrong.
        """
        if not self.invalidation_policy.invalidate_on_config_change:
            return True
        current_config = self._config_hashes.get(detector_id)
        if current_config is None:
            return True
        return entry.metadata.get("config_hash") == current_config

    def _check_max_age(self, entry: CacheEntry) -> bool:
        """True only if the entry is within max_age_seconds, if configured."""
        max_age = self.invalidation_policy.max_age_seconds
        if max_age is None:
            return True
        created_at = _parse_time(entry.created_at)
        if created_at is None:
            return False
        return (datetime.now(UTC) - created_at).total_seconds() <= max_age

    def get(
        self,
        text: str,
        detector_id: str,
        detector_version: str,
    ) -> tuple[dict[str, Any] | None, CacheEntryStatus]:
        """Get cached result for text and detector.

        Returns a deep copy of the cached result: mutating it cannot
        change cached evidence.
        """
        content_hash = self._compute_content_hash(text)
        key = self._generate_key(content_hash, detector_id, detector_version)

        with self._lock:
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

            # Check for config change (fail closed: missing hash invalidates)
            if not self._check_config(entry, detector_id):
                self._remove_entry(key, InvalidationReason.CONFIG_CHANGED)
                self.stats.misses += 1
                return None, CacheEntryStatus.INVALIDATED

            # Check expiration (fail closed on unparseable expiry)
            if entry.is_expired():
                self._remove_entry(key, InvalidationReason.TTL_EXPIRED)
                self.stats.misses += 1
                return None, CacheEntryStatus.EXPIRED

            # Check maximum age
            if not self._check_max_age(entry):
                self._remove_entry(key, InvalidationReason.MAX_AGE_EXCEEDED)
                self.stats.misses += 1
                return None, CacheEntryStatus.INVALIDATED

            # Custom invalidator. It runs under the re-entrant lock (see
            # the module docstring), receives a deep copy, and an exception
            # from it invalidates the entry instead of propagating.
            if self.invalidation_policy.custom_invalidator:
                try:
                    invalid = self.invalidation_policy.custom_invalidator(
                        copy.deepcopy(entry.result), None
                    )
                except Exception:
                    invalid = True
                if invalid:
                    self._remove_entry(key, InvalidationReason.MANUAL)
                    self.stats.misses += 1
                    return None, CacheEntryStatus.INVALIDATED

            # Hit! Update access metadata. The touch/reinsert happens
            # inside the same locked transaction as the lookup, so a
            # concurrent clear cannot be undone by this write-back.
            self._cache[key] = entry.touch()
            self.stats.hits += 1

            # Move to end (most recently used)
            self._cache.move_to_end(key)

            return copy.deepcopy(entry.result), CacheEntryStatus.FRESH

    async def put(
        self,
        text: str,
        detector_id: str,
        detector_version: str,
        result: dict[str, Any],
        ttl_seconds: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Store a result in cache.

        Returns False (without storing anything) when the entry's
        resident size alone exceeds the budget. Raises ValueError for a
        non-finite or non-positive explicit TTL override. The result and
        metadata are deep-copied, so later caller mutation cannot change
        cached evidence or its accounting.
        """
        if ttl_seconds is None:
            ttl = self.policy.ttl_seconds
        elif not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a finite positive number")
        else:
            ttl = ttl_seconds

        # Snapshot the caller's data first: later mutation of the passed
        # dicts must not change what is cached or how it is charged.
        stored_result = copy.deepcopy(result)
        stored_metadata = copy.deepcopy(metadata or {})
        resident_size = self._resident_size(stored_result, stored_metadata)

        # A single entry larger than the whole budget can never fit.
        if resident_size > self.policy.max_size_bytes:
            return False

        content_hash = self._compute_content_hash(text)
        key = self._generate_key(content_hash, detector_id, detector_version)

        now = datetime.now(UTC)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl, UTC).isoformat()

        entry = CacheEntry(
            content_hash=content_hash,
            detector_id=detector_id,
            detector_version=detector_version,
            result=stored_result,
            created_at=now.isoformat(),
            expires_at=expires_at,
            size_bytes=resident_size,
            metadata=stored_metadata,
        )

        with self._lock:
            # Replacement: subtract the old entry before admission, so a
            # repeated put of one key never double-counts entries or bytes.
            self._drop_entry(key)

            # Ensure capacity against the incoming entry's resident cost.
            self._ensure_capacity(resident_size)

            # Store
            self._cache[key] = entry
            self._detector_index[detector_id].add(key)

            self.stats.total_entries += 1
            self.stats.total_size_bytes += resident_size
            self.stats.total_size_bytes_ever += resident_size

            return True

    def invalidate(
        self,
        detector_id: str | None = None,
        detector_version: str | None = None,
        content_hash: str | None = None,
        reason: InvalidationReason = InvalidationReason.MANUAL,
    ) -> int:
        """Invalidate cache entries matching criteria."""
        with self._lock:
            if content_hash and detector_id and detector_version:
                key = self._generate_key(content_hash, detector_id, detector_version)
                if key in self._cache:
                    self._remove_entry(key, reason)
                    return 1
                return 0

            # Match by detector
            keys_to_remove = []
            if detector_id:
                for key in list(self._detector_index.get(detector_id, set())):
                    entry = self._cache.get(key)
                    if entry is None:
                        continue
                    if (
                        detector_version is None or entry.detector_version == detector_version
                    ) and (content_hash is None or entry.content_hash == content_hash):
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
        with self._lock:
            old_version = self._model_versions.get(detector_id)
            self._model_versions[detector_id] = new_version

            if not old_version or old_version == new_version:
                return 0

            return self.invalidate(
                detector_id=detector_id, reason=InvalidationReason.MODEL_VERSION_CHANGED
            )

    def invalidate_config(self, detector_id: str, new_config_hash: str) -> int:
        """Invalidate all entries for a detector when config changes."""
        with self._lock:
            self._config_hashes[detector_id] = new_config_hash
            return self.invalidate(
                detector_id=detector_id, reason=InvalidationReason.CONFIG_CHANGED
            )

    def set_model_version(self, detector_id: str, version: str) -> None:
        """Set current model version for a detector."""
        with self._lock:
            self._model_versions[detector_id] = version

    def set_config_hash(self, detector_id: str, config_hash: str) -> None:
        """Set current config hash for a detector."""
        with self._lock:
            self._config_hashes[detector_id] = config_hash

    def get_stats(self) -> CacheStats:
        """Get a snapshot copy of cache statistics."""
        with self._lock:
            return CacheStats(
                total_entries=self.stats.total_entries,
                total_size_bytes=self.stats.total_size_bytes,
                hits=self.stats.hits,
                misses=self.stats.misses,
                evictions=self.stats.evictions,
                invalidations=self.stats.invalidations,
                expired_entries=self.stats.expired_entries,
                total_size_bytes_ever=self.stats.total_size_bytes_ever,
            )

    def get_entry_status(
        self, text: str, detector_id: str, detector_version: str
    ) -> CacheEntryStatus:
        """Get status of a cache entry without modifying it.

        Applies the same fail-closed model/config/max-age/expiry checks
        as :meth:`get`, without removing the entry, touching statistics,
        or invoking the custom invalidator.
        """
        content_hash = self._compute_content_hash(text)
        key = self._generate_key(content_hash, detector_id, detector_version)

        with self._lock:
            if key not in self._cache:
                return CacheEntryStatus.MISSING

            entry = self._cache[key]

            if entry.is_expired():
                return CacheEntryStatus.EXPIRED

            # Check invalidation conditions without removing
            if self.invalidation_policy.invalidate_on_model_version_change:
                current_version = self._model_versions.get(detector_id)
                if current_version and current_version != entry.detector_version:
                    return CacheEntryStatus.INVALIDATED

            if not self._check_config(entry, detector_id):
                return CacheEntryStatus.INVALIDATED

            if not self._check_max_age(entry):
                return CacheEntryStatus.INVALIDATED

            return CacheEntryStatus.FRESH

    def get_all_entries(self) -> list[CacheEntry]:
        """Get deep copies of all cache entries (for inspection/debugging)."""
        with self._lock:
            return copy.deepcopy(list(self._cache.values()))

    def clear(self) -> int:
        """Clear all cache entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._detector_index.clear()
            self.stats.total_entries = 0
            self.stats.total_size_bytes = 0
            return count

    def save(self) -> bool:
        """Persist the cache to ``storage_path`` (if configured).

        Atomic: temp file + flush + fsync + ``os.replace``. Returns
        False (and records :attr:`last_persistence_error`) on failure
        instead of claiming success; the previous durable file is left
        untouched.
        """
        return self._save_to_disk()

    def _save_to_disk(self) -> bool:
        """Save cache to disk."""
        if not self.storage_path:
            return False

        with self._lock:
            data = {
                "version": 1,
                "entries": [entry.to_dict() for entry in self._cache.values()],
                "model_versions": dict(self._model_versions),
                "config_hashes": dict(self._config_hashes),
            }
        payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")

        temp_path: str | None = None
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_path = tempfile.mkstemp(
                dir=self.storage_path.parent,
                prefix=f".{self.storage_path.name}.",
                suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_path, self.storage_path)
                temp_path = None
            finally:
                if temp_path is not None:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(temp_path)
            # Best-effort directory fsync so the rename itself is durable.
            try:
                dir_fd = os.open(self.storage_path.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
            self.last_persistence_error = None
            return True
        except Exception as exc:
            self.last_persistence_error = f"{type(exc).__name__}: {exc}"
            return False

    def load(self) -> bool:
        """Load the cache from ``storage_path`` (if configured).

        Validates the whole file into temporary structures before
        publishing anything. Returns False (and records
        :attr:`last_persistence_error`) on any malformed input, leaving
        the prior in-memory state untouched.
        """
        return self._load_from_disk()

    def _load_from_disk(self) -> bool:
        """Load cache from disk."""
        if not self.storage_path or not self.storage_path.exists():
            return False

        try:
            raw = self.storage_path.read_bytes()
        except Exception as exc:
            self.last_persistence_error = f"{type(exc).__name__}: {exc}"
            return False

        try:
            if len(raw) > self._max_persisted_bytes():
                raise ValueError(
                    f"cache file is {len(raw)} bytes, over the "
                    f"{self._max_persisted_bytes()}-byte budget"
                )
            data = json.loads(raw.decode("utf-8"), parse_constant=_reject_json_constant)
            if not isinstance(data, dict):
                raise ValueError("cache file must be a JSON object")
            if data.get("version") != 1:
                raise ValueError(f"unsupported cache file version {data.get('version')!r}")
            raw_entries = data.get("entries", [])
            if not isinstance(raw_entries, list):
                raise ValueError("cache file 'entries' must be a list")
            model_versions = _validate_str_map(data.get("model_versions", {}), "model_versions")
            config_hashes = _validate_str_map(data.get("config_hashes", {}), "config_hashes")

            # Validate every entry before publishing any of them.
            entries = [_validate_entry_dict(item) for item in raw_entries]

            # Admit through the same capacity rules as put(), in file
            # order (LRU first): recompute resident sizes, drop expired
            # and single oversized entries, evict LRU when over budget.
            now = datetime.now(UTC)
            new_cache: OrderedDict[str, CacheEntry] = OrderedDict()
            new_index: dict[str, set[str]] = defaultdict(set)
            total_entries = 0
            total_size = 0

            def drop_temp(key: str) -> None:
                nonlocal total_entries, total_size
                old = new_cache.pop(key)
                new_index[old.detector_id].discard(key)
                if not new_index[old.detector_id]:
                    del new_index[old.detector_id]
                total_entries -= 1
                total_size -= old.size_bytes

            for entry in entries:
                expires_at = _parse_time(entry.expires_at)
                if expires_at is None or expires_at <= now:
                    continue
                resident = self._resident_size(entry.result, entry.metadata)
                if resident > self.policy.max_size_bytes:
                    continue
                entry = CacheEntry(
                    content_hash=entry.content_hash,
                    detector_id=entry.detector_id,
                    detector_version=entry.detector_version,
                    result=entry.result,
                    created_at=entry.created_at,
                    expires_at=entry.expires_at,
                    access_count=entry.access_count,
                    last_accessed=entry.last_accessed,
                    size_bytes=resident,
                    metadata=entry.metadata,
                )
                key = self._generate_key(
                    entry.content_hash, entry.detector_id, entry.detector_version
                )
                if key in new_cache:
                    drop_temp(key)
                while len(new_cache) >= self.policy.max_entries:
                    if not new_cache:
                        break
                    drop_temp(next(iter(new_cache)))
                while total_size + resident > self.policy.max_size_bytes:
                    if not new_cache:
                        break
                    drop_temp(next(iter(new_cache)))
                new_cache[key] = entry
                new_index[entry.detector_id].add(key)
                total_entries += 1
                total_size += resident
        except Exception as exc:
            self.last_persistence_error = f"{type(exc).__name__}: {exc}"
            return False

        with self._lock:
            self._cache = new_cache
            self._detector_index = new_index
            self.stats.total_entries = total_entries
            self.stats.total_size_bytes = total_size
            self._model_versions = model_versions
            self._config_hashes = config_hashes
            self.last_persistence_error = None
        return True

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
