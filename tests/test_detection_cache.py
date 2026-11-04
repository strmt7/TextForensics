"""Tests for detection_cache.py — comprehensive coverage.

This module was previously at 74% coverage. These tests exercise:
- CachePolicy: validation, defaults
- InvalidationPolicy: configuration
- CacheEntry: serialization, expiration, touch
- CacheStats: hit_rate, serialization
- DetectionCache: get, put, invalidate, model version changes, config changes
- LRU eviction, capacity limits, TTL expiration
- Disk persistence: save/load
- Background cleanup task
- Async context manager
- create_detection_cache factory
- Edge cases: missing entries, corrupted data, empty cache
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from textforensics.detection_cache import (
    CacheEntry,
    CacheEntryStatus,
    CachePolicy,
    CacheStats,
    DetectionCache,
    InvalidationPolicy,
    InvalidationReason,
    create_detection_cache,
)


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def cache():
    """Create a cache with short TTL for testing."""
    policy = CachePolicy(ttl_seconds=0.1, max_entries=100, max_size_bytes=1024 * 1024)
    return DetectionCache(policy=policy)


@pytest.fixture
def cache_with_storage():
    """Create a cache with disk storage."""
    with tempfile.TemporaryDirectory() as td:
        storage = Path(td) / "cache.json"
        policy = CachePolicy(ttl_seconds=3600.0, max_entries=1000)
        cache = DetectionCache(policy=policy, storage_path=storage)
        yield cache


# ============================================================
# Synchronous tests (no await needed)
# ============================================================

class TestCachePolicy:
    """Tests for CachePolicy dataclass."""

    def test_default_values(self):
        policy = CachePolicy()
        assert policy.ttl_seconds == 3600.0
        assert policy.max_entries == 10000
        assert policy.max_size_bytes == 100 * 1024 * 1024
        assert policy.check_interval_seconds == 60.0
        assert policy.enable_compression is True
        assert policy.compress_threshold_bytes == 1024

    def test_custom_values(self):
        policy = CachePolicy(
            ttl_seconds=7200.0,
            max_entries=5000,
            max_size_bytes=50 * 1024 * 1024,
            check_interval_seconds=30.0,
            enable_compression=False,
            compress_threshold_bytes=2048,
        )
        assert policy.ttl_seconds == 7200.0
        assert policy.max_entries == 5000
        assert policy.max_size_bytes == 50 * 1024 * 1024
        assert policy.check_interval_seconds == 30.0
        assert policy.enable_compression is False
        assert policy.compress_threshold_bytes == 2048

    def test_invalid_ttl_raises(self):
        with pytest.raises(ValueError, match="ttl_seconds must be positive"):
            CachePolicy(ttl_seconds=0)
        with pytest.raises(ValueError, match="ttl_seconds must be positive"):
            CachePolicy(ttl_seconds=-1)

    def test_invalid_max_entries_raises(self):
        with pytest.raises(ValueError, match="max_entries must be positive"):
            CachePolicy(max_entries=0)

    def test_invalid_max_size_raises(self):
        with pytest.raises(ValueError, match="max_size_bytes must be positive"):
            CachePolicy(max_size_bytes=0)


class TestInvalidationPolicy:
    """Tests for InvalidationPolicy dataclass."""

    def test_default_values(self):
        policy = InvalidationPolicy()
        assert policy.invalidate_on_model_version_change is True
        assert policy.invalidate_on_config_change is True
        assert policy.max_age_seconds is None
        assert policy.custom_invalidator is None

    def test_custom_values(self):
        def custom(entry, _):
            return False
        policy = InvalidationPolicy(
            invalidate_on_model_version_change=False,
            invalidate_on_config_change=False,
            max_age_seconds=1800.0,
            custom_invalidator=custom,
        )
        assert policy.invalidate_on_model_version_change is False
        assert policy.invalidate_on_config_change is False
        assert policy.max_age_seconds == 1800.0
        assert policy.custom_invalidator is custom


class TestCacheEntry:
    """Tests for CacheEntry dataclass."""

    def test_to_dict_and_from_dict(self):
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="det1",
            detector_version="1.0",
            result={"score": 0.5, "verdict": "human"},
            created_at="2024-01-01T00:00:00Z",
            expires_at="2024-01-01T01:00:00Z",
            access_count=5,
            last_accessed="2024-01-01T00:30:00Z",
            size_bytes=1024,
            metadata={"config_hash": "config1"},
        )
        d = entry.to_dict()
        restored = CacheEntry.from_dict(d)
        assert restored.content_hash == "abc123"
        assert restored.detector_id == "det1"
        assert restored.detector_version == "1.0"
        assert restored.result == {"score": 0.5, "verdict": "human"}
        assert restored.access_count == 5
        assert restored.size_bytes == 1024
        assert restored.metadata == {"config_hash": "config1"}

    def test_is_expired_false(self):
        from datetime import datetime, timezone, timedelta
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="det1",
            detector_version="1.0",
            result={},
            created_at="2024-01-01T00:00:00Z",
            expires_at=future.isoformat(),
        )
        assert entry.is_expired() is False

    def test_is_expired_true(self):
        from datetime import datetime, timezone, timedelta
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="det1",
            detector_version="1.0",
            result={},
            created_at="2024-01-01T00:00:00Z",
            expires_at=past.isoformat(),
        )
        assert entry.is_expired() is True

    def test_touch_updates_access_metadata(self):
        from datetime import datetime, timezone, timedelta
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="det1",
            detector_version="1.0",
            result={},
            created_at="2024-01-01T00:00:00Z",
            expires_at=future.isoformat(),
            access_count=3,
            last_accessed="2024-01-01T00:00:00Z",
        )
        touched = entry.touch()
        assert touched.access_count == 4
        assert touched.last_accessed != "2024-01-01T00:00:00Z"
        # Original unchanged (frozen=True)
        assert entry.access_count == 3


class TestCacheStats:
    """Tests for CacheStats dataclass."""

    def test_hit_rate_zero_when_no_requests(self):
        stats = CacheStats()
        assert stats.hit_rate == 0.0

    def test_hit_rate_calculation(self):
        stats = CacheStats(hits=7, misses=3)
        assert stats.hit_rate == 0.7

    def test_hit_rate_all_hits(self):
        stats = CacheStats(hits=10, misses=0)
        assert stats.hit_rate == 1.0

    def test_to_dict(self):
        stats = CacheStats(
            total_entries=100,
            total_size_bytes=50000,
            hits=80,
            misses=20,
            evictions=5,
            invalidations=3,
            expired_entries=2,
            total_size_bytes_ever=100000,
        )
        d = stats.to_dict()
        assert d["total_entries"] == 100
        assert d["hits"] == 80
        assert d["misses"] == 20
        assert d["hit_rate"] == 0.8
        assert d["evictions"] == 5


# ============================================================
# Async tests
# ============================================================

class TestDetectionCache:
    """Tests for DetectionCache class."""

    @pytest.mark.asyncio
    async def test_put_and_get_hit(self, cache):
        """Basic put and get should return FRESH hit."""
        await cache.put("test text", "det1", "1.0", {"score": 0.5, "verdict": "human"})
        result, status = cache.get("test text", "det1", "1.0")
        assert status == CacheEntryStatus.FRESH
        assert result == {"score": 0.5, "verdict": "human"}

    @pytest.mark.asyncio
    async def test_get_missing_returns_missing(self, cache):
        result, status = cache.get("unknown text", "det1", "1.0")
        assert result is None
        assert status == CacheEntryStatus.MISSING

    @pytest.mark.asyncio
    async def test_get_wrong_detector_version_invalidated(self, cache):
        await cache.put("test text", "det1", "1.0", {"score": 0.5})
        cache.set_model_version("det1", "2.0")
        result, status = cache.get("test text", "det1", "1.0")
        assert status == CacheEntryStatus.INVALIDATED
        assert result is None

    @pytest.mark.asyncio
    async def test_get_wrong_config_hash_invalidated(self, cache):
        await cache.put("test text", "det1", "1.0", {"score": 0.5}, metadata={"config_hash": "old"})
        cache.set_config_hash("det1", "new")
        result, status = cache.get("test text", "det1", "1.0")
        assert status == CacheEntryStatus.INVALIDATED

    @pytest.mark.asyncio
    async def test_get_expired_entry(self, cache):
        import time
        await cache.put("test text", "det1", "1.0", {"score": 0.5})
        time.sleep(0.2)  # Wait for TTL (0.1s)
        result, status = cache.get("test text", "det1", "1.0")
        assert status == CacheEntryStatus.EXPIRED
        assert result is None

    @pytest.mark.asyncio
    async def test_get_entry_status_without_modifying(self, cache):
        await cache.put("test text", "det1", "1.0", {"score": 0.5})
        status = cache.get_entry_status("test text", "det1", "1.0")
        assert status == CacheEntryStatus.FRESH
        # Stats should not change
        assert cache.stats.hits == 0
        assert cache.stats.misses == 0

    @pytest.mark.asyncio
    async def test_get_entry_status_expired(self, cache):
        import time
        await cache.put("test text", "det1", "1.0", {"score": 0.5})
        time.sleep(0.2)
        status = cache.get_entry_status("test text", "det1", "1.0")
        assert status == CacheEntryStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_invalidate_specific_entry(self, cache):
        await cache.put("text1", "det1", "1.0", {"score": 0.5})
        await cache.put("text2", "det1", "1.0", {"score": 0.6})
        content_hash = cache._compute_content_hash("text1")
        count = cache.invalidate(content_hash=content_hash, detector_id="det1", detector_version="1.0")
        assert count == 1
        result, status = cache.get("text1", "det1", "1.0")
        assert status == CacheEntryStatus.MISSING
        result, status = cache.get("text2", "det1", "1.0")
        assert status == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_invalidate_by_detector_id(self, cache):
        await cache.put("text1", "det1", "1.0", {"score": 0.5})
        await cache.put("text2", "det2", "1.0", {"score": 0.6})
        count = cache.invalidate(detector_id="det1")
        assert count == 1
        result, status = cache.get("text1", "det1", "1.0")
        assert status == CacheEntryStatus.MISSING
        result, status = cache.get("text2", "det2", "1.0")
        assert status == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_invalidate_by_content_hash(self, cache):
        await cache.put("same text", "det1", "1.0", {"score": 0.5})
        await cache.put("same text", "det2", "1.0", {"score": 0.6})
        content_hash = cache._compute_content_hash("same text")
        count = cache.invalidate(content_hash=content_hash)
        assert count == 2

    @pytest.mark.asyncio
    async def test_invalidate_model_version(self, cache):
        await cache.put("text1", "det1", "1.0", {"score": 0.5})
        await cache.put("text2", "det1", "1.0", {"score": 0.6})
        await cache.put("text3", "det2", "1.0", {"score": 0.7})
        # Must set the old version first
        cache.set_model_version("det1", "1.0")
        count = cache.invalidate_model_version("det1", "2.0")
        assert count == 2
        assert cache._model_versions["det1"] == "2.0"
        # Same version -> no invalidation
        count2 = cache.invalidate_model_version("det1", "2.0")
        assert count2 == 0

    @pytest.mark.asyncio
    async def test_invalidate_config(self, cache):
        await cache.put("text1", "det1", "1.0", {"score": 0.5})
        await cache.put("text2", "det1", "1.0", {"score": 0.6})
        count = cache.invalidate_config("det1", "new_hash")
        assert count == 2
        assert cache._config_hashes["det1"] == "new_hash"

    @pytest.mark.asyncio
    async def test_lru_eviction_on_max_entries(self, cache):
        policy = CachePolicy(ttl_seconds=3600, max_entries=3, max_size_bytes=1024*1024)
        cache = DetectionCache(policy=policy)
        await cache.put("a", "det", "1.0", {"v": 1})
        await cache.put("b", "det", "1.0", {"v": 2})
        await cache.put("c", "det", "1.0", {"v": 3})
        # Adding 4th should evict LRU (a)
        await cache.put("d", "det", "1.0", {"v": 4})
        assert cache.get("a", "det", "1.0")[1] == CacheEntryStatus.MISSING
        assert cache.get("b", "det", "1.0")[1] == CacheEntryStatus.FRESH
        assert cache.get("c", "det", "1.0")[1] == CacheEntryStatus.FRESH
        assert cache.get("d", "det", "1.0")[1] == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_lru_eviction_on_max_size(self, cache):
        policy = CachePolicy(ttl_seconds=3600, max_entries=1000, max_size_bytes=1000)
        cache = DetectionCache(policy=policy)
        # Each entry ~200 bytes, so 5 should evict
        for i in range(7):
            await cache.put(f"text{i}", "det", "1.0", {"data": "x" * 200})
        # First entries should be evicted
        assert cache.stats.evictions >= 1

    @pytest.mark.asyncio
    async def test_custom_invalidator(self, cache):
        def invalidator(entry, _):
            return entry.get("score", 0) > 0.8
        policy = InvalidationPolicy(custom_invalidator=invalidator)
        cache = DetectionCache(policy=CachePolicy(), invalidation_policy=policy)
        await cache.put("low", "det", "1.0", {"score": 0.5})
        await cache.put("high", "det", "1.0", {"score": 0.9})
        result, status = cache.get("low", "det", "1.0")
        assert status == CacheEntryStatus.FRESH
        result, status = cache.get("high", "det", "1.0")
        assert status == CacheEntryStatus.INVALIDATED

    @pytest.mark.asyncio
    async def test_clear(self, cache):
        await cache.put("text1", "det", "1.0", {"score": 0.5})
        await cache.put("text2", "det", "1.0", {"score": 0.6})
        count = cache.clear()
        assert count == 2
        assert cache.stats.total_entries == 0
        assert cache.stats.total_size_bytes == 0
        assert len(cache._cache) == 0

    @pytest.mark.asyncio
    async def test_get_all_entries(self, cache):
        await cache.put("a", "det", "1.0", {"v": 1})
        await cache.put("b", "det", "1.0", {"v": 2})
        entries = cache.get_all_entries()
        assert len(entries) == 2

    @pytest.mark.asyncio
    async def test_stats_tracking(self, cache):
        await cache.put("text", "det", "1.0", {"score": 0.5})
        cache.get("text", "det", "1.0")  # hit
        cache.get("unknown", "det", "1.0")  # miss
        stats = cache.get_stats()
        assert stats.hits == 1
        assert stats.misses == 1
        assert stats.hit_rate == 0.5

    @pytest.mark.asyncio
    async def test_save_load_persistence(self, cache_with_storage):
        cache = cache_with_storage
        await cache.put("text1", "det1", "1.0", {"score": 0.5})
        await cache.put("text2", "det1", "1.0", {"score": 0.6})
        cache.set_model_version("det1", "1.0")
        cache.set_config_hash("det1", "config1")
        cache._save_to_disk()

        # Load into new cache
        policy = CachePolicy(ttl_seconds=3600)
        cache2 = DetectionCache(policy=policy, storage_path=cache.storage_path)
        assert cache2.stats.total_entries == 2
        assert cache2._model_versions["det1"] == "1.0"
        assert cache2._config_hashes["det1"] == "config1"
        result, status = cache2.get("text1", "det1", "1.0")
        assert status == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_load_corrupt_file_returns_false(self):
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            storage.write_text("not json")
            policy = CachePolicy(ttl_seconds=3600)
            cache = DetectionCache(policy=policy, storage_path=storage)
            # Should not crash, just start empty
            assert cache.stats.total_entries == 0

    @pytest.mark.asyncio
    async def test_save_without_storage_path_returns_false(self):
        cache = DetectionCache()
        assert cache._save_to_disk() is False

    @pytest.mark.asyncio
    async def test_compression_large_results(self, cache):
        large_result = {"data": "x" * 5000}  # > 1KB threshold
        await cache.put("large", "det", "1.0", large_result)
        result, status = cache.get("large", "det", "1.0")
        assert status == CacheEntryStatus.FRESH
        assert result == large_result

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        policy = CachePolicy(ttl_seconds=3600, check_interval_seconds=0.01)
        async with DetectionCache(policy=policy) as cache:
            await cache.put("text", "det", "1.0", {"score": 0.5})
            result, status = cache.get("text", "det", "1.0")
            assert status == CacheEntryStatus.FRESH


class TestCreateDetectionCache:
    """Tests for create_detection_cache factory function."""

    def test_default_parameters(self):
        cache = create_detection_cache()
        assert cache.policy.ttl_seconds == 3600.0
        assert cache.policy.max_entries == 10000
        assert cache.policy.max_size_bytes == 100 * 1024 * 1024

    def test_custom_parameters(self):
        cache = create_detection_cache(
            ttl_seconds=7200,
            max_entries=5000,
            max_size_mb=50,
            storage_path=Path("/tmp/cache.json"),
        )
        assert cache.policy.ttl_seconds == 7200
        assert cache.policy.max_entries == 5000
        assert cache.policy.max_size_bytes == 50 * 1024 * 1024
        assert cache.storage_path == Path("/tmp/cache.json")


class TestEdgeCases:
    """Edge case and regression tests."""

    @pytest.mark.asyncio
    async def test_put_with_custom_ttl(self, cache):
        await cache.put("text", "det", "1.0", {"score": 0.5}, ttl_seconds=7200)
        result, status = cache.get("text", "det", "1.0")
        assert status == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_put_with_metadata(self, cache):
        await cache.put("text", "det", "1.0", {"score": 0.5}, metadata={"source": "test"})
        result, status = cache.get("text", "det", "1.0")
        assert status == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_invalidate_nonexistent_returns_zero(self, cache):
        count = cache.invalidate(detector_id="nonexistent")
        assert count == 0

    @pytest.mark.asyncio
    async def test_empty_cache_operations(self, cache):
        assert cache.get_all_entries() == []
        assert cache.clear() == 0
        assert cache.stats.total_entries == 0

    @pytest.mark.asyncio
    async def test_version_mismatch_with_no_current_version(self, cache):
        """If no current version set, should not invalidate."""
        await cache.put("text", "det", "1.0", {"score": 0.5})
        # Don't set model version
        result, status = cache.get("text", "det", "1.0")
        assert status == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_config_mismatch_with_no_current_config(self, cache):
        """If no current config hash set, should not invalidate."""
        await cache.put("text", "det", "1.0", {"score": 0.5}, metadata={"config_hash": "abc"})
        result, status = cache.get("text", "det", "1.0")
        assert status == CacheEntryStatus.FRESH


if __name__ == "__main__":
    pytest.main([__file__, "-v"])