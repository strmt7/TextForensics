"""Tests for Detection Cache."""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from textforensics.detection_cache import (
    CacheEntry,
    CacheEntryStatus,
    CachePolicy,
    CacheStats,
    InvalidationPolicy,
    InvalidationReason,
    create_detection_cache,
)


class TestCachePolicy:
    def test_default_policy(self):
        policy = CachePolicy()
        assert policy.ttl_seconds == 3600.0
        assert policy.max_entries == 10000
        assert policy.max_size_bytes == 100 * 1024 * 1024

    def test_custom_policy(self):
        policy = CachePolicy(
            ttl_seconds=7200.0,
            max_entries=5000,
            max_size_bytes=50 * 1024 * 1024,
        )
        assert policy.ttl_seconds == 7200.0
        assert policy.max_entries == 5000
        assert policy.max_size_bytes == 50 * 1024 * 1024

    def test_invalid_ttl(self):
        with pytest.raises(ValueError):
            CachePolicy(ttl_seconds=0)

    def test_invalid_max_entries(self):
        with pytest.raises(ValueError):
            CachePolicy(max_entries=0)


class TestInvalidationPolicy:
    def test_default_policy(self):
        policy = InvalidationPolicy()
        assert policy.invalidate_on_model_version_change is True
        assert policy.invalidate_on_config_change is True
        assert policy.max_age_seconds is None
        assert policy.custom_invalidator is None

    def test_custom_invalidator(self):
        def custom_invalidator(entry, _):
            return entry.get("verdict") == "ai"

        policy = InvalidationPolicy(custom_invalidator=custom_invalidator)
        assert policy.custom_invalidator is not None


class TestCacheEntry:
    def test_entry_creation(self):
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={"verdict": "ai", "score": 0.9},
            created_at="2024-01-01T00:00:00+00:00",
            expires_at="2024-01-01T01:00:00+00:00",
            size_bytes=100,
        )
        assert entry.content_hash == "abc123"
        assert entry.detector_id == "test/detector"
        assert entry.access_count == 0

    def test_entry_serialization(self):
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={"verdict": "ai"},
            created_at="2024-01-01T00:00:00+00:00",
            expires_at="2024-01-01T01:00:00+00:00",
        )
        d = entry.to_dict()
        entry2 = CacheEntry.from_dict(d)
        assert entry2.content_hash == entry.content_hash
        assert entry2.detector_id == entry.detector_id
        assert entry2.result == entry.result

    def test_entry_expiration(self):
        from datetime import datetime, timedelta, timezone

        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={},
            created_at="2024-01-01T00:00:00+00:00",
            expires_at=past,
        )
        assert entry.is_expired() is True

        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        entry2 = CacheEntry(
            content_hash="abc123",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={},
            created_at="2024-01-01T00:00:00+00:00",
            expires_at=future,
        )
        assert entry2.is_expired() is False

    def test_entry_touch(self):
        entry = CacheEntry(
            content_hash="abc123",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={},
            created_at="2024-01-01T00:00:00+00:00",
            expires_at="2024-01-01T01:00:00+00:00",
        )
        original_access = entry.access_count
        touched = entry.touch()
        assert touched.access_count == original_access + 1
        assert touched.last_accessed != ""


class TestCacheStats:
    def test_stats_creation(self):
        stats = CacheStats()
        assert stats.total_entries == 0
        assert stats.hits == 0
        assert stats.misses == 0

    def test_hit_rate(self):
        stats = CacheStats(hits=80, misses=20)
        assert stats.hit_rate == 0.8

    def test_hit_rate_zero(self):
        stats = CacheStats()
        assert stats.hit_rate == 0.0


class TestDetectionCache:
    @pytest.fixture
    def cache(self):
        return create_detection_cache(ttl_seconds=3600.0, max_entries=100)

    def test_basic_put_and_get(self, cache):
        text = "This is a test sentence."
        result = {"verdict": "ai", "score": 0.95}

        # Put
        success = asyncio.run(cache.put(
            text=text,
            detector_id="test/detector",
            detector_version="1.0.0",
            result=result,
        ))
        assert success is True

        # Get
        cached_result, status = cache.get(text, "test/detector", "1.0.0")
        assert status == CacheEntryStatus.FRESH
        assert cached_result == result

    def test_cache_miss(self, cache):
        text = "This text is not in cache."
        result, status = cache.get(text, "test/detector", "1.0.0")
        assert result is None
        assert status == CacheEntryStatus.MISSING

    def test_cache_expiration(self):
        cache = create_detection_cache(ttl_seconds=0.001, max_entries=100)  # Very short TTL
        text = "Test text for expiration."
        result = {"verdict": "human", "score": 0.1}

        asyncio.run(cache.put(
            text=text,
            detector_id="test/detector",
            detector_version="1.0.0",
            result=result,
        ))

        time.sleep(0.01)  # Wait for expiration

        result_cached, status = cache.get(text, "test/detector", "1.0.0")
        assert status == CacheEntryStatus.EXPIRED

    def test_lru_eviction(self):
        cache = create_detection_cache(ttl_seconds=3600, max_entries=3)

        # Fill cache beyond capacity
        for i in range(5):
            asyncio.run(cache.put(
                text=f"Text number {i}",
                detector_id="test/detector",
                detector_version="1.0.0",
                result={"verdict": "ai", "score": 0.5 + i * 0.1},
            ))

        # Should have evicted entries
        assert len(cache._cache) <= 3
        assert cache.stats.evictions > 0

    def test_model_version_invalidation(self, cache):
        text = "Test text for version invalidation."
        result = {"verdict": "ai", "score": 0.9}

        # Put with version 1.0
        asyncio.run(cache.put(
            text=text,
            detector_id="test/detector",
            detector_version="1.0.0",
            result=result,
        ))

        # Verify it's there
        result_cached, status = cache.get(text, "test/detector", "1.0.0")
        assert status == CacheEntryStatus.FRESH

        # Update model version
        cache.set_model_version("test/detector", "2.0.0")

        # Should be invalidated now
        result_cached, status = cache.get(text, "test/detector", "2.0.0")
        assert status == CacheEntryStatus.MISSING  # Not in cache with new version

    def test_config_invalidation(self, cache):
        text = "Test text for config invalidation."
        result = {"verdict": "human", "score": 0.1}

        asyncio.run(cache.put(
            text=text,
            detector_id="test/detector",
            detector_version="1.0.0",
            result=result,
            metadata={"config_hash": "abc123"},
        ))

        # Verify it's there
        result_cached, status = cache.get(text, "test/detector", "1.0.0")
        assert status == CacheEntryStatus.FRESH

        # Change config
        cache.set_config_hash("test/detector", "new_config_hash")

        # Should be invalidated
        result_cached, status = cache.get(text, "test/detector", "1.0.0")
        assert status == CacheEntryStatus.INVALIDATED

    def test_manual_invalidation(self, cache):
        text = "Text to manually invalidate."
        result = {"verdict": "ai", "score": 0.8}

        asyncio.run(cache.put(
            text=text,
            detector_id="test/detector",
            detector_version="1.0.0",
            result=result,
        ))

        # Verify it's there
        result_cached, status = cache.get(text, "test/detector", "1.0.0")
        assert status == CacheEntryStatus.FRESH

        # Manually invalidate
        count = cache.invalidate(
            detector_id="test/detector",
            detector_version="1.0.0",
            reason=InvalidationReason.MANUAL,
        )
        assert count == 1

        # Should be gone
        result_cached, status = cache.get(text, "test/detector", "1.0.0")
        assert status == CacheEntryStatus.MISSING

    def test_lru_ordering(self, cache):
        """Test that LRU ordering works correctly."""
        # Add entries
        for i in range(3):
            asyncio.run(cache.put(
                text=f"Text {i}",
                detector_id="test/detector",
                detector_version="1.0.0",
                result={"verdict": "ai", "score": i * 0.1},
            ))

        # Access first entry to make it MRU
        cache.get("Text 0", "test/detector", "1.0.0")

        # Add more entries to trigger eviction
        for i in range(3, 6):
            asyncio.run(cache.put(
                text=f"Text {i}",
                detector_id="test/detector",
                detector_version="1.0.0",
                result={"verdict": "ai", "score": i * 0.1},
            ))

        # "Text 0" should still be there (was accessed recently)
        result, status = cache.get("Text 0", "test/detector", "1.0.0")
        assert status == CacheEntryStatus.FRESH

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cache.json"

            cache1 = create_detection_cache(
                ttl_seconds=3600,
                max_entries=100,
                storage_path=path,
            )

            asyncio.run(cache1.put(
                text="Persistent text.",
                detector_id="test/detector",
                detector_version="1.0.0",
                result={"verdict": "ai", "score": 0.9},
            ))

            # Save to disk
            cache1._save_to_disk()

            # Create new cache instance
            cache2 = create_detection_cache(
                ttl_seconds=3600,
                max_entries=100,
                storage_path=path,
            )

            result, status = cache2.get("Persistent text.", "test/detector", "1.0.0")
            assert status == CacheEntryStatus.FRESH
            assert result["verdict"] == "ai"

    def test_stats(self, cache):
        stats = cache.get_stats()
        assert isinstance(stats, CacheStats)
        assert stats.total_entries == 0
        assert stats.hits == 0
        assert stats.misses == 0

        # Add some data
        asyncio.run(cache.put(
            text="Test",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={"verdict": "ai"},
        ))

        cache.get("Test", "test/detector", "1.0.0")

        stats = cache.get_stats()
        assert stats.total_entries == 1
        assert stats.hits == 1
        assert stats.misses == 0
        assert stats.hit_rate == 1.0

    def test_clear(self, cache):
        asyncio.run(cache.put(
            text="To be cleared",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={"verdict": "ai"},
        ))

        assert cache.get_stats().total_entries == 1

        count = cache.clear()
        assert count == 1
        assert cache.get_stats().total_entries == 0

    def test_get_all_entries(self, cache):
        asyncio.run(cache.put(
            text="Entry 1",
            detector_id="det1",
            detector_version="1.0",
            result={"v": 1},
        ))
        asyncio.run(cache.put(
            text="Entry 2",
            detector_id="det2",
            detector_version="1.0",
            result={"v": 2},
        ))

        entries = cache.get_all_entries()
        assert len(entries) == 2

    def test_entry_status(self, cache):
        asyncio.run(cache.put(
            text="Status test",
            detector_id="test/detector",
            detector_version="1.0.0",
            result={"verdict": "ai"},
        ))

        status = cache.get_entry_status("Status test", "test/detector", "1.0.0")
        assert status == CacheEntryStatus.FRESH

        # After invalidation
        cache.set_model_version("test/detector", "2.0.0")
        status = cache.get_entry_status("Status test", "test/detector", "1.0.0")
        assert status == CacheEntryStatus.INVALIDATED


class TestInvalidationReason:
    def test_reason_values(self):
        assert InvalidationReason.TTL_EXPIRED.value == "ttl_expired"
        assert InvalidationReason.MODEL_VERSION_CHANGED.value == "model_version_changed"
        assert InvalidationReason.CONFIG_CHANGED.value == "config_changed"
        assert InvalidationReason.MANUAL.value == "manual"
        assert InvalidationReason.EVICTION.value == "eviction"
        assert InvalidationReason.CONTENT_HASH_MISMATCH.value == "content_hash_mismatch"


class TestCacheEntryStatus:
    def test_status_values(self):
        assert CacheEntryStatus.FRESH.value == "fresh"
        assert CacheEntryStatus.STALE.value == "stale"
        assert CacheEntryStatus.EXPIRED.value == "expired"
        assert CacheEntryStatus.INVALIDATED.value == "invalidated"
        assert CacheEntryStatus.MISSING.value == "missing"


class TestCreateDetectionCache:
    def test_create_with_defaults(self):
        cache = create_detection_cache()
        assert cache.policy.ttl_seconds == 3600.0
        assert cache.policy.max_entries == 10000

    def test_create_with_custom_params(self):
        cache = create_detection_cache(
            ttl_seconds=7200,
            max_entries=5000,
            max_size_mb=50,
        )
        assert cache.policy.ttl_seconds == 7200
        assert cache.policy.max_entries == 5000
        assert cache.policy.max_size_bytes == 50 * 1024 * 1024


class TestCacheEntryStatusEnum:
    def test_all_values(self):
        assert CacheEntryStatus.FRESH.value == "fresh"
        assert CacheEntryStatus.STALE.value == "stale"
        assert CacheEntryStatus.EXPIRED.value == "expired"
        assert CacheEntryStatus.INVALIDATED.value == "invalidated"
        assert CacheEntryStatus.MISSING.value == "missing"


class TestInvalidationReasonEnum:
    def test_all_values(self):
        assert InvalidationReason.TTL_EXPIRED.value == "ttl_expired"
        assert InvalidationReason.MODEL_VERSION_CHANGED.value == "model_version_changed"
        assert InvalidationReason.CONFIG_CHANGED.value == "config_changed"
        assert InvalidationReason.MANUAL.value == "manual"
        assert InvalidationReason.EVICTION.value == "eviction"
        assert InvalidationReason.CONTENT_HASH_MISMATCH.value == "content_hash_mismatch"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
