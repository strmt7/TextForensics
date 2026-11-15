"""W4 mutation kill tests: textforensics.detection_cache (Worker F2).

Each test kills one or more phase-1 survivors from the W4 proof set
(audit-w4-f-proofset.json / audit-w4-f-survivors.json). The tests drive
DetectionCache through put/get/invalidate and through the disk loader,
with direct _cache/_detector_index setup where the mutant changes a
capacity or eviction rule the public API cannot otherwise reach, and
with a fixed-clock stub where the mutant only differs at an exact
equality instant. Equivalent detection_cache mutants are documented in
audit-w4-f-equiv-reasons-detection_cache.json and must SURVIVE this file.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

import textforensics.detection_cache as dc
from textforensics.detection_cache import (
    CacheEntry,
    CacheEntryStatus,
    CachePolicy,
    DetectionCache,
    InvalidationPolicy,
    InvalidationReason,
    _parse_time,
    _validate_entry_dict,
    _validate_str_map,
)

FUTURE = "2999-01-01T00:00:00+00:00"
PAST = "2000-01-01T00:00:00+00:00"
CREATED = "2026-01-01T00:00:00+00:00"


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _entry(
    text: str = "hello",
    detector_id: str = "d1",
    detector_version: str = "v1",
    result: dict | None = None,
    expires_at: str = FUTURE,
    created_at: str = CREATED,
    size_bytes: int = 0,
    metadata: dict | None = None,
) -> CacheEntry:
    return CacheEntry(
        content_hash=_hash(text),
        detector_id=detector_id,
        detector_version=detector_version,
        result=result if result is not None else {"r": 1},
        created_at=created_at,
        expires_at=expires_at,
        size_bytes=size_bytes,
        metadata=metadata or {},
    )


def _insert(cache: DetectionCache, entry: CacheEntry) -> str:
    """Insert *entry* directly, keeping index and totals consistent."""
    key = cache._generate_key(entry.content_hash, entry.detector_id, entry.detector_version)
    cache._cache[key] = entry
    cache._detector_index[entry.detector_id].add(key)
    cache.stats.total_entries += 1
    cache.stats.total_size_bytes += entry.size_bytes
    return key


def _put(
    cache: DetectionCache,
    text: str = "hello",
    detector_id: str = "d1",
    detector_version: str = "v1",
    result: dict | None = None,
    ttl_seconds: float | None = None,
    metadata: dict | None = None,
) -> bool:
    return asyncio.run(
        cache.put(
            text,
            detector_id,
            detector_version,
            result if result is not None else {"r": 1},
            ttl_seconds=ttl_seconds,
            metadata=metadata,
        )
    )


def _entry_dict(
    text: str = "hello",
    detector_id: str = "d1",
    detector_version: str = "v1",
    result: dict | None = None,
    expires_at: str = FUTURE,
    created_at: str = CREATED,
    size_bytes: int = 0,
    metadata: dict | None = None,
    **overrides,
) -> dict:
    entry = {
        "content_hash": _hash(text),
        "detector_id": detector_id,
        "detector_version": detector_version,
        "result": result if result is not None else {"r": 1},
        "created_at": created_at,
        "expires_at": expires_at,
        "access_count": 0,
        "last_accessed": "",
        "size_bytes": size_bytes,
        "metadata": metadata or {},
    }
    entry.update(overrides)
    return entry


def _write_cache_file(path: Path, entries: list[dict], version: int = 1) -> Path:
    data = {
        "version": version,
        "entries": entries,
        "model_versions": {},
        "config_hashes": {},
    }
    path.write_bytes(json.dumps(data).encode("utf-8"))
    return path


class _FixedDateTime(datetime):
    """datetime stub whose now() is pinned; fromisoformat is inherited."""

    _fixed: datetime | None = None

    @classmethod
    def now(cls, tz=None):  # noqa: D102 - test stub
        assert cls._fixed is not None
        return cls._fixed


@pytest.fixture
def fixed_now(monkeypatch):
    fixed = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    _FixedDateTime._fixed = fixed
    monkeypatch.setattr(dc, "datetime", _FixedDateTime)
    return fixed


class TestParseTime:
    def test_non_string_and_unparseable_return_none(self):
        # (95,34) Or->And: 123 reaches value.replace -> AttributeError.
        assert _parse_time(123) is None
        # (99,11) ExceptionReplacer: the ValueError must be swallowed.
        assert _parse_time("not-a-date") is None
        assert _parse_time("2026-01-01T00:00:00") is None  # naive
        assert _parse_time("2026-01-01T00:00:00+00:00") is not None


class TestCachePolicy:
    def test_ttl_boundaries(self):
        # Boundary guard for the ttl validation. (The ttl LtE->Eq /
        # NumberReplacer mutants at line 145 were killed by the existing
        # suite in phase 1; no W4 survivor lives here.)
        with pytest.raises(ValueError):
            CachePolicy(ttl_seconds=-0.5)
        assert CachePolicy(ttl_seconds=0.5).ttl_seconds == 0.5
        with pytest.raises(ValueError):
            CachePolicy(ttl_seconds=0.0)

    def test_max_entries_boundaries(self):
        # (147,28) LtE->Eq: -1 must raise; (147,31) NumberReplacer 22:
        # 1 must construct (mutant <= 1 raises).
        with pytest.raises(ValueError):
            CachePolicy(max_entries=-1)
        assert CachePolicy(max_entries=1).max_entries == 1

    def test_max_size_bytes_boundaries(self):
        # (149,31) LtE->Eq: -1 must raise; (149,34) NumberReplacer 24:
        # 1 must construct (mutant <= 1 raises).
        with pytest.raises(ValueError):
            CachePolicy(max_size_bytes=-1)
        assert CachePolicy(max_size_bytes=1).max_size_bytes == 1

    def test_check_interval_boundaries(self):
        # (151,58) Or->And: inf must raise (mutant needs both arms true).
        with pytest.raises(ValueError):
            CachePolicy(check_interval_seconds=float("inf"))
        # (151,89) LtE->Eq: -0.5 must raise; LtE->Lt: 0 must raise.
        with pytest.raises(ValueError):
            CachePolicy(check_interval_seconds=-0.5)
        with pytest.raises(ValueError):
            CachePolicy(check_interval_seconds=0.0)
        # (151,92) NumberReplacer 27: 0.5 must construct (mutant <= 1).
        assert CachePolicy(check_interval_seconds=0.5).check_interval_seconds == 0.5

    def test_compress_threshold_boundaries(self):
        # (153,41) Lt->Eq: -1 must raise; Lt->LtE: 0 must construct.
        with pytest.raises(ValueError):
            CachePolicy(compress_threshold_bytes=-1)
        assert CachePolicy(compress_threshold_bytes=0).compress_threshold_bytes == 0
        # (153,43) NumberReplacer 28/29: 0 constructs, -1 raises.
        assert CachePolicy(compress_threshold_bytes=0).compress_threshold_bytes == 0


class TestFromDict:
    def test_defaults_are_zero(self):
        # (213,50) NumberReplacer 36/37 and (215,46) NumberReplacer 38/39:
        # omitted access_count/size_bytes default to 0, not 1 or -1.
        entry = CacheEntry.from_dict(
            {
                "content_hash": "a" * 64,
                "detector_id": "d1",
                "detector_version": "v1",
                "result": {"r": 1},
                "created_at": CREATED,
                "expires_at": FUTURE,
            }
        )
        assert entry.access_count == 0
        assert entry.size_bytes == 0


class TestIsExpired:
    def test_unparseable_expiry_is_expired(self):
        # (227,19) ReplaceTrueWithFalse: unparseable expiry must be expired.
        assert _entry(expires_at="not-a-date").is_expired() is True
        assert _entry(expires_at=FUTURE).is_expired() is False

    def test_exact_now_expiry_is_expired(self, fixed_now):
        # (228,33) GtE->Gt: expiry exactly now is expired (>=, not >).
        assert _entry(expires_at=fixed_now.isoformat()).is_expired() is True


class TestValidateEntryDict:
    def test_missing_key_and_empty_field(self):
        base = _entry_dict()
        # (287,15) ZeroIterationForLoop: a missing key must raise
        # ValueError, not fall through to a KeyError on data["result"].
        missing = dict(base)
        del missing["result"]
        with pytest.raises(ValueError, match="missing 'result'"):
            _validate_entry_dict(missing)
        # (297,15) ZeroIterationForLoop: an empty content_hash must raise.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(content_hash=""))
        # (298,42) Or->And: a non-string content_hash must raise
        # (mutant requires both arms true, so 123 slips through).
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(content_hash=123))

    def test_access_count_rules(self):
        # (305,44) NumberReplacer 63: the default applies only when the
        # key is ABSENT; the -1 default fails validation, so the call
        # raises. (The +1 twin, occ 62, is EQUIVALENT and unobservable:
        # _validate_entry_dict validates a local copy, but
        # CacheEntry.from_dict re-reads data.get("access_count", 0) from
        # the raw dict, so a default of 1 never reaches the entry.)
        no_count = _entry_dict()
        del no_count["access_count"]
        assert _validate_entry_dict(no_count).access_count == 0
        # (306,38) Or->And: a bool access_count must raise.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(access_count=True))
        # (306,75) Or->And: a float access_count must raise.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(access_count=1.5))
        # (306,91) Lt->Gt: -1 must raise; Lt->NotEq: 5 must validate.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(access_count=-1))
        assert _validate_entry_dict(_entry_dict(access_count=5)).access_count == 5
        # (306,93) NumberReplacer 65: 0 must validate (mutant < 1 raises).
        assert _validate_entry_dict(_entry_dict(access_count=0)).access_count == 0

    def test_size_bytes_rules(self):
        # (311,7) AddNot: a present but bad size_bytes must be validated.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(size_bytes="bad"))
        # (313,34) Or->And: a bool size must raise.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(size_bytes=True))
        # (313,63) Or->And: a float size must raise.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(size_bytes=1.5))
        # (313,71) Lt->Eq: -1 must raise; Lt->LtE: 0 must validate.
        with pytest.raises(ValueError):
            _validate_entry_dict(_entry_dict(size_bytes=-1))
        assert _validate_entry_dict(_entry_dict(size_bytes=0)).size_bytes == 0
        # (313,73) NumberReplacer 66/67: 0 validates, -1 raises.
        assert _validate_entry_dict(_entry_dict(size_bytes=0)).size_bytes == 0


class TestValidateStrMap:
    def test_non_string_key_or_value_raises(self):
        # (325,22) ZeroIterationForLoop and (326,36) Or->And: a non-str
        # key must raise (both mutants let {1: "x"} through).
        with pytest.raises(ValueError):
            _validate_str_map({1: "x"}, "model_versions")
        with pytest.raises(ValueError):
            _validate_str_map({"a": 1}, "model_versions")
        assert _validate_str_map({"a": "b"}, "model_versions") == {"a": "b"}


class TestLifecycle:
    def test_start_creates_cleanup_task(self):
        # (374,24) ReplaceFalseWithTrue: _running must start False so
        # start() actually creates the background task.
        cache = DetectionCache()
        assert cache._running is False
        asyncio.run(cache.start())
        try:
            assert cache._cleanup_task is not None
        finally:
            asyncio.run(cache.stop())

    def test_stop_clears_running(self):
        # (462,24) ReplaceFalseWithTrue: stop() must clear _running.
        cache = DetectionCache()
        asyncio.run(cache.start())
        asyncio.run(cache.stop())
        assert cache._running is False

    def test_resident_size_metadata_unicode(self):
        # (437,69) ReplaceFalseWithTrue: metadata JSON is UTF-8, not
        # ASCII-escaped: {"k":"café"} is 13 bytes, so resident is 15.
        cache = DetectionCache()
        assert cache._resident_size({}, {"k": "café"}) == 15

    def test_max_persisted_bytes(self):
        # (446,*) the whole family: the second term dominates, but only
        # for S >= 512; at S=1 the +1 first-term mutants win the max,
        # and at S=600000 the BitOr/BitXor second-term mutants differ.
        small = DetectionCache(policy=CachePolicy(max_size_bytes=1))
        assert small._max_persisted_bytes() == 2 * 1 + 1024 * 1024
        big = DetectionCache(policy=CachePolicy(max_size_bytes=600000))
        assert big._max_persisted_bytes() == 2 * 600000 + 1024 * 1024


class TestCleanupExpired:
    def test_expired_entry_removed(self):
        # (488,30) ZeroIterationForLoop: the scan must run;
        # (493,23) ZeroIterationForLoop: the removal loop must run.
        cache = DetectionCache()
        key = _insert(cache, _entry(expires_at=PAST, size_bytes=10))
        assert cache._cleanup_expired() == 1
        assert key not in cache._cache

    def test_unparseable_expiry_removed(self):
        # (490,19) AddNot, (490,30) Is->IsNot, (490,38) Or->And: an
        # unparseable expiry is expired; every mutant raises TypeError
        # (None <= now) or returns 0 instead of 1.
        cache = DetectionCache()
        _insert(cache, _entry(expires_at="not-a-date", size_bytes=10))
        assert cache._cleanup_expired() == 1

    def test_expiry_boundaries(self, fixed_now):
        # (490,52) LtE family: past is expired (Eq/Gt/GtE/Is),
        # future is not (IsNot/NotEq), exact now is expired (Lt/NotEq/Is).
        cache = DetectionCache()
        _insert(cache, _entry(text="past", expires_at=PAST, size_bytes=10))
        assert cache._cleanup_expired() == 1
        cache = DetectionCache()
        _insert(cache, _entry(text="future", expires_at=FUTURE, size_bytes=10))
        assert cache._cleanup_expired() == 0
        cache = DetectionCache()
        _insert(
            cache,
            _entry(text="exact", expires_at=fixed_now.isoformat(), size_bytes=10),
        )
        assert cache._cleanup_expired() == 1


class TestEvictDropRemove:
    def test_evict_lru_empty_and_present(self):
        # (502,23) ReplaceFalseWithTrue: empty cache evicts nothing.
        cache = DetectionCache()
        assert cache._evict_lru() is False
        # (507,19) ReplaceTrueWithFalse: a present entry evicts True.
        _insert(cache, _entry(size_bytes=10))
        assert cache._evict_lru() is True

    def test_drop_entry_missing(self):
        # (517,23) ReplaceFalseWithTrue: a missing key drops False.
        assert DetectionCache()._drop_entry("missing") is False

    def test_remove_entry_missing(self):
        # (530,23) ReplaceFalseWithTrue: a missing key removes False.
        cache = DetectionCache()
        assert cache._remove_entry("missing", InvalidationReason.MANUAL) is False

    def test_remove_entry_reason_counters(self):
        # (532,22) Eq->GtE: MANUAL must not count as an eviction;
        # Eq->LtE: CONFIG_CHANGED must not count as an eviction.
        # (534,24) Eq->Gt/IsNot/NotEq: TTL_EXPIRED must count expired;
        # Eq->Lt/LtE: MANUAL must not count expired.
        # (533,40) NumberReplacer 82, (535,46) 84/85, (537,44) 86/87:
        # each counter increments by exactly 1.
        cache = DetectionCache()
        key = _insert(cache, _entry(text="one", size_bytes=10))
        assert cache._remove_entry(key, InvalidationReason.MANUAL) is True
        assert cache.stats.invalidations == 1
        assert cache.stats.evictions == 0
        assert cache.stats.expired_entries == 0
        key = _insert(cache, _entry(text="two", size_bytes=10))
        assert cache._remove_entry(key, InvalidationReason.CONFIG_CHANGED) is True
        assert cache.stats.invalidations == 2
        assert cache.stats.evictions == 0
        key = _insert(cache, _entry(text="three", size_bytes=10))
        assert cache._remove_entry(key, InvalidationReason.TTL_EXPIRED) is True
        assert cache.stats.expired_entries == 1
        assert cache.stats.invalidations == 2
        key = _insert(cache, _entry(text="four", size_bytes=10))
        assert cache._remove_entry(key, InvalidationReason.EVICTION) is True
        assert cache.stats.evictions == 1
        key = _insert(cache, _entry(text="five", size_bytes=10))
        assert cache._remove_entry(key, InvalidationReason.TTL_EXPIRED) is True
        assert cache.stats.expired_entries == 2
        key = _insert(cache, _entry(text="six", size_bytes=10))
        assert cache._remove_entry(key, InvalidationReason.MANUAL) is True
        assert cache.stats.invalidations == 3


class TestEnsureCapacity:
    def _overfull_cache(self) -> DetectionCache:
        cache = DetectionCache(policy=CachePolicy(max_entries=2, max_size_bytes=1000))
        for text in ("a", "b", "c"):
            _insert(cache, _entry(text=text, size_bytes=10))
        return cache

    def test_overfull_entries_evicted_to_one(self):
        # (548,35) GtE->Eq/Is: an over-full cache (3 > max 2) must evict;
        # (549,19) AddNot/Delete_Not: the loop must not stop after one.
        cache = self._overfull_cache()
        cache._ensure_capacity(0)
        assert len(cache._cache) == 1

    def test_size_loop_evicts_enough(self):
        # (551,46) Add->Mul: 100 + 60 > 150 evicts A only; the Mul
        # mutant evicts B as well (40 * 60 > 150).
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=150))
        assert _put(cache, text="a", result={"x": "a" * 50}) is True  # resident 60
        assert _put(cache, text="b", result={"x": "a" * 30}) is True  # resident 40
        cache._ensure_capacity(60)
        assert len(cache._cache) == 1
        assert cache._generate_key(_hash("b"), "d1", "v1") in cache._cache

    def test_size_loop_exact_budget_no_eviction(self):
        # (551,62) Gt->GtE: total + incoming == max does not evict.
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=150))
        assert _put(cache, text="a", result={"x": "a" * 50}) is True
        assert _put(cache, text="b", result={"x": "a" * 30}) is True
        cache._ensure_capacity(50)
        assert len(cache._cache) == 2

    def test_size_loop_evicts_all_when_needed(self):
        # (552,19) AddNot/Delete_Not: the loop must evict B as well as A
        # (40 + 120 > 150); the mutants break after the first eviction.
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=150))
        assert _put(cache, text="a", result={"x": "a" * 50}) is True
        assert _put(cache, text="b", result={"x": "a" * 30}) is True
        cache._ensure_capacity(120)
        assert len(cache._cache) == 0

    def test_empty_oversized_returns(self):
        # (553,20) Break->Continue: an empty cache with an oversized
        # incoming entry must return (the mutant loops forever). The
        # call runs in a daemon thread so a hang fails fast, not forever.
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=100))
        done: list[bool] = []
        thread = threading.Thread(
            target=lambda: (cache._ensure_capacity(101), done.append(True)),
            daemon=True,
        )
        thread.start()
        thread.join(timeout=2.0)
        assert done == [True]
        assert len(cache._cache) == 0


class TestCheckConfigMaxAge:
    def test_config_check_disabled(self):
        # (563,19) ReplaceTrueWithFalse: a disabled config check passes.
        cache = DetectionCache(
            invalidation_policy=InvalidationPolicy(invalidate_on_config_change=False)
        )
        assert cache._check_config(_entry(), "d1") is True

    def test_max_age_unparseable_and_exact(self, fixed_now):
        # (576,19) ReplaceFalseWithTrue: an unparseable created_at fails.
        cache = DetectionCache(invalidation_policy=InvalidationPolicy(max_age_seconds=60.0))
        assert cache._check_max_age(_entry(created_at="not-a-date")) is False
        # (577,64) LtE->Lt: age exactly max_age is within budget.
        exact = fixed_now.timestamp() - 60.0
        created = datetime.fromtimestamp(exact, UTC).isoformat()
        assert cache._check_max_age(_entry(created_at=created)) is True


class TestGet:
    def test_version_mismatch_invalidates(self):
        # (603,55) NotEq->Gt: current "1" vs entry "2" invalidates.
        # (605,41) NumberReplacer 90/91: misses increments by exactly 1.
        cache = DetectionCache()
        assert _put(cache, detector_version="2") is True
        cache.set_model_version("d1", "1")
        result, status = cache.get("hello", "d1", "2")
        assert result is None
        assert status is CacheEntryStatus.INVALIDATED
        assert cache.stats.misses == 1

    def test_config_mismatch_miss_counter(self):
        # (611,37) NumberReplacer 92/93: misses increments by exactly 1.
        cache = DetectionCache()
        assert _put(cache) is True
        cache.set_config_hash("d1", "cfg1")
        result, status = cache.get("hello", "d1", "v1")
        assert result is None
        assert status is CacheEntryStatus.INVALIDATED
        assert cache.stats.misses == 1

    def test_expired_miss_counter(self):
        # (617,37) NumberReplacer 94/95: misses increments by exactly 1.
        cache = DetectionCache()
        _insert(cache, _entry(expires_at=PAST, size_bytes=10))
        result, status = cache.get("hello", "d1", "v1")
        assert result is None
        assert status is CacheEntryStatus.EXPIRED
        assert cache.stats.misses == 1

    def test_max_age_miss_counter(self):
        # (623,37) NumberReplacer 96/97: misses increments by exactly 1.
        cache = DetectionCache(invalidation_policy=InvalidationPolicy(max_age_seconds=60.0))
        _insert(cache, _entry(created_at="2000-01-01T00:00:00+00:00", size_bytes=10))
        result, status = cache.get("hello", "d1", "v1")
        assert result is None
        assert status is CacheEntryStatus.INVALIDATED
        assert cache.stats.misses == 1

    def test_custom_invalidator_raises_and_true(self):
        # (634,23) ExceptionReplacer: a raising invalidator invalidates
        # instead of propagating; (635,30) ReplaceTrueWithFalse: the
        # except path sets invalid True; (638,41) NumberReplacer 98/99:
        # misses increments by exactly 1.
        def _raising(result, _meta):
            raise RuntimeError("boom")

        cache = DetectionCache(invalidation_policy=InvalidationPolicy(custom_invalidator=_raising))
        assert _put(cache) is True
        result, status = cache.get("hello", "d1", "v1")
        assert result is None
        assert status is CacheEntryStatus.INVALIDATED
        assert cache.stats.misses == 1


class TestPut:
    def test_small_ttl_accepted(self):
        # (671,62) NumberReplacer 102: ttl 0.5 is positive (mutant <= 1).
        cache = DetectionCache()
        assert _put(cache, ttl_seconds=0.5) is True


class TestInvalidate:
    def test_direct_branch_needs_all_three(self):
        # (730,15) AddNot and (730,44) And->Or: invalidate by detector
        # alone must use the detector loop (returns 1), not the direct
        # branch with None components (returns 0).
        cache = DetectionCache()
        assert _put(cache) is True
        assert cache.invalidate(detector_id="d1") == 1
        assert len(cache._cache) == 0

    def test_direct_branch_returns_one(self):
        # (735,23) NumberReplacer 108/109: a direct hit returns exactly 1.
        cache = DetectionCache()
        assert _put(cache) is True
        assert cache.invalidate("d1", "v1", _hash("hello")) == 1

    def test_direct_branch_miss_returns_zero(self):
        # (735,23) NumberReplacer 108/109: a direct MISS returns
        # exactly 0 (the mutants return 1 and -1 instead).
        cache = DetectionCache()
        assert _put(cache) is True
        assert cache.invalidate("d1", "v1", _hash("missing-text")) == 0

    def test_version_filter_ordering(self):
        # (745,75) Eq family: only the exact version matches.
        def _two_version_cache() -> DetectionCache:
            cache = DetectionCache()
            assert _put(cache, text="one", detector_version="v1") is True
            assert _put(cache, text="two", detector_version="v2") is True
            return cache

        # Gt/GtE: filter "v1" must not remove the "v2" entry.
        cache = _two_version_cache()
        assert cache.invalidate(detector_id="d1", detector_version="v1") == 1
        assert cache.get("two", "d1", "v2")[1] is CacheEntryStatus.FRESH
        # Lt/LtE: filter "v2" must not remove the "v1" entry.
        cache = _two_version_cache()
        assert cache.invalidate(detector_id="d1", detector_version="v2") == 1
        assert cache.get("one", "d1", "v1")[1] is CacheEntryStatus.FRESH
        # Is: an equal-but-distinct filter string still matches.
        cache = _two_version_cache()
        distinct = "".join(["v", "1"])
        stored = cache._cache[cache._generate_key(_hash("one"), "d1", "v1")].detector_version
        assert distinct == "v1" and distinct is not stored
        assert cache.invalidate(detector_id="d1", detector_version=distinct) == 1
        # IsNot: the identical filter object still matches.
        cache = _two_version_cache()
        same = cache._cache[cache._generate_key(_hash("one"), "d1", "v1")].detector_version
        assert cache.invalidate(detector_id="d1", detector_version=same) == 1
        # NotEq: the exact filter removes the entry.
        cache = _two_version_cache()
        assert cache.invalidate(detector_id="d1", detector_version="v1") == 1

    def test_version_filter_and(self):
        # (746,22) And->Or: a version mismatch must not remove the entry
        # even when the content-hash arm is open (None).
        cache = DetectionCache()
        assert _put(cache, text="one", detector_version="2") is True
        assert cache.invalidate(detector_id="d1", detector_version="1") == 0
        assert cache.get("one", "d1", "2")[1] is CacheEntryStatus.FRESH

    def test_content_hash_filter_ordering(self):
        # (746,70) Eq family: only the exact content hash matches.
        def _two_hash_cache() -> DetectionCache:
            cache = DetectionCache()
            assert _put(cache, text="alpha") is True
            assert _put(cache, text="beta") is True
            return cache

        # Gt/GtE: the minimum hash "0"*64 matches nothing.
        cache = _two_hash_cache()
        assert cache.invalidate(detector_id="d1", content_hash="0" * 64) == 0
        assert cache.get("alpha", "d1", "v1")[1] is CacheEntryStatus.FRESH
        # Lt/LtE: the maximum hash "f"*64 matches nothing.
        cache = _two_hash_cache()
        assert cache.invalidate(detector_id="d1", content_hash="f" * 64) == 0
        assert cache.get("alpha", "d1", "v1")[1] is CacheEntryStatus.FRESH
        # Is: an equal-but-distinct filter string still matches.
        cache = _two_hash_cache()
        stored = cache._cache[cache._generate_key(_hash("alpha"), "d1", "v1")].content_hash
        distinct = "".join([stored[i : i + 8] for i in range(0, 64, 8)])
        assert distinct == stored and distinct is not stored
        assert cache.invalidate(detector_id="d1", content_hash=distinct) == 1
        # IsNot: the identical filter object still matches.
        cache = _two_hash_cache()
        same = cache._cache[cache._generate_key(_hash("alpha"), "d1", "v1")].content_hash
        assert cache.invalidate(detector_id="d1", content_hash=same) == 1
        # NotEq: the exact filter removes the entry.
        cache = _two_hash_cache()
        assert cache.invalidate(detector_id="d1", content_hash=_hash("alpha")) == 1

    def test_content_hash_only_branch(self):
        # (751,42) Eq->GtE/IsNot/LtE and (751,58) And->Or: the
        # content-hash-only branch matches exactly one entry.
        cache = DetectionCache()
        assert _put(cache, text="alpha") is True
        assert cache.invalidate(content_hash="0" * 64) == 0
        assert cache.get("alpha", "d1", "v1")[1] is CacheEntryStatus.FRESH
        cache = DetectionCache()
        assert _put(cache, text="alpha") is True
        assert cache.invalidate(content_hash="f" * 64) == 0
        assert cache.get("alpha", "d1", "v1")[1] is CacheEntryStatus.FRESH
        cache = DetectionCache()
        assert _put(cache, text="alpha") is True
        same = cache._cache[cache._generate_key(_hash("alpha"), "d1", "v1")].content_hash
        assert cache.invalidate(content_hash=same) == 1

    def test_content_hash_branch_version_filter(self):
        # (752,75) Eq family: the version arm inside the content-hash
        # branch compares exactly.
        def _two_version_cache() -> DetectionCache:
            cache = DetectionCache()
            assert _put(cache, text="alpha", detector_version="v1") is True
            assert _put(cache, text="beta", detector_version="v2") is True
            return cache

        # Gt/GtE: filter "v1" must not remove the "v2" entry.
        cache = _two_version_cache()
        assert cache.invalidate(content_hash=_hash("beta"), detector_version="v1") == 0
        assert cache.get("beta", "d1", "v2")[1] is CacheEntryStatus.FRESH
        # Lt/LtE: filter "v2" must not remove the "v1" entry.
        cache = _two_version_cache()
        assert cache.invalidate(content_hash=_hash("alpha"), detector_version="v2") == 0
        assert cache.get("alpha", "d1", "v1")[1] is CacheEntryStatus.FRESH
        # Is: an equal-but-distinct filter string still matches.
        cache = _two_version_cache()
        distinct = "".join(["v", "1"])
        stored = cache._cache[cache._generate_key(_hash("alpha"), "d1", "v1")].detector_version
        assert distinct == "v1" and distinct is not stored
        assert cache.invalidate(content_hash=_hash("alpha"), detector_version=distinct) == 1
        # IsNot: the identical filter object still matches.
        cache = _two_version_cache()
        same = cache._cache[cache._generate_key(_hash("alpha"), "d1", "v1")].detector_version
        assert cache.invalidate(content_hash=_hash("alpha"), detector_version=same) == 1
        # NotEq: the exact filter removes the entry.
        cache = _two_version_cache()
        assert cache.invalidate(content_hash=_hash("alpha"), detector_version="v1") == 1


class TestInvalidateModelVersion:
    def test_empty_old_version_and_ordering(self):
        # (769,31) Or->And: an empty old version invalidates nothing.
        cache = DetectionCache()
        assert _put(cache) is True
        cache.set_model_version("d1", "")
        assert cache.invalidate_model_version("d1", "v2") == 0
        assert len(cache._cache) == 1
        # (769,46) Eq->Gt/GtE: old "2" vs new "1" invalidates.
        cache = DetectionCache()
        assert _put(cache, detector_version="2") is True
        cache.set_model_version("d1", "2")
        assert cache.invalidate_model_version("d1", "1") == 1
        # (769,46) Eq->Is: equal-but-distinct versions do not invalidate.
        cache = DetectionCache()
        assert _put(cache) is True
        cache.set_model_version("d1", "v1")
        distinct = "".join(["v", "1"])
        stored = cache._model_versions["d1"]
        assert distinct == "v1" and distinct is not stored
        assert cache.invalidate_model_version("d1", distinct) == 0
        assert cache.get("hello", "d1", "v1")[1] is CacheEntryStatus.FRESH


class TestGetEntryStatus:
    def test_missing_and_fresh(self):
        # Contract guard for get_entry_status. (The MISSING-check AddNot
        # at [821,15] occ 65 was killed by the existing suite in phase 1;
        # the surviving [830,15] AddNot occ 67 negates the
        # model-version-change flag and is killed by test_version_ordering.)
        cache = DetectionCache()
        assert cache.get_entry_status("hello", "d1", "v1") is CacheEntryStatus.MISSING
        assert _put(cache) is True
        assert cache.get_entry_status("hello", "d1", "v1") is CacheEntryStatus.FRESH

    def test_version_ordering(self):
        # (832,55) NotEq family: the version comparison is exact.
        # Eq: the same version is fresh.
        cache = DetectionCache()
        assert _put(cache) is True
        cache.set_model_version("d1", "v1")
        assert cache.get_entry_status("hello", "d1", "v1") is CacheEntryStatus.FRESH
        # Gt/GtE: current "1" vs entry "2" is invalidated.
        cache = DetectionCache()
        assert _put(cache, detector_version="2") is True
        cache.set_model_version("d1", "1")
        assert cache.get_entry_status("hello", "d1", "2") is CacheEntryStatus.INVALIDATED
        # Lt/LtE: current "2" vs entry "1" is invalidated.
        cache = DetectionCache()
        assert _put(cache, detector_version="1") is True
        cache.set_model_version("d1", "2")
        assert cache.get_entry_status("hello", "d1", "1") is CacheEntryStatus.INVALIDATED
        # Is: the identical version object is fresh.
        cache = DetectionCache()
        version = "v1"
        assert _put(cache, detector_version=version) is True
        cache.set_model_version("d1", version)
        assert cache.get_entry_status("hello", "d1", "v1") is CacheEntryStatus.FRESH
        # IsNot: an equal-but-distinct version object is fresh.
        cache = DetectionCache()
        assert _put(cache) is True
        distinct = "".join(["v", "1"])
        stored = cache._cache[cache._generate_key(_hash("hello"), "d1", "v1")].detector_version
        assert distinct == "v1" and distinct is not stored
        cache.set_model_version("d1", distinct)
        assert cache.get_entry_status("hello", "d1", "v1") is CacheEntryStatus.FRESH


class TestSaveToDisk:
    def test_save_version_and_unicode(self, tmp_path):
        # (880,42) NumberReplacer 122/123: the saved version is 1.
        # (880,58) ReplaceFalseWithTrue: the payload is UTF-8, not
        # ASCII-escaped (café stays two bytes, not \\u00e9).
        path = tmp_path / "cache.json"
        cache = DetectionCache(storage_path=path)
        assert _put(cache, result={"k": "café"}) is True
        assert cache.save() is True
        raw = path.read_bytes()
        assert json.loads(raw)["version"] == 1
        # (880,42) NumberReplacer 122/123: the payload uses indent=2,
        # not 3 or 1 (the parsed version alone cannot tell them apart).
        assert raw.startswith(b'{\n  "version": 1,')
        assert "café".encode() in raw
        assert b"\\u00e9" not in raw

    def test_save_creates_parent_dirs(self, tmp_path):
        # (884,51) ReplaceTrueWithFalse: mkdir must create parents.
        path = tmp_path / "a" / "b" / "cache.json"
        cache = DetectionCache(storage_path=path)
        assert _put(cache) is True
        assert cache.save() is True
        assert path.exists()

    def test_save_close_error_still_succeeds(self, tmp_path, monkeypatch):
        # (908,19) ExceptionReplacer: an OSError from os.close(dir_fd)
        # is swallowed (best-effort directory fsync), so save succeeds.
        path = tmp_path / "cache.json"
        cache = DetectionCache(storage_path=path)
        assert _put(cache) is True

        def _raise(*args, **kwargs):
            raise OSError("boom")

        monkeypatch.setattr(os, "close", _raise)
        assert cache.save() is True


class TestLoadFromDisk:
    def test_load_no_path_and_directory(self, tmp_path):
        # (928,33) Or->And: no storage_path loads False (the mutant
        # dereferences None); (929,19) ReplaceFalseWithTrue: same.
        assert DetectionCache(storage_path=None).load() is False
        # (933,15) ExceptionReplacer and (935,19) ReplaceFalseWithTrue:
        # a directory is not a readable cache file.
        assert DetectionCache(storage_path=tmp_path).load() is False

    def test_load_file_size_budget(self, tmp_path):
        # (938,24) Gt->Eq/GtE: a file exactly at the budget loads;
        # Gt->Is: an over-budget file does not load (the mutant's `is`
        # never matches a fresh 1048776 int, so it loads everything).
        cache = DetectionCache(
            policy=CachePolicy(max_size_bytes=100), storage_path=tmp_path / "c.json"
        )
        budget = cache._max_persisted_bytes()
        assert budget == 2 * 100 + 1024 * 1024
        raw = json.dumps({"version": 1, "entries": []}).encode("utf-8")
        exact = raw + b" " * (budget - len(raw))
        assert len(exact) == budget
        (tmp_path / "c.json").write_bytes(exact)
        assert cache.load() is True
        (tmp_path / "c.json").write_bytes(exact + b" " * 100)
        assert cache.load() is False

    def test_load_version_check(self, tmp_path):
        # (946,35) NotEq->Gt/Lt: version 0 and version 2 both reject.
        for version in (0, 2):
            path = tmp_path / f"v{version}.json"
            _write_cache_file(path, [], version=version)
            assert DetectionCache(storage_path=path).load() is False
        path = tmp_path / "v1.json"
        _write_cache_file(path, [], version=1)
        assert DetectionCache(storage_path=path).load() is True

    def test_load_skips_expired_entries(self, tmp_path):
        # (977,38) Or->And and (977,52) LtE->Eq/Is: a past-expiry entry
        # is skipped; (978,20) Continue->Break: the following valid
        # entry must still be admitted.
        path = tmp_path / "cache.json"
        _write_cache_file(
            path,
            [
                _entry_dict(text="expired", expires_at=PAST),
                _entry_dict(text="valid"),
            ],
        )
        cache = DetectionCache(storage_path=path)
        assert cache.load() is True
        assert cache.get("expired", "d1", "v1")[1] is CacheEntryStatus.MISSING
        assert cache.get("valid", "d1", "v1")[1] is CacheEntryStatus.FRESH

    def test_load_exact_now_expiry_skipped(self, tmp_path, fixed_now):
        # (977,52) LtE->Lt: expiry exactly now is skipped (<=, not <).
        path = tmp_path / "cache.json"
        _write_cache_file(path, [_entry_dict(text="exact", expires_at=fixed_now.isoformat())])
        cache = DetectionCache(storage_path=path)
        assert cache.load() is True
        assert cache.get("exact", "d1", "v1")[1] is CacheEntryStatus.MISSING

    def test_load_oversized_skipped_and_exact_size_admitted(self, tmp_path):
        # (981,20) Continue->Break: an oversized entry must not block
        # the following valid entry.
        path = tmp_path / "cache.json"
        _write_cache_file(
            path,
            [
                _entry_dict(text="big", result={"x": "a" * 200}),  # resident 210
                _entry_dict(text="valid"),
            ],
        )
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=100), storage_path=path)
        assert cache.load() is True
        assert cache.get("valid", "d1", "v1")[1] is CacheEntryStatus.FRESH
        # (980,28) Gt->GtE: an entry exactly at the budget is admitted.
        path = tmp_path / "exact.json"
        _write_cache_file(
            path,
            [_entry_dict(text="exact", result={"x": "a" * 90})],  # resident 100
        )
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=100), storage_path=path)
        assert cache.load() is True
        assert cache.get("exact", "d1", "v1")[1] is CacheEntryStatus.FRESH

    def test_load_max_entries_evicts_lru(self, tmp_path):
        # (999,37) GtE->Gt and (1000,23) AddNot/Delete_Not: three entries
        # under max_entries=2 leave exactly the last two.
        path = tmp_path / "cache.json"
        _write_cache_file(
            path,
            [
                _entry_dict(text="one"),
                _entry_dict(text="two"),
                _entry_dict(text="three"),
            ],
        )
        cache = DetectionCache(policy=CachePolicy(max_entries=2), storage_path=path)
        assert cache.load() is True
        assert len(cache._cache) == 2
        assert cache.get("one", "d1", "v1")[1] is CacheEntryStatus.MISSING
        assert cache.get("two", "d1", "v1")[1] is CacheEntryStatus.FRESH
        assert cache.get("three", "d1", "v1")[1] is CacheEntryStatus.FRESH

    def test_load_max_entries_is_identity(self, tmp_path):
        # (999,37) GtE->Is: `len(...) is max_entries` is False for 300
        # (above the small-int cache), so the mutant never evicts.
        path = tmp_path / "cache.json"
        entries = [_entry_dict(text=f"entry-{i}") for i in range(301)]
        _write_cache_file(path, entries)
        cache = DetectionCache(policy=CachePolicy(max_entries=300), storage_path=path)
        assert cache.load() is True
        assert len(cache._cache) == 300

    def test_load_size_loop_operators(self, tmp_path):
        # (1003,33) Add family: A(100) + B(60) over 150 evicts A only,
        # so the load ends with [B, C]; every operator mutant either
        # keeps A (BitAnd/BitOr/BitXor/Div/FloorDiv/Mod/RShift/Sub) or
        # evicts B as well (Mul).
        path = tmp_path / "cache.json"
        _write_cache_file(
            path,
            [
                _entry_dict(text="a", result={"x": "a" * 90}),  # resident 100
                _entry_dict(text="b", result={"x": "a" * 50}),  # resident 60
                _entry_dict(text="c", result={"x": "a" * 30}),  # resident 40
            ],
        )
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=150), storage_path=path)
        assert cache.load() is True
        assert cache.get("a", "d1", "v1")[1] is CacheEntryStatus.MISSING
        assert cache.get("b", "d1", "v1")[1] is CacheEntryStatus.FRESH
        assert cache.get("c", "d1", "v1")[1] is CacheEntryStatus.FRESH
        # (1003,44) Gt->Eq/GtE/Is: total + resident == max admits both
        # (150 is a cached small int, so even `is` matches here).
        path = tmp_path / "exact.json"
        _write_cache_file(
            path,
            [
                _entry_dict(text="a", result={"x": "a" * 90}),  # resident 100
                _entry_dict(text="b", result={"x": "a" * 40}),  # resident 50
            ],
        )
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=150), storage_path=path)
        assert cache.load() is True
        assert cache.get("a", "d1", "v1")[1] is CacheEntryStatus.FRESH
        assert cache.get("b", "d1", "v1")[1] is CacheEntryStatus.FRESH

    def test_load_size_loop_breaks(self, tmp_path):
        # (1004,23) AddNot/Delete_Not: admitting C(100) over 150 must
        # evict both A(60) and B(60); the mutants break after the first.
        path = tmp_path / "cache.json"
        _write_cache_file(
            path,
            [
                _entry_dict(text="a", result={"x": "a" * 50}),  # resident 60
                _entry_dict(text="b", result={"x": "a" * 50}),  # resident 60
                _entry_dict(text="c", result={"x": "a" * 90}),  # resident 100
            ],
        )
        cache = DetectionCache(policy=CachePolicy(max_size_bytes=150), storage_path=path)
        assert cache.load() is True
        assert len(cache._cache) == 1
        assert cache.get("c", "d1", "v1")[1] is CacheEntryStatus.FRESH

    def test_load_returns_true(self, tmp_path):
        # (1023,15) ReplaceTrueWithFalse: a valid load returns True.
        path = tmp_path / "cache.json"
        _write_cache_file(path, [_entry_dict()])
        assert DetectionCache(storage_path=path).load() is True
