"""W4 Worker D red regression tests: S11, S12, S13, S14, CORE-08.

Each test encodes the expected (fixed) behaviour from
docs/audits/2026-11-10/STATEFUL_RELIABILITY.md and CORE.md, not the
current output. They were written red against main c91672a and must
all pass after the fix. No real user text is used in fixtures.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from textforensics.datasets import (
    DatasetFetchError,
    NormalizedRow,
    get_spec,
    read_sample_cache,
    write_sample_cache,
)
from textforensics.detection_cache import (
    CacheEntryStatus,
    CachePolicy,
    DetectionCache,
    InvalidationPolicy,
)


def _resident(result: dict, metadata: dict | None = None) -> int:
    """Resident size as charged by the fixed cache: uncompressed JSON."""
    n = len(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    n += len(json.dumps(metadata or {}, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    return n


def _reconciled(cache: DetectionCache) -> None:
    """Assert cache contents, index and statistics agree exactly."""
    assert len(cache._cache) == cache.stats.total_entries
    assert sum(e.size_bytes for e in cache._cache.values()) == cache.stats.total_size_bytes
    assert cache.stats.total_size_bytes >= 0
    indexed: set[str] = set()
    for keys in cache._detector_index.values():
        indexed |= set(keys)
    assert indexed == set(cache._cache)
    for key, entry in cache._cache.items():
        assert (
            cache._generate_key(entry.content_hash, entry.detector_id, entry.detector_version)
            == key
        )
        assert entry.size_bytes == _resident(entry.result, entry.metadata)


# ============================================================ S11
class TestS11BudgetAndReplacement:
    @pytest.mark.asyncio
    async def test_oversized_single_entry_rejected(self):
        # Audit evidence cache_budget: a 20-byte cache retained a 75-byte entry.
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=20)
        )
        ok = await cache.put("t", "det", "1.0", {"data": "x" * 60})
        assert ok is False
        assert len(cache._cache) == 0
        assert cache.stats.total_entries == 0
        assert cache.stats.total_size_bytes == 0
        assert cache.get("t", "det", "1.0")[1] == CacheEntryStatus.MISSING

    @pytest.mark.asyncio
    async def test_exact_boundary_entry_admitted(self):
        result = {"v": 1}
        budget = _resident(result)
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=budget)
        )
        assert await cache.put("t", "det", "1.0", result) is True
        assert cache.get("t", "det", "1.0")[1] == CacheEntryStatus.FRESH
        _reconciled(cache)

    @pytest.mark.asyncio
    async def test_compressible_large_result_charged_resident(self):
        # Compressed bytes (~tens) must not stand in for resident size (~5 KB).
        big = {"data": "x" * 5000}
        assert _resident(big) > 5000
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=1000)
        )
        assert await cache.put("t", "det", "1.0", big) is False
        assert len(cache._cache) == 0
        roomy = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=6000)
        )
        assert await roomy.put("t", "det", "1.0", big) is True
        assert roomy.stats.total_size_bytes == _resident(big)
        _reconciled(roomy)

    @pytest.mark.asyncio
    async def test_replace_accounting_no_phantoms(self):
        # Audit evidence cache_replace_accounting: same key twice counted 2
        # entries; invalidating the sole real entry left a phantom entry.
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=100000)
        )
        await cache.put("t", "det", "1.0", {"v": 1})
        await cache.put("t", "det", "1.0", {"v": 22})
        assert cache.stats.total_entries == 1
        assert cache.stats.total_size_bytes == _resident({"v": 22})
        assert cache.get("t", "det", "1.0")[0] == {"v": 22}
        _reconciled(cache)
        assert cache.invalidate(detector_id="det") == 1
        assert cache.stats.total_entries == 0
        assert cache.stats.total_size_bytes == 0
        _reconciled(cache)

    @pytest.mark.asyncio
    async def test_repeated_replace_delete_reconciles(self):
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=100000)
        )
        for i in range(5):
            await cache.put("t", "det", "1.0", {"v": "x" * i})
            _reconciled(cache)
        assert cache.stats.total_entries == 1
        assert cache.invalidate(detector_id="det") == 1
        _reconciled(cache)

    @pytest.mark.asyncio
    async def test_replacement_at_capacity_evicts_lru(self):
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=2, max_size_bytes=100000)
        )
        await cache.put("a", "det", "1.0", {"v": 1})
        await cache.put("b", "det", "1.0", {"v": 2})
        # Replacing "a" must not evict "a" itself or double-count; adding
        # "c" afterwards must evict the LRU entry.
        await cache.put("a", "det", "1.0", {"v": 10})
        assert cache.stats.total_entries == 2
        _reconciled(cache)
        await cache.put("c", "det", "1.0", {"v": 3})
        assert cache.stats.total_entries == 2
        assert cache.get("b", "det", "1.0")[1] == CacheEntryStatus.MISSING
        assert cache.get("a", "det", "1.0")[1] == CacheEntryStatus.FRESH
        assert cache.get("c", "det", "1.0")[1] == CacheEntryStatus.FRESH
        _reconciled(cache)

    @pytest.mark.asyncio
    async def test_size_budget_never_exceeded(self):
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=100, max_size_bytes=1000)
        )
        for i in range(20):
            await cache.put(f"text{i}", "det", "1.0", {"data": "y" * 200})
            assert cache.stats.total_size_bytes <= 1000
            _reconciled(cache)

    def test_load_recomputes_sizes_and_enforces_budget(self):
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            now = datetime.now(UTC)
            good = {
                "content_hash": "a" * 64,
                "detector_id": "det",
                "detector_version": "1.0",
                "result": {"v": 1},
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
                "access_count": 0,
                "last_accessed": "",
                "size_bytes": 999999,  # stored size is a lie; must be recomputed
                "metadata": {},
            }
            oversized = dict(good, content_hash="b" * 64, result={"data": "x" * 5000})
            storage.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "entries": [good, oversized],
                        "model_versions": {},
                        "config_hashes": {},
                    }
                ),
                encoding="utf-8",
            )
            cache = DetectionCache(
                policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=1000),
                storage_path=storage,
            )
            # Oversized entry dropped; good entry kept with recomputed size.
            assert cache.stats.total_entries == 1
            assert cache.stats.total_size_bytes == _resident({"v": 1})
            (only,) = cache._cache.values()
            assert only.content_hash == "a" * 64
            _reconciled(cache)


# ============================================================ S12
class TestS12FailClosedAndImmutable:
    @pytest.mark.asyncio
    async def test_missing_config_hash_invalidated_when_current_set(self):
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))
        cache.set_config_hash("det1", "current")
        await cache.put("text", "det1", "1.0", {"score": 0.5}, metadata={})
        result, status = cache.get("text", "det1", "1.0")
        assert result is None
        assert status == CacheEntryStatus.INVALIDATED

    @pytest.mark.asyncio
    async def test_matching_config_hash_stays_fresh(self):
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))
        cache.set_config_hash("det1", "current")
        await cache.put("text", "det1", "1.0", {"score": 0.5}, metadata={"config_hash": "current"})
        assert cache.get("text", "det1", "1.0")[1] == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_max_age_enforced(self):
        # max_age 0.001 s is never consulted on main: a 0.01 s old entry is fresh.
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600),
            invalidation_policy=InvalidationPolicy(max_age_seconds=0.001),
        )
        await cache.put("text", "det1", "1.0", {"score": 0.5})
        time.sleep(0.01)
        result, status = cache.get("text", "det1", "1.0")
        assert result is None
        assert status == CacheEntryStatus.INVALIDATED

    @pytest.mark.asyncio
    async def test_max_age_longer_than_age_stays_fresh(self):
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600),
            invalidation_policy=InvalidationPolicy(max_age_seconds=3600.0),
        )
        await cache.put("text", "det1", "1.0", {"score": 0.5})
        assert cache.get("text", "det1", "1.0")[1] == CacheEntryStatus.FRESH

    def test_invalid_max_age_policy_rejected(self):
        for bad in (0, -1.0, float("nan"), float("inf")):
            with pytest.raises(ValueError):
                InvalidationPolicy(max_age_seconds=bad)

    @pytest.mark.asyncio
    async def test_invalid_ttl_overrides_rejected(self):
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))
        for bad in (0, -5.0, float("nan"), float("inf")):
            with pytest.raises(ValueError):
                await cache.put("text", "det", "1.0", {"score": 0.5}, ttl_seconds=bad)
        assert len(cache._cache) == 0

    @pytest.mark.asyncio
    async def test_mutating_put_argument_does_not_change_cached(self):
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))
        result = {"v": 1, "nested": {"n": 1}}
        await cache.put("text", "det", "1.0", result, metadata={"m": [1]})
        result["v"] = 99
        result["nested"]["n"] = 99
        got, status = cache.get("text", "det", "1.0")
        assert status == CacheEntryStatus.FRESH
        assert got == {"v": 1, "nested": {"n": 1}}

    @pytest.mark.asyncio
    async def test_mutating_get_result_does_not_change_cached(self):
        # Audit evidence cache_mutable_result: changing a returned result to
        # v=99 changed the next cache hit without recomputation.
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))
        await cache.put("text", "det", "1.0", {"v": 1, "nested": {"n": 1}})
        got, _ = cache.get("text", "det", "1.0")
        got["v"] = 99
        got["nested"]["n"] = 99
        got2, status = cache.get("text", "det", "1.0")
        assert status == CacheEntryStatus.FRESH
        assert got2 == {"v": 1, "nested": {"n": 1}}
        # get_all_entries must not hand out mutable internals either.
        entries = cache.get_all_entries()
        entries[0].result["v"] = 99
        assert cache.get("text", "det", "1.0")[0] == {"v": 1, "nested": {"n": 1}}

    @pytest.mark.asyncio
    async def test_get_entry_status_applies_fail_closed_config(self):
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))
        cache.set_config_hash("det1", "current")
        await cache.put("text", "det1", "1.0", {"score": 0.5}, metadata={})
        assert cache.get_entry_status("text", "det1", "1.0") == CacheEntryStatus.INVALIDATED
        assert cache.stats.hits == 0 and cache.stats.misses == 0


# ============================================================ S13
class TestS13ThreadSafety:
    def test_read_clear_race_no_resurrection(self):
        # Audit evidence cache_read_clear_race: a get paused inside the
        # custom invalidator, a concurrent clear, then resume -> the entry
        # was reinserted with stats entries 0. After the fix the final
        # state must be coherent: empty cache, empty index, zero stats.
        entered = threading.Event()
        release = threading.Event()
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))

        def invalidator(result, _):
            entered.set()
            assert release.wait(timeout=5)
            return False

        cache.invalidation_policy = InvalidationPolicy(custom_invalidator=invalidator)
        import asyncio

        asyncio.run(cache.put("text", "det", "1.0", {"v": 1}))
        outcomes: dict[str, object] = {}

        def do_get():
            outcomes["get"] = cache.get("text", "det", "1.0")

        t = threading.Thread(target=do_get)
        t.start()
        assert entered.wait(timeout=5)
        # The clear runs on its own thread: it must wait for the paused
        # read's locked transaction, then remove the entry — never let the
        # resumed read reinsert it outside the index/statistics.
        clear_thread = threading.Thread(target=cache.clear)
        clear_thread.start()
        time.sleep(0.2)
        assert clear_thread.is_alive()  # blocked behind the read's lock
        release.set()
        t.join(timeout=5)
        clear_thread.join(timeout=5)
        assert not t.is_alive()
        assert not clear_thread.is_alive()
        assert len(cache._cache) == 0
        assert cache.stats.total_entries == 0
        assert cache.stats.total_size_bytes == 0
        assert dict(cache._detector_index) == {}
        assert cache.get("text", "det", "1.0")[1] == CacheEntryStatus.MISSING
        _reconciled(cache)

    def test_concurrent_mixed_ops_stay_reconciled(self):
        cache = DetectionCache(
            policy=CachePolicy(ttl_seconds=3600, max_entries=20, max_size_bytes=100000)
        )
        errors: list[BaseException] = []

        def worker(n: int):
            try:
                import asyncio

                for i in range(30):
                    asyncio.run(cache.put(f"t{n}-{i}", "det", "1.0", {"v": i}))
                    cache.get(f"t{n}-{i}", "det", "1.0")
                    if i % 5 == 0:
                        cache.invalidate(detector_id="det")
                    if i % 7 == 0:
                        cache.clear()
            except BaseException as exc:  # noqa: BLE001 - collected for the test
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive()
        assert errors == []
        _reconciled(cache)

    def test_get_stats_returns_copy(self):
        cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600))
        stats = cache.get_stats()
        stats.total_entries = 999
        stats.hits = 999
        assert cache.stats.total_entries == 0
        assert cache.stats.hits == 0


# ============================================================ S14
class TestS14PersistenceLifecycle:
    @pytest.mark.asyncio
    async def test_stop_persists(self):
        # Audit evidence cache_lifecycle_not_persisted: after put + stop the
        # configured storage_path did not exist.
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            await cache.put("text1", "det1", "1.0", {"score": 0.5})
            await cache.stop()
            assert storage.exists()
            cache2 = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            assert cache2.get("text1", "det1", "1.0")[1] == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_context_manager_exit_persists(self):
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            async with DetectionCache(
                policy=CachePolicy(ttl_seconds=3600), storage_path=storage
            ) as cache:
                await cache.put("text1", "det1", "1.0", {"score": 0.5})
            assert storage.exists()
            cache2 = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            assert cache2.get("text1", "det1", "1.0")[1] == CacheEntryStatus.FRESH

    @pytest.mark.asyncio
    async def test_malformed_load_preserves_prior_state(self):
        # Audit evidence cache_partial_load: a bad entry was installed and a
        # later get raised ValueError instead of a graceful miss.
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            await cache.put("good", "det", "1.0", {"v": 1})
            now = datetime.now(UTC)
            bad = {
                "content_hash": "b" * 64,
                "detector_id": "det",
                "detector_version": "1.0",
                "result": {"v": 2},
                "created_at": now.isoformat(),
                "expires_at": "not-a-date",  # invalid expiry, last entry
                "access_count": 0,
                "last_accessed": "",
                "size_bytes": 10,
                "metadata": {},
            }
            good_disk = {
                "content_hash": "c" * 64,
                "detector_id": "det",
                "detector_version": "1.0",
                "result": {"v": 3},
                "created_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=1)).isoformat(),
                "access_count": 0,
                "last_accessed": "",
                "size_bytes": 10,
                "metadata": {},
            }
            storage.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "entries": [good_disk, bad],
                        "model_versions": {},
                        "config_hashes": {},
                    }
                ),
                encoding="utf-8",
            )
            assert cache.load() is False
            # Prior in-memory state untouched; no poisoned entry installed.
            assert cache.get("good", "det", "1.0") == ({"v": 1}, CacheEntryStatus.FRESH)
            assert len(cache._cache) == 1
            _reconciled(cache)
            # A fresh cache constructed over the same bad file starts empty
            # and answers a graceful miss, never ValueError.
            cache2 = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            assert cache2.stats.total_entries == 0
            assert cache2.get("good", "det", "1.0")[1] == CacheEntryStatus.MISSING

    @pytest.mark.asyncio
    async def test_bad_first_entry_and_naive_expiry_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            await cache.put("good", "det", "1.0", {"v": 1})
            now = datetime.now(UTC)
            naive = {
                "content_hash": "d" * 64,
                "detector_id": "det",
                "detector_version": "1.0",
                "result": {"v": 2},
                "created_at": now.replace(tzinfo=None).isoformat(),
                "expires_at": (now + timedelta(hours=1)).replace(tzinfo=None).isoformat(),
                "access_count": 0,
                "last_accessed": "",
                "size_bytes": 10,
                "metadata": {},
            }
            storage.write_text(
                json.dumps(
                    {"version": 1, "entries": [naive], "model_versions": {}, "config_hashes": {}}
                ),
                encoding="utf-8",
            )
            assert cache.load() is False
            assert cache.get("good", "det", "1.0")[1] == CacheEntryStatus.FRESH
            assert len(cache._cache) == 1

    @pytest.mark.asyncio
    async def test_forced_write_failure_preserves_old_file(self):
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            await cache.put("text1", "det1", "1.0", {"score": 0.5})
            assert cache.save() is True
            original = storage.read_bytes()
            # Point the cache at an unwritable location (parent is a file):
            # the save must fail without touching the old durable file.
            blocker = Path(td) / "blocker"
            blocker.write_text("not a directory", encoding="utf-8")
            cache.storage_path = blocker / "cache.json"
            assert cache.save() is False
            assert cache.last_persistence_error is not None
            assert storage.read_bytes() == original
            assert not list(Path(td).glob("cache.json.*.tmp"))
            # The old file still loads cleanly.
            cache2 = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            assert cache2.get("text1", "det1", "1.0")[1] == CacheEntryStatus.FRESH

    def test_oversized_file_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "cache.json"
            cache = DetectionCache(
                policy=CachePolicy(ttl_seconds=3600, max_entries=10, max_size_bytes=100),
                storage_path=storage,
            )
            # File budget derives from the policy; 2 MB of junk exceeds it.
            storage.write_bytes(b" " * (2 * 1024 * 1024))
            assert cache.load() is False
            assert cache.stats.total_entries == 0

    @pytest.mark.asyncio
    async def test_save_leaves_no_temp_files(self):
        with tempfile.TemporaryDirectory() as td:
            storage = Path(td) / "sub" / "cache.json"
            cache = DetectionCache(policy=CachePolicy(ttl_seconds=3600), storage_path=storage)
            await cache.put("text1", "det1", "1.0", {"score": 0.5})
            assert cache.save() is True
            assert sorted(p.name for p in storage.parent.iterdir()) == ["cache.json"]


# ============================================================ CORE-08
def _row(text: str, label: int) -> NormalizedRow:
    return NormalizedRow(
        text=text,
        label=label,
        dataset="beemo",
        config="default",
        split="train",
        source_id="test:1",
        regime="test",
        meta={},
    )


class TestCore08PersistedByteHash:
    def test_manifest_digest_matches_persisted_bytes(self):
        spec = get_spec("beemo")
        rows = [_row("héllo wörld — ünïcode", 0), _row("machine text here", 1)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest_file = write_sample_cache(spec, "default", "train", rows, cache_dir=root)
            raw = path.read_bytes()
            # The persisted bytes are exactly one LF-encoded UTF-8 encoding;
            # no CRLF can be introduced by a text-mode write.
            assert b"\r\n" not in raw
            assert (
                raw
                == "\n".join(
                    json.dumps(r.to_jsonl(), ensure_ascii=False, sort_keys=True) for r in rows
                ).encode("utf-8")
                + b"\n"
            )
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            assert manifest["file_sha256"] == hashlib.sha256(raw).hexdigest()

    def test_empty_rows_digest_is_empty_bytes_digest(self):
        spec = get_spec("beemo")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest_file = write_sample_cache(spec, "default", "train", [], cache_dir=root)
            assert path.read_bytes() == b""
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            assert manifest["file_sha256"] == hashlib.sha256(b"").hexdigest()
            assert manifest["rows"] == 0
            assert read_sample_cache(spec, "default", "train", cache_dir=root) == []

    def test_read_refuses_tampered_cache(self):
        spec = get_spec("beemo")
        rows = [_row("hello world", 0), _row("machine text here", 1)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, _ = write_sample_cache(spec, "default", "train", rows, cache_dir=root)
            # Tamper with the persisted bytes without updating the manifest.
            path.write_bytes(path.read_bytes() + b'{"text": "forged", "label": 1}\n')
            with pytest.raises(DatasetFetchError, match="digest"):
                read_sample_cache(spec, "default", "train", cache_dir=root)

    def test_read_refuses_wrong_row_count_manifest(self):
        spec = get_spec("beemo")
        rows = [_row("hello world", 0)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest_file = write_sample_cache(spec, "default", "train", rows, cache_dir=root)
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            manifest["rows"] = 99
            manifest_file.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            with pytest.raises(DatasetFetchError, match="row count"):
                read_sample_cache(spec, "default", "train", cache_dir=root)

    def test_failed_write_preserves_prior_cache(self):
        spec = get_spec("beemo")
        rows = [_row("hello world", 0)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, _ = write_sample_cache(spec, "default", "train", rows, cache_dir=root)
            original = path.read_bytes()
            # A path component of the new cache_dir is a regular file, so
            # the write must fail loudly instead of truncating the old file.
            blocker = root / "blocked"
            blocker.write_text("not a directory", encoding="utf-8")
            with pytest.raises(OSError):
                write_sample_cache(spec, "default", "train", rows, cache_dir=blocker)
            assert path.read_bytes() == original
