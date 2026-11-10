"""Tests for scripts/measure_opai_bench_humans.py (Phase 5 OpAI-Bench humans-100).

No network is used here and no real cache is needed: the offset tests
are pure arithmetic on ``sample_offsets``, and the server-total test
uses a stub client. The live fetch itself is exercised by the run,
not by these tests.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_measure_module():
    spec = importlib.util.spec_from_file_location(
        "measure_opai_bench_humans", SCRIPTS_DIR / "measure_opai_bench_humans.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["measure_opai_bench_humans"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def measure():
    return _load_measure_module()


class TestPhaseShiftedOffsets:
    def test_offsets_are_unique_and_in_range(self, measure):
        offsets = measure.opai_bench_humans_offsets()
        assert len(offsets) == 2000
        assert len(set(offsets)) == 2000
        assert min(offsets) == 49
        assert max(offsets) < 196_029

    def test_offsets_are_disjoint_from_the_u1_sample(self, measure):
        from textforensics.datasets import sample_offsets

        old = set(sample_offsets(196_029, 500))
        new = set(measure.opai_bench_humans_offsets())
        assert not new & old

    def test_offsets_stay_evenly_spaced(self, measure):
        offsets = sorted(measure.opai_bench_humans_offsets())
        gaps = [b - a for a, b in zip(offsets, offsets[1:], strict=False)]
        # The 2000-grid step is ~98 rows; a phase shift must not open
        # a gap a contiguous slice could hide in.
        assert max(gaps) < 200
        assert min(gaps) > 90

    def test_unshifted_2000_grid_would_reuse_the_u1_sample(self, measure):
        """The phase shift is load-bearing: same-stride n=2000 is a superset of n=500."""
        from textforensics.datasets import sample_offsets

        old = set(sample_offsets(196_029, 500))
        unshifted = set(sample_offsets(196_029, 2000))
        assert old <= unshifted


class TestContentHashAndExclusion:
    def test_content_hash_matches_the_benchmark_construction(self, measure):
        import hashlib
        import json

        expected = hashlib.sha256(
            json.dumps(
                {"text": "hello world"},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        assert measure.content_hash("hello world") == expected

    def test_exclude_duplicate_rows_drops_only_the_colliding_rows(self, measure):
        from types import SimpleNamespace

        rows = [
            SimpleNamespace(text="aaa", label=0),
            SimpleNamespace(text="bbb", label=1),
            SimpleNamespace(text="ccc", label=None),
            SimpleNamespace(text="ddd", label=0),
        ]
        offsets = [101, 202, 303, 404]
        dupes = {measure.content_hash("bbb"), measure.content_hash("ddd")}
        kept, kept_offsets, excluded = measure.exclude_duplicate_rows(rows, offsets, dupes)
        assert [r.text for r in kept] == ["aaa", "ccc"]
        assert kept_offsets == [101, 303]
        assert excluded == [
            {"offset": 202, "content_hash": measure.content_hash("bbb"), "label": 1},
            {"offset": 404, "content_hash": measure.content_hash("ddd"), "label": 0},
        ]

    def test_exclude_duplicate_rows_keeps_everything_when_nothing_collides(self, measure):
        from types import SimpleNamespace

        rows = [SimpleNamespace(text="aaa", label=0)]
        kept, kept_offsets, excluded = measure.exclude_duplicate_rows(rows, [7], set())
        assert kept == rows
        assert kept_offsets == [7]
        assert excluded == []

    def test_exclude_duplicate_rows_raises_on_an_internal_duplicate(self, measure):
        from types import SimpleNamespace

        import pytest

        rows = [
            SimpleNamespace(text="aaa", label=0),
            SimpleNamespace(text="aaa", label=1),
        ]
        with pytest.raises(ValueError, match="duplicate content hash inside the new sample"):
            measure.exclude_duplicate_rows(rows, [7, 8], set())


class TestServerTotalCheck:
    def test_fetch_refuses_on_a_changed_server_total(self, measure, tmp_path):
        class StubClient:
            def size(self, hf_id):
                return {
                    "splits": [
                        {"config": "default", "split": "train", "num_rows": 1},
                        {"config": "default", "split": "dev", "num_rows": 42_363},
                    ]
                }

            def rows(self, *args, **kwargs):
                raise AssertionError("rows must not be called after a total mismatch")

        with pytest.raises(ValueError, match="server reports 1 rows"):
            measure.fetch_new_sample(cache_dir=tmp_path, client=StubClient())


class _EchoClient:
    """Stub datasets-server client: echoes the requested offset as the row."""

    def __init__(self):
        import threading

        self._lock = threading.Lock()
        self.calls = 0

    def size(self, hf_id):
        return {
            "splits": [
                {"config": "default", "split": "train", "num_rows": 196_029},
                {"config": "default", "split": "dev", "num_rows": 42_363},
            ]
        }

    def rows(self, hf_id, config, split, *, offset=0, length=1):
        with self._lock:
            self.calls += 1
        return [{"offset": offset, "text": "test text"}]


def _write_fake_old_cache(measure, tmp_path, monkeypatch):
    """Write a fake U1 cache + manifest, and point the module at its SHA."""
    import hashlib
    import json

    cache = tmp_path / "opai_bench" / "default" / "train.jsonl"
    cache.parent.mkdir(parents=True, exist_ok=True)
    content = '{"text": "u1 row"}\n'
    cache.write_text(content, encoding="utf-8")
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    (tmp_path / "opai_bench" / "default" / "train.manifest.json").write_text(
        json.dumps({"file_sha256": sha}), encoding="utf-8"
    )
    monkeypatch.setattr(measure, "OLD_CACHE_SHA256", sha)
    return cache


class TestParallelFetch:
    def test_fetch_assembles_rows_in_offset_order_with_workers(
        self, measure, tmp_path, monkeypatch
    ):
        _write_fake_old_cache(measure, tmp_path, monkeypatch)
        stub = _EchoClient()
        rows, offsets = measure.fetch_new_sample(cache_dir=tmp_path, client=stub, workers=3)
        assert len(rows) == 2000
        assert offsets == measure.opai_bench_humans_offsets()
        assert [row["offset"] for row in rows] == offsets
        assert stub.calls == 2000
        checkpoint = tmp_path / "opai_bench" / "default" / "train-2000.raw.jsonl"
        assert len(checkpoint.read_text(encoding="utf-8").splitlines()) == 2000

    def test_fetch_drops_truncated_trailing_checkpoint_line(self, measure, tmp_path, monkeypatch):
        import json

        _write_fake_old_cache(measure, tmp_path, monkeypatch)
        offsets = measure.opai_bench_humans_offsets()
        checkpoint = tmp_path / "opai_bench" / "default" / "train-2000.raw.jsonl"
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        checkpoint.write_text(
            "\n".join(
                [
                    json.dumps({"offset": offsets[0], "row": {"offset": offsets[0]}}),
                    json.dumps({"offset": offsets[1], "row": {"offset": offsets[1]}}),
                    "{",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        stub = _EchoClient()
        rows, _offsets = measure.fetch_new_sample(cache_dir=tmp_path, client=stub, workers=2)
        assert len(rows) == 2000
        # The two intact rows were resumed, not re-fetched.
        assert stub.calls == 2000 - 2
        # The truncated line is gone: every checkpoint line parses now.
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            json.loads(line)
