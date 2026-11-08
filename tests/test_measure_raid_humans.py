"""Tests for scripts/measure_raid_humans.py (Phase 5 RAID humans-100).

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
        "measure_raid_humans", SCRIPTS_DIR / "measure_raid_humans.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["measure_raid_humans"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def measure():
    return _load_measure_module()


class TestPhaseShiftedOffsets:
    def test_offsets_are_unique_and_in_range(self, measure):
        offsets = measure.raid_humans_offsets()
        assert len(offsets) == 6000
        assert len(set(offsets)) == 6000
        assert min(offsets) == 189
        assert max(offsets) < 2_270_000

    def test_offsets_are_disjoint_from_the_u1_sample(self, measure):
        from textforensics.datasets import sample_offsets

        old = set(sample_offsets(2_270_000, 3000))
        new = set(measure.raid_humans_offsets())
        assert not new & old

    def test_offsets_stay_evenly_spaced(self, measure):
        offsets = sorted(measure.raid_humans_offsets())
        gaps = [b - a for a, b in zip(offsets, offsets[1:], strict=False)]
        # The 6000-grid step is ~378 rows; a phase shift must not open
        # a gap a contiguous slice could hide in.
        assert max(gaps) < 800
        assert min(gaps) > 300

    def test_unshifted_6000_grid_would_reuse_the_u1_sample(self, measure):
        """The phase shift is load-bearing: same-stride n=6000 is a superset of n=3000."""
        from textforensics.datasets import sample_offsets

        old = set(sample_offsets(2_270_000, 3000))
        unshifted = set(sample_offsets(2_270_000, 6000))
        assert old <= unshifted


class TestServerTotalCheck:
    def test_fetch_refuses_on_a_changed_server_total(self, measure, tmp_path):
        class StubClient:
            def size(self, hf_id):
                return {
                    "splits": [
                        {"config": "raid", "split": "train", "num_rows": 1},
                        {"config": "raid_test", "split": "test", "num_rows": 672_000},
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
                {"config": "raid", "split": "train", "num_rows": 2_270_000},
                {"config": "raid_test", "split": "test", "num_rows": 672_000},
            ]
        }

    def rows(self, hf_id, config, split, *, offset=0, length=1):
        with self._lock:
            self.calls += 1
        return [{"offset": offset, "model": "human", "generation": "test text"}]


def _write_fake_old_cache(measure, tmp_path, monkeypatch):
    """Write a fake U1 cache + manifest, and point the module at its SHA."""
    import hashlib
    import json

    cache = tmp_path / "raid" / "raid" / "train.jsonl"
    cache.parent.mkdir(parents=True, exist_ok=True)
    content = '{"text": "u1 row"}\n'
    cache.write_text(content, encoding="utf-8")
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    (tmp_path / "raid" / "raid" / "train.manifest.json").write_text(
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
        assert len(rows) == 6000
        assert offsets == measure.raid_humans_offsets()
        assert [row["offset"] for row in rows] == offsets
        assert stub.calls == 6000
        checkpoint = tmp_path / "raid" / "raid" / "train-6000.raw.jsonl"
        assert len(checkpoint.read_text(encoding="utf-8").splitlines()) == 6000

    def test_fetch_drops_truncated_trailing_checkpoint_line(self, measure, tmp_path, monkeypatch):
        import json

        _write_fake_old_cache(measure, tmp_path, monkeypatch)
        offsets = measure.raid_humans_offsets()
        checkpoint = tmp_path / "raid" / "raid" / "train-6000.raw.jsonl"
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
        assert len(rows) == 6000
        # The two intact rows were resumed, not re-fetched.
        assert stub.calls == 6000 - 2
        # The truncated line is gone: every checkpoint line parses now.
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            json.loads(line)
