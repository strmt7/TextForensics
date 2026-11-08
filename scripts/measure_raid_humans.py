#!/usr/bin/env python3
"""measure_raid_humans.py — Grow the RAID human slice past 100 (Phase 5 release gate).

Fetches a NEW strided RAID train sample of n=6000 rows and measures the
builtin detector on it, writing the U7 run artifact
``EV-20261108-dataset-raid``. This replaces the U1 sample (n=3000,
92 humans, ~3.07% human density) with a sample expected to hold ~184
humans, comfortably past the 100-row minimum for a ``supported`` slice
(and past the 120-human margin target).

Why a phase shift, not a same-stride extension
----------------------------------------------
``sample_offsets(total, n)`` places offsets at ``i * total // n``. The
n=6000 grid is a SUPERSET of the n=3000 grid (every U1 offset reappears),
so extending the stride would re-fetch all 3000 U1 rows. This script
instead fetches the n=6000 grid shifted by +189 rows — half the 6000
grid step (~378) — which is provably disjoint from the U1 offsets by
row index (verified in code before any fetch) and is then proven
disjoint by content hash with ``check_disjointness`` against the U1
cache. The shifted grid is still evenly spaced across the whole split,
so the sample stays strided, never contiguous (RAID train is
blocked-ordered: the first ~200 rows are all human).

The U1 cache is NEVER clobbered: the new sample is written to a
separate cache file (``train-6000.jsonl`` + manifest) next to the U1
``train.jsonl``; the old file and manifest are verified (SHA-256)
before the fetch and left untouched. The old record's
``data.file_sha256`` keeps pointing at the U1 cache.

The fetch checkpoints raw rows to ``train-6000.raw.jsonl`` in the same
cache directory and resumes from it, so a transient datasets-server
failure (HTTP 503 on /rows was seen in U1) costs the remaining rows,
not the whole fetch. The checkpoint is deleted once the normalised
cache is written and verified.

REGISTRY HOLD: this script writes the run artifact only. It does NOT
call ``rebuild_registry`` and does NOT touch ``docs/evidence/registry.json``
or ``docs/validation/registry.json`` — the registry record for the new
sample is produced separately by ``scripts/build_raid_humans_patch.py``
as a patch file for the parent to apply.

Usage:
    python scripts/measure_raid_humans.py [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from measure_datasets import auroc, tpr_at_fpr  # noqa: E402
from seed_evidence import _base_record, _write_record  # noqa: E402

from textforensics.benchmark import check_disjointness, fingerprint_dataset  # noqa: E402
from textforensics.datasets import (  # noqa: E402
    DatasetsServerClient,
    default_cache_dir,
    fetch_sample,
    get_spec,
    map_row,
    sample_offsets,
    write_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402

N_ROWS = 6000
SPLIT_TOTAL = 2_270_000
PHASE_SHIFT = 189
OLD_N_ROWS = 3000
OLD_CACHE_SHA256 = "f689a30963024b2dc1fa159f2888e1d2ba36e68263d467ab7f73db5d9e780c00"
NEW_FILENAME = "train-6000.jsonl"
RAW_CHECKPOINT_FILENAME = "train-6000.raw.jsonl"
RUN_ID = "EV-20261108-dataset-raid"
DISJOINT_CONFIG = "raid_test"
DISJOINT_SPLIT = "test"
DISJOINT_N = 50
DISJOINT_TOTAL = 672_000
UNMEASURED_VERSIONS = ["3.11", "3.13", "3.14", "3.15"]
# Per-offset resilience against datasets-server 502/503 bursts: rounds
# of the client's own 4-attempt fetch, with a growing pause between
# rounds (30s, 60s, 90s, 120s). A burst longer than ~5 minutes per
# offset still fails loudly with the checkpoint preserved.
FETCH_ROUNDS = 5
FETCH_ROUND_PAUSE_S = 30
# Sequential fetching ran at ~0.3 rows/s once the server started
# shedding load (single requests take 1-2s each); 4 workers share the
# same offsets, clients and checkpoint, and restored ~1 row/s. Each
# worker owns its client (the client holds no mutable per-call state,
# but sharing one across threads is not a contract the loader makes),
# each offset is assigned to exactly one worker, and rows are
# reassembled in offset order — the sample is identical to a
# sequential fetch of the same offsets.
DEFAULT_WORKERS = 4


def raid_humans_offsets(
    *, total: int = SPLIT_TOTAL, n: int = N_ROWS, phase_shift: int = PHASE_SHIFT
) -> list[int]:
    """Phase-shifted strided offsets: the n-grid shifted by ``phase_shift`` rows.

    The shift is half the grid step, so the shifted grid interleaves
    with the unshifted grid instead of reusing it. Offsets wrap modulo
    ``total`` (the largest shifted offset stays below ``total`` for
    this shift, so no wrap occurs in practice).
    """
    return [(offset + phase_shift) % total for offset in sample_offsets(total, n)]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_server_total(
    spec, config: str, split: str, expected: int, client: DatasetsServerClient
) -> None:
    sizes = client.size(spec.hf_id)
    actual = None
    for entry in sizes.get("splits", []):
        if entry.get("config") == config and entry.get("split") == split:
            actual = entry.get("num_rows")
            break
    if actual is None:
        raise ValueError(f"{spec.hf_id} {config}/{split}: split not reported by server")
    if actual != expected:
        raise ValueError(
            f"{spec.hf_id} {config}/{split}: server reports {actual} rows, "
            f"plan expects {expected} — re-verify the plan before sampling"
        )


def _score_summary(scores: list[float]) -> dict:
    if not scores:
        return {"n": 0, "mean": None, "median": None, "min": None, "max": None}
    return {
        "n": len(scores),
        "mean": round(statistics.fmean(scores), 4),
        "median": round(statistics.median(scores), 4),
        "min": round(min(scores), 4),
        "max": round(max(scores), 4),
    }


def _fetch_one_offset(offset: int, client: DatasetsServerClient, spec) -> dict:
    """Fetch one row, retrying 502/503 bursts in rounds (see FETCH_ROUNDS)."""
    page: list[dict] | None = None
    for round_no in range(1, FETCH_ROUNDS + 1):
        try:
            page = client.rows(spec.hf_id, "raid", "train", offset=offset, length=1)
            break
        except Exception as exc:  # noqa: BLE001 - retry, then re-raise below
            print(
                f"[raid] offset {offset}: attempt round {round_no}/{FETCH_ROUNDS} failed ({exc})",
                flush=True,
            )
            if round_no == FETCH_ROUNDS:
                raise
            # Jittered pause: without it, parallel workers that fail
            # together retry together and re-trigger the limit as one
            # synchronized burst (thundering herd).
            time.sleep(FETCH_ROUND_PAUSE_S * round_no + random.uniform(0, FETCH_ROUND_PAUSE_S))
    if not page:
        raise ValueError(f"liamdugan/raid raid/train: server returned no row at offset {offset}")
    return page[0]


def fetch_new_sample(
    *,
    cache_dir: Path | None = None,
    client: DatasetsServerClient | None = None,
    workers: int = DEFAULT_WORKERS,
) -> tuple[list[dict], list[int]]:
    """Fetch the phase-shifted RAID sample, resuming from the checkpoint.

    Returns the raw rows (in offset order) and the offsets used. The U1
    cache is verified first (manifest SHA-256) and the new offsets are
    proven disjoint from the U1 offsets by row index before any fetch.
    Raises on a server failure after the per-offset retry rounds; the
    checkpoint on disk preserves the rows fetched so far and a re-run
    resumes from it. ``workers`` threads fetch distinct offsets in
    parallel (each with its own client); rows are reassembled in offset
    order, so the result is identical to a sequential fetch.
    """
    spec = get_spec("raid")
    client = client or DatasetsServerClient()
    _check_server_total(spec, "raid", "train", SPLIT_TOTAL, client)
    _check_server_total(spec, DISJOINT_CONFIG, DISJOINT_SPLIT, DISJOINT_TOTAL, client)

    root = cache_dir or default_cache_dir()
    old_cache = root / "raid" / "raid" / "train.jsonl"
    old_manifest = root / "raid" / "raid" / "train.manifest.json"
    if not old_cache.exists():
        raise ValueError(f"U1 RAID cache missing: {old_cache} — refusing to fetch blind")
    if not old_manifest.exists():
        raise ValueError(f"U1 RAID manifest missing: {old_manifest}")
    manifest = json.loads(old_manifest.read_text(encoding="utf-8"))
    if manifest["file_sha256"] != OLD_CACHE_SHA256:
        raise ValueError(
            "U1 RAID manifest file_sha256 "
            f"{manifest['file_sha256']} != expected {OLD_CACHE_SHA256} — "
            "the U1 cache is not the sample the current record cites; refusing"
        )
    if _sha256_file(old_cache) != OLD_CACHE_SHA256:
        raise ValueError(
            f"U1 RAID cache {old_cache} does not hash to {OLD_CACHE_SHA256} — refusing"
        )
    print(f"[raid] U1 cache verified: 3000 rows, sha256 {OLD_CACHE_SHA256[:12]}...")

    offsets = raid_humans_offsets()
    if len(set(offsets)) != N_ROWS:
        raise ValueError(f"shifted offsets are not unique: {len(set(offsets))} of {N_ROWS}")
    old_offsets = set(sample_offsets(SPLIT_TOTAL, OLD_N_ROWS))
    overlap = set(offsets) & old_offsets
    if overlap:
        raise ValueError(
            f"shifted offsets overlap the U1 offsets at {len(overlap)} positions "
            f"(e.g. {sorted(overlap)[:5]}) — refusing"
        )
    print(
        f"[raid] {N_ROWS} phase-shifted offsets (shift +{PHASE_SHIFT}) are "
        f"disjoint from the {OLD_N_ROWS} U1 offsets by row index"
    )

    checkpoint = root / "raid" / "raid" / RAW_CHECKPOINT_FILENAME
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    done: dict[int, dict] = {}
    if checkpoint.exists():
        lines = [
            line for line in checkpoint.read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        dropped_trailing = False
        for line_no, line in enumerate(lines):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                if line_no == len(lines) - 1:
                    # A kill mid-write can leave a truncated trailing
                    # line; it holds no complete row, so drop it (the
                    # offset is simply re-fetched) instead of failing.
                    print(
                        "[raid] dropping truncated trailing checkpoint line "
                        "(offset unknown); it will be re-fetched"
                    )
                    dropped_trailing = True
                    break
                raise
            done[int(entry["offset"])] = entry["row"]
        if dropped_trailing:
            # Remove the truncated line from the file, or a later
            # resume would meet it mid-file and fail on it.
            checkpoint.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        print(f"[raid] resuming from checkpoint: {len(done)} rows already fetched")
    if workers < 1:
        raise ValueError(f"workers must be positive, got {workers}")
    remaining = [offset for offset in offsets if offset not in done]
    results: dict[int, dict] = dict(done)
    started = time.time()
    state = {"fetched_this_run": 0, "appended": 0}
    lock = threading.Lock()
    thread_local = threading.local()

    def thread_client() -> DatasetsServerClient:
        if not isinstance(client, DatasetsServerClient):
            # Test stub: shared by design (stubs in tests are thread-safe).
            return client  # type: ignore[return-value]
        owned = getattr(thread_local, "client", None)
        if owned is None:
            owned = DatasetsServerClient(
                base_url=client.base_url,
                timeout_s=client.timeout_s,
                retries=client.retries,
                user_agent=client.user_agent,
            )
            thread_local.client = owned
        return owned

    def work(offset: int) -> tuple[int, dict]:
        return offset, _fetch_one_offset(offset, thread_client(), spec)

    with (
        checkpoint.open("a", encoding="utf-8") as handle,
        ThreadPoolExecutor(max_workers=workers) as pool,
    ):
        futures = {pool.submit(work, offset): offset for offset in remaining}
        for future in as_completed(futures):
            offset, row = future.result()
            with lock:
                handle.write(json.dumps({"offset": offset, "row": row}, ensure_ascii=False) + "\n")
                state["appended"] += 1
                if state["appended"] % 100 == 0:
                    handle.flush()
                results[offset] = row
                state["fetched_this_run"] += 1
                fetched = len(results)
                if fetched % 500 == 0 or fetched == N_ROWS:
                    elapsed = time.time() - started
                    rate = state["fetched_this_run"] / max(elapsed, 1e-9)
                    eta = (N_ROWS - fetched) / rate if rate > 0 else 0.0
                    print(
                        f"[raid] fetched {fetched}/{N_ROWS} rows "
                        f"({elapsed:.0f}s elapsed this run, ETA {eta:.0f}s)",
                        flush=True,
                    )
    rows = [results[offset] for offset in offsets]
    if len(rows) != N_ROWS:
        raise ValueError(f"fetched {len(rows)} rows, expected {N_ROWS}")
    return rows, offsets


def measure_new_sample(force: bool, workers: int = DEFAULT_WORKERS) -> dict:
    """Fetch, cache, verify disjointness, measure, and write the run artifact."""
    spec = get_spec("raid")
    raw, _offsets = fetch_new_sample(workers=workers)
    normalized = []
    for row in raw:
        normalized.extend(map_row("raid", row, "raid", "train"))
    cache_path, manifest_path = write_sample_cache(
        spec, "raid", "train", normalized, filename=NEW_FILENAME
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_sha = _sha256_file(cache_path)
    if manifest["file_sha256"] != cache_sha:
        raise ValueError(
            f"new cache manifest file_sha256 {manifest['file_sha256']} != "
            f"recomputed SHA-256 {cache_sha} of {cache_path}"
        )
    if len(normalized) != N_ROWS:
        raise ValueError(f"mapped {len(normalized)} normalised rows, expected {N_ROWS}")
    counts = Counter(r.label for r in normalized)
    n_human = counts.get(0, 0)
    n_ai = counts.get(1, 0)
    print(
        f"[raid] mapped to {len(normalized)} normalised rows "
        f"({n_human} human / {n_ai} AI) -> {cache_path}"
    )
    print(f"[raid] new cache sha256 {cache_sha}")

    # Disjointness by content hash: against the U1 3000-row cache (the
    # task's proof) and against raid_test/test (the U1 procedure).
    root = default_cache_dir()
    old_cache = root / "raid" / "raid" / "train.jsonl"
    fp_new = fingerprint_dataset(cache_path, "raid", split="train")
    fp_old = fingerprint_dataset(old_cache, "raid", split="train")
    check_old = check_disjointness(cache_path, fp_new, old_cache, fp_old)
    print(
        f"[raid] disjointness vs U1 3000-row cache: {check_old['disjoint']} "
        f"(verified={check_old['verified']}, shared={check_old['shared_samples']})"
    )
    if not check_old["disjoint"] or not check_old["verified"]:
        raise ValueError(
            "new sample is NOT disjoint from the U1 cache by content hash: "
            f"{check_old} — refusing to measure it as a fresh sample"
        )
    test_cache = root / "raid" / DISJOINT_CONFIG / "test.jsonl"
    if not test_cache.exists():
        print("[raid] raid_test/test cache missing; fetching the 50 first rows ...")
        raw2 = fetch_sample(spec, DISJOINT_CONFIG, DISJOINT_SPLIT, DISJOINT_N)
        normalized2 = []
        for row in raw2:
            normalized2.extend(map_row("raid", row, DISJOINT_CONFIG, DISJOINT_SPLIT))
        test_cache, _ = write_sample_cache(spec, DISJOINT_CONFIG, DISJOINT_SPLIT, normalized2)
    fp_test = fingerprint_dataset(test_cache, "raid", split="test")
    check_test = check_disjointness(cache_path, fp_new, test_cache, fp_test)
    print(
        f"[raid] disjointness vs {DISJOINT_CONFIG}/{DISJOINT_SPLIT}: "
        f"{check_test['disjoint']} (verified={check_test['verified']}, "
        f"shared={check_test['shared_samples']})"
    )
    if not check_test["disjoint"] or not check_test["verified"]:
        raise ValueError(
            "new sample is NOT disjoint from raid_test/test by content hash: "
            f"{check_test} — refusing to report it as disjoint"
        )

    # Detector behaviour on the labelled rows only (same procedure as
    # scripts/measure_datasets.py).
    detector = BuiltinHeuristicDetector()
    labelled = [r for r in normalized if r.label is not None]
    pairs: list[tuple[int, float]] = []
    abstentions = 0
    per_kind: dict[str, list[float]] = {}
    for row in labelled:
        prediction = detector.detect(row.text)
        if prediction.verdict == "abstain":
            abstentions += 1
        pairs.append((int(row.label), float(prediction.score)))
        kind = str(row.meta.get("kind", row.regime))
        per_kind.setdefault(kind, []).append(float(prediction.score))
    labels = [lab for lab, _ in pairs]
    scores = [s for _, s in pairs]
    results: dict = {
        "dataset": "raid",
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "preliminary": True,
        "config": "raid",
        "split": "train",
        "sampling": "strided",
        "phase_shift": PHASE_SHIFT,
        "sampling_note": (
            f"strided offsets i*{SPLIT_TOTAL}//{N_ROWS}+{PHASE_SHIFT}: the "
            f"{N_ROWS}-grid shifted by half its step so the sample is "
            f"disjoint from the U1 {OLD_N_ROWS}-row strided sample by row "
            "index (verified by content hash below); never contiguous — "
            "RAID train is blocked-ordered (first ~200 rows all human)"
        ),
        "split_rows_total": SPLIT_TOTAL,
        "rows_fetched": N_ROWS,
        "rows_normalised": len(normalized),
        "label_counts": {str(k): counts[k] for k in (0, 1, None) if k in counts},
        "cache_file": NEW_FILENAME,
        "cache_file_sha256": cache_sha,
        "detector": BuiltinHeuristicDetector.detector_id,
        "detector_version": BuiltinHeuristicDetector.detector_version,
        "detector_evaluated_rows": len(pairs),
        "detector_abstentions": abstentions,
        "score_by_label": {
            "human": _score_summary([s for lab, s in pairs if lab == 0]),
            "machine": _score_summary([s for lab, s in pairs if lab == 1]),
        },
        "disjointness": {
            "checked": True,
            "against": f"{DISJOINT_CONFIG}/{DISJOINT_SPLIT} (n={DISJOINT_N})",
            "disjoint": check_test["disjoint"],
            "verified": check_test["verified"],
            "shared_samples": check_test["shared_samples"],
            "errors": check_test["errors"],
        },
        "disjointness_vs_previous_sample": {
            "checked": True,
            "against": f"raid/train U1 sample (n={OLD_N_ROWS})",
            "disjoint": check_old["disjoint"],
            "verified": check_old["verified"],
            "shared_samples": check_old["shared_samples"],
            "errors": check_old["errors"],
        },
    }
    if len(set(labels)) == 2 and min(Counter(labels).values()) >= 10:
        results["auroc"] = round(auroc(labels, scores), 4)
        results["tpr_at_1pct_fpr"] = round(tpr_at_fpr(labels, scores, 0.01), 4)
        results["tpr_at_5pct_fpr"] = round(tpr_at_fpr(labels, scores, 0.05), 4)
    else:
        results["auroc"] = None
        results["auroc_not_computed"] = (
            f"both classes need >= 10 rows; label counts are {dict(Counter(labels))}"
        )
    results["mean_score_by_kind"] = {
        kind: round(statistics.fmean(vals), 4) for kind, vals in sorted(per_kind.items())
    }
    results["rows_by_kind"] = {kind: len(vals) for kind, vals in sorted(per_kind.items())}

    drops = [
        {
            "item": "full-corpus evaluation",
            "reason": (
                f"preliminary sample only (n={len(normalized)} normalised rows "
                f"from {SPLIT_TOTAL} split rows)"
            ),
        },
        {
            "item": f"Python {', '.join(UNMEASURED_VERSIONS)}",
            "reason": "measured on the local interpreter only; CI covers the matrix",
        },
        {
            "item": "train/test threshold selection",
            "reason": ("no threshold was fitted on this sample; AUROC/TPR@FPR are threshold-free"),
        },
    ]
    record = _base_record(RUN_ID, "command", "python scripts/measure_raid_humans.py")
    record["results"] = results
    record["drops"] = drops
    record["badge"] = "available"
    path = _write_record(record, force)
    print(f"[raid] wrote {path.name} (sha256 {_sha256_file(path)})")

    # The normalised cache + manifest is the authoritative sample; the
    # raw checkpoint only duplicates it.
    checkpoint = default_cache_dir() / "raid" / "raid" / RAW_CHECKPOINT_FILENAME
    checkpoint.unlink(missing_ok=True)
    print(f"[raid] removed raw checkpoint {checkpoint.name}")
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace the existing run artifact if one is already present",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="parallel fetch workers (default 4; each fetches distinct offsets)",
    )
    args = parser.parse_args(argv)
    results = measure_new_sample(force=args.force, workers=args.workers)
    print(
        f"[raid] done: n={results['rows_normalised']} "
        f"human={results['label_counts'].get('0')} ai={results['label_counts'].get('1')} "
        f"auroc={results.get('auroc')} tpr@1%={results.get('tpr_at_1pct_fpr')} "
        f"tpr@5%={results.get('tpr_at_5pct_fpr')} "
        f"abstentions={results['detector_abstentions']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
