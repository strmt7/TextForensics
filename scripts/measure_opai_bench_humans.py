#!/usr/bin/env python3
"""measure_opai_bench_humans.py — Grow the OpAI-Bench human slice past 100 (Phase 5 release gate).

Fetches a NEW strided OpAI-Bench ``default``/``train`` sample of
n=2000 rows and measures the builtin detector on it, writing the U7
run artifact ``EV-20261110-dataset-opai-bench``. This replaces the U1
sample (n=500, 56 humans, 55 AI — 11.2% v0 density) with a sample
expected to hold ~224 humans and ~224 AI, comfortably past the
100-row minimum for a ``supported`` slice (and past the 150-human
margin target for the worst-slice human-FPR gate: the U1 slice fails
it with Wilson 95% upper 0.0642 at n=56).

Why a phase shift, not a same-stride extension
----------------------------------------------
``sample_offsets(total, n)`` places offsets at ``i * total // n``.
The n=2000 grid is a SUPERSET of the n=500 grid (2000 = 4 * 500, so
every U1 offset reappears), so extending the stride would re-fetch
all 500 U1 rows. This script instead fetches the n=2000 grid shifted
by +49 rows — half the 2000 grid step (~98) — which is provably
disjoint from the U1 offsets by row index (verified in code before
any fetch) and is then proven disjoint by content hash with
``check_disjointness`` against the U1 cache. The shifted grid is
still evenly spaced across the whole split, so the sample stays
strided, never contiguous.

Slice discipline (identical to U1)
-----------------------------------
Same config (``default``) and split (``train``), same strided
method, same mapper: only the v0/v8 endpoint rows carry binary
labels (v0 pure-human / v8 fully-machine); partial rows
(0 < ai_sentence_ratio < 1) get ``label=None`` and are the U4 spine,
not U1 evidence. The detector is run at its native operating point
over the labelled rows only, exactly as in
``scripts/measure_datasets.py``.

The U1 cache is NEVER clobbered: the new sample is written to a
separate cache file (``train-2000.jsonl`` + manifest) next to the U1
``train.jsonl``; the old file and manifest are verified (SHA-256)
before the fetch and left untouched. The old record's
``data.file_sha256`` keeps pointing at the U1 cache. The U4 segment
cache (``train-segments.jsonl``, the same 500 texts with segment
ground truth) is likewise untouched and is checked for disjointness
by content hash as well.

The fetch checkpoints raw rows to ``train-2000.raw.jsonl`` in the
same cache directory and resumes from it, so a transient
datasets-server failure (HTTP 502/503 bursts were seen in the RAID
growth wave) costs the remaining rows, not the whole fetch. The
checkpoint is deleted once the normalised cache is written and
verified.

REGISTRY HOLD: this script writes the run artifact only. It does NOT
call ``rebuild_registry`` and does NOT touch ``docs/evidence/registry.json``
or ``docs/validation/registry.json`` — the registry record for the new
sample is produced separately by
``scripts/build_opai_bench_humans_patch.py`` as a patch file for the
parent to apply.

Human-FPR reporting: the run artifact carries the native false
positive count ``k_fp`` over ``n_human`` human rows and the honest
Wilson 95% interval from the repo's own ``wilson_ci``
(``textforensics.probe_metrics``) — the bootstrap ``fpr_native`` CI
in the registry record is degenerate ``[0.0, 0.0]`` at zero false
positives, so the Wilson interval is the number the FPR bar
(n >= 100 AND Wilson upper <= 0.05) is judged on. A first false
positive, if one appears, is reported with its (k, n, Wilson)
numbers; nothing is re-sampled and no threshold is changed.

Usage:
    python scripts/measure_opai_bench_humans.py [--force]

Corpus duplication (found 2026-11-10, Worker A2)
-------------------------------------------------
Offset-disjointness is NOT sufficient: the OpAI-Bench train split
repeats each pure-human v0 document once per generator (the same
``document_hash_id``, the same byte-identical text, a different
``record_id`` and ``generator``). The first full fetch of the shifted
grid therefore shared 4 content hashes with the U1 cache — all four
human (v0) rows, lengths 1417–4057 chars, texts exactly equal. The
script drops exactly those rows (by content hash against the U1
cache) before writing the normalised cache, so the kept sample is
disjoint from U1 by content hash (0 shared, proven by the
``check_disjointness`` step below) while staying the shifted strided
grid minus 4 documented exclusions. The exclusion is by identity,
not by detector score: no row is dropped for how it scores, nothing
is re-sampled to avoid a false positive, and the excluded offsets,
hashes and labels are recorded in the run artifact.
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
    fetch_strided_sample,
    get_spec,
    map_row,
    sample_offsets,
    write_sample_cache,
)
from textforensics.detectors import BuiltinHeuristicDetector  # noqa: E402
from textforensics.probe_metrics import wilson_ci  # noqa: E402

N_ROWS = 2000
SPLIT_TOTAL = 196_029
PHASE_SHIFT = 49
CONFIG = "default"
SPLIT = "train"
OLD_N_ROWS = 500
OLD_CACHE_SHA256 = "72bcfe9f0948afa036f6707da5f366c989ce2f455592764b56c7bfea08e2a2ae"
NEW_FILENAME = "train-2000.jsonl"
RAW_CHECKPOINT_FILENAME = "train-2000.raw.jsonl"
RUN_ID = "EV-20261110-dataset-opai-bench"
DISJOINT_CONFIG = "default"
DISJOINT_SPLIT = "dev"
DISJOINT_N = 50
DISJOINT_TOTAL = 42_363
SEGMENTS_FILENAME = "train-segments.jsonl"
UNMEASURED_VERSIONS = ["3.11", "3.13", "3.14", "3.15"]
# Per-offset resilience against datasets-server 502/503 bursts: rounds
# of the client's own 4-attempt fetch, with a growing pause between
# rounds (30s, 60s, 90s, 120s). A burst longer than ~5 minutes per
# offset still fails loudly with the checkpoint preserved.
FETCH_ROUNDS = 5
FETCH_ROUND_PAUSE_S = 30
# Sequential fetching ran at ~0.3 rows/s once the server started
# shedding load in the RAID growth wave (single requests take 1-2s
# each); 4 workers share the same offsets, clients and checkpoint, and
# restored ~1 row/s. Each worker owns its client (the client holds no
# mutable per-call state, but sharing one across threads is not a
# contract the loader makes), each offset is assigned to exactly one
# worker, and rows are reassembled in offset order — the sample is
# identical to a sequential fetch of the same offsets.
DEFAULT_WORKERS = 4


def content_hash(text: str) -> str:
    """Content hash of one normalised text.

    Same construction as ``textforensics.benchmark._compute_sample_hashes``
    (SHA-256 of ``{"text": text}`` as compact sorted JSON), so hashes
    computed here are directly comparable to fingerprint hashes.
    """
    content = json.dumps({"text": text}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def exclude_duplicate_rows(rows, offsets, duplicate_hashes):
    """Drop rows whose content hash is in ``duplicate_hashes``.

    Returns ``(kept_rows, kept_offsets, excluded)`` where each excluded
    entry is ``{"offset": int, "content_hash": str, "label": int | None}``.
    Order is preserved. Raises if the kept rows contain an internal
    content duplicate (fail closed: a duplicated document inside the
    new sample would double-count one text).
    """
    kept_rows: list = []
    kept_offsets: list[int] = []
    excluded: list[dict] = []
    seen: set[str] = set()
    for row, offset in zip(rows, offsets, strict=True):
        digest = content_hash(row.text)
        if digest in duplicate_hashes:
            excluded.append({"offset": offset, "content_hash": digest, "label": row.label})
            continue
        if digest in seen:
            raise ValueError(f"duplicate content hash inside the new sample at offset {offset}")
        seen.add(digest)
        kept_rows.append(row)
        kept_offsets.append(offset)
    return kept_rows, kept_offsets, excluded


def opai_bench_humans_offsets(
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
            page = client.rows(spec.hf_id, CONFIG, SPLIT, offset=offset, length=1)
            break
        except Exception as exc:  # noqa: BLE001 - retry, then re-raise below
            print(
                f"[opai] offset {offset}: attempt round {round_no}/{FETCH_ROUNDS} failed ({exc})",
                flush=True,
            )
            if round_no == FETCH_ROUNDS:
                raise
            # Jittered pause: without it, parallel workers that fail
            # together retry together and re-trigger the limit as one
            # synchronized burst (thundering herd).
            time.sleep(FETCH_ROUND_PAUSE_S * round_no + random.uniform(0, FETCH_ROUND_PAUSE_S))
    if not page:
        raise ValueError(
            f"OpAI-Bench1/OpAI-Bench {CONFIG}/{SPLIT}: server returned no row at offset {offset}"
        )
    return page[0]


def fetch_new_sample(
    *,
    cache_dir: Path | None = None,
    client: DatasetsServerClient | None = None,
    workers: int = DEFAULT_WORKERS,
) -> tuple[list[dict], list[int]]:
    """Fetch the phase-shifted OpAI-Bench sample, resuming from the checkpoint.

    Returns the raw rows (in offset order) and the offsets used. The U1
    cache is verified first (manifest SHA-256) and the new offsets are
    proven disjoint from the U1 offsets by row index before any fetch.
    Raises on a server failure after the per-offset retry rounds; the
    checkpoint on disk preserves the rows fetched so far and a re-run
    resumes from it. ``workers`` threads fetch distinct offsets in
    parallel (each with its own client); rows are reassembled in offset
    order, so the result is identical to a sequential fetch.
    """
    spec = get_spec("opai_bench")
    client = client or DatasetsServerClient()
    _check_server_total(spec, CONFIG, SPLIT, SPLIT_TOTAL, client)
    _check_server_total(spec, DISJOINT_CONFIG, DISJOINT_SPLIT, DISJOINT_TOTAL, client)

    root = cache_dir or default_cache_dir()
    old_cache = root / "opai_bench" / CONFIG / "train.jsonl"
    old_manifest = root / "opai_bench" / CONFIG / "train.manifest.json"
    if not old_cache.exists():
        raise ValueError(f"U1 OpAI-Bench cache missing: {old_cache} — refusing to fetch blind")
    if not old_manifest.exists():
        raise ValueError(f"U1 OpAI-Bench manifest missing: {old_manifest}")
    manifest = json.loads(old_manifest.read_text(encoding="utf-8"))
    if manifest["file_sha256"] != OLD_CACHE_SHA256:
        raise ValueError(
            "U1 OpAI-Bench manifest file_sha256 "
            f"{manifest['file_sha256']} != expected {OLD_CACHE_SHA256} — "
            "the U1 cache is not the sample the current record cites; refusing"
        )
    if _sha256_file(old_cache) != OLD_CACHE_SHA256:
        raise ValueError(
            f"U1 OpAI-Bench cache {old_cache} does not hash to {OLD_CACHE_SHA256} — refusing"
        )
    print(f"[opai] U1 cache verified: 500 rows, sha256 {OLD_CACHE_SHA256[:12]}...")

    offsets = opai_bench_humans_offsets()
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
        f"[opai] {N_ROWS} phase-shifted offsets (shift +{PHASE_SHIFT}) are "
        f"disjoint from the {OLD_N_ROWS} U1 offsets by row index"
    )

    checkpoint = root / "opai_bench" / CONFIG / RAW_CHECKPOINT_FILENAME
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
                        "[opai] dropping truncated trailing checkpoint line "
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
        print(f"[opai] resuming from checkpoint: {len(done)} rows already fetched")
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
                        f"[opai] fetched {fetched}/{N_ROWS} rows "
                        f"({elapsed:.0f}s elapsed this run, ETA {eta:.0f}s)",
                        flush=True,
                    )
    rows = [results[offset] for offset in offsets]
    if len(rows) != N_ROWS:
        raise ValueError(f"fetched {len(rows)} rows, expected {N_ROWS}")
    return rows, offsets


def _check_content_disjoint(
    *, new_cache: Path, other_cache: Path, label: str, dataset: str = "opai_bench"
) -> dict:
    """Content-hash disjointness of the new cache against one other cache."""
    fp_new = fingerprint_dataset(new_cache, dataset, split="train")
    fp_other = fingerprint_dataset(other_cache, dataset, split="train")
    check = check_disjointness(new_cache, fp_new, other_cache, fp_other)
    print(
        f"[opai] disjointness vs {label}: {check['disjoint']} "
        f"(verified={check['verified']}, shared={check['shared_samples']})"
    )
    if not check["disjoint"] or not check["verified"]:
        raise ValueError(f"new sample is NOT disjoint from {label} by content hash: {check}")
    return check


def measure_new_sample(force: bool, workers: int = DEFAULT_WORKERS) -> dict:
    """Fetch, cache, verify disjointness, measure, and write the run artifact."""
    spec = get_spec("opai_bench")
    raw, _offsets = fetch_new_sample(workers=workers)
    normalized = []
    for row in raw:
        normalized.extend(map_row("opai_bench", row, CONFIG, SPLIT))
    if len(normalized) != N_ROWS:
        raise ValueError(f"mapped {len(normalized)} normalised rows, expected {N_ROWS}")
    # Corpus duplication: OpAI-Bench repeats each pure-human v0
    # document once per generator, so offset-disjoint rows can still
    # duplicate U1 documents by content. Drop exactly those rows
    # (by content hash vs the U1 cache) before writing the cache, so
    # the kept sample is disjoint from U1 by content hash. Exclusion
    # is by identity, never by detector score.
    root = default_cache_dir()
    old_cache = root / "opai_bench" / CONFIG / "train.jsonl"
    old_hashes = set(fingerprint_dataset(old_cache, "opai_bench", split="train").content_hashes)
    normalized, _kept_offsets, excluded = exclude_duplicate_rows(normalized, _offsets, old_hashes)
    if excluded:
        print(
            f"[opai] !!! EXCLUDED {len(excluded)} rows duplicating U1 documents "
            "by content hash (same document_hash_id, different record_id/generator):"
        )
        for entry in excluded:
            print(
                f"[opai]   excluded offset {entry['offset']} "
                f"label={entry['label']} hash={entry['content_hash'][:12]}..."
            )
    cache_path, manifest_path = write_sample_cache(
        spec, CONFIG, SPLIT, normalized, filename=NEW_FILENAME
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_sha = _sha256_file(cache_path)
    if manifest["file_sha256"] != cache_sha:
        raise ValueError(
            f"new cache manifest file_sha256 {manifest['file_sha256']} != "
            f"recomputed SHA-256 {cache_sha} of {cache_path}"
        )
    if len(normalized) + len(excluded) != N_ROWS:
        raise ValueError(
            f"kept {len(normalized)} normalised rows + {len(excluded)} excluded, "
            f"expected {N_ROWS} fetched"
        )
    counts = Counter(r.label for r in normalized)
    n_human = counts.get(0, 0)
    n_ai = counts.get(1, 0)
    n_partial = counts.get(None, 0)
    print(
        f"[opai] mapped to {len(normalized)} normalised rows "
        f"({n_human} human / {n_ai} AI / {n_partial} partial) -> {cache_path}"
    )
    print(f"[opai] new cache sha256 {cache_sha}")

    # Disjointness by content hash: against the U1 500-row cache (the
    # task's proof), against the U4 segment cache (the same 500 texts
    # with segment ground truth), and against default/dev (the U1
    # procedure).
    root = default_cache_dir()
    old_cache = root / "opai_bench" / CONFIG / "train.jsonl"
    check_old = _check_content_disjoint(
        new_cache=cache_path, other_cache=old_cache, label="opai_bench/default train U1 (n=500)"
    )
    segments_cache = root / "opai_bench" / CONFIG / SEGMENTS_FILENAME
    check_segments = None
    if segments_cache.exists():
        check_segments = _check_content_disjoint(
            new_cache=cache_path,
            other_cache=segments_cache,
            label=f"opai_bench/default {SEGMENTS_FILENAME} (U4, n=500)",
        )
    else:
        print(f"[opai] segment cache {SEGMENTS_FILENAME} missing; skipping that check")
    dev_cache = root / "opai_bench" / DISJOINT_CONFIG / "dev.jsonl"
    if not dev_cache.exists():
        print("[opai] default/dev cache missing; fetching the 50 strided dev rows ...")
        raw2 = fetch_strided_sample(
            spec, DISJOINT_CONFIG, DISJOINT_SPLIT, DISJOINT_N, DISJOINT_TOTAL
        )
        normalized2 = []
        for row in raw2:
            normalized2.extend(map_row("opai_bench", row, DISJOINT_CONFIG, DISJOINT_SPLIT))
        dev_cache, _ = write_sample_cache(spec, DISJOINT_CONFIG, DISJOINT_SPLIT, normalized2)
    check_dev = _check_content_disjoint(
        new_cache=cache_path,
        other_cache=dev_cache,
        label=f"{DISJOINT_CONFIG}/{DISJOINT_SPLIT} (n={DISJOINT_N})",
    )

    # Detector behaviour on the labelled rows only (same procedure as
    # scripts/measure_datasets.py).
    detector = BuiltinHeuristicDetector()
    labelled = [r for r in normalized if r.label is not None]
    pairs: list[tuple[int, float]] = []
    verdicts_by_label: dict[int, list[str]] = {0: [], 1: []}
    abstentions = 0
    per_kind: dict[str, list[float]] = {}
    for row in labelled:
        prediction = detector.detect(row.text)
        if prediction.verdict == "abstain":
            abstentions += 1
        pairs.append((int(row.label), float(prediction.score)))
        verdicts_by_label[int(row.label)].append(str(prediction.verdict))
        kind = str(row.meta.get("kind", row.regime))
        per_kind.setdefault(kind, []).append(float(prediction.score))
    labels = [lab for lab, _ in pairs]
    scores = [s for _, s in pairs]
    k_fp = sum(1 for v in verdicts_by_label[0] if v == "ai_like")
    wilson_lo, wilson_hi = wilson_ci(k_fp, n_human)
    fpr_value = k_fp / n_human if n_human else 0.0
    fpr_passes = bool(n_human >= 100 and wilson_hi <= 0.05)
    print(
        f"[opai] native human FPR: {k_fp}/{n_human} = {fpr_value:.4f}, "
        f"Wilson 95% CI [{wilson_lo:.4f}, {wilson_hi:.4f}] — "
        f"FPR bar (n>=100, Wilson upper<=0.05): {'PASSES' if fpr_passes else 'FAILS'}"
    )
    if k_fp > 0:
        print(
            "!!! FIRST FALSE POSITIVE(S) ON THIS SLICE: "
            f"{k_fp} of {n_human} human rows verdict ai_like at the native "
            "operating point — reported as measured, no re-sampling !!!"
        )
    results: dict = {
        "dataset": "opai_bench",
        "hf_id": spec.hf_id,
        "licence": spec.licence,
        "preliminary": True,
        "config": CONFIG,
        "split": SPLIT,
        "sampling": "strided",
        "phase_shift": PHASE_SHIFT,
        "sampling_note": (
            f"strided offsets i*{SPLIT_TOTAL}//{N_ROWS}+{PHASE_SHIFT}: the "
            f"{N_ROWS}-grid shifted by half its step so the sample is "
            f"disjoint from the U1 {OLD_N_ROWS}-row strided sample by row "
            "index (verified by content hash below); never contiguous"
            + (
                f"; {len(excluded)} rows excluded as U1 duplicates by content hash "
                "(the same human document repeated once per generator)"
                if excluded
                else ""
            )
        ),
        "split_rows_total": SPLIT_TOTAL,
        "rows_fetched": N_ROWS,
        "rows_normalised": len(normalized),
        "rows_excluded_as_u1_duplicates": len(excluded),
        "excluded_u1_duplicates": excluded,
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
        "human_fpr_native": {
            "k_fp": k_fp,
            "n_human": n_human,
            "value": round(fpr_value, 4),
            "wilson_95_ci_lower": round(wilson_lo, 4),
            "wilson_95_ci_upper": round(wilson_hi, 4),
            "method": "wilson_ci (textforensics.probe_metrics), 95%",
        },
        "fpr_bar": {
            "n_human_minimum": 100,
            "wilson_upper_ceiling": 0.05,
            "passes": fpr_passes,
        },
        "disjointness": {
            "checked": True,
            "against": f"{DISJOINT_CONFIG}/{DISJOINT_SPLIT} (n={DISJOINT_N})",
            "disjoint": check_dev["disjoint"],
            "verified": check_dev["verified"],
            "shared_samples": check_dev["shared_samples"],
            "errors": check_dev["errors"],
        },
        "disjointness_vs_previous_sample": {
            "checked": True,
            "against": f"opai_bench/{CONFIG} train U1 sample (n={OLD_N_ROWS})",
            "disjoint": check_old["disjoint"],
            "verified": check_old["verified"],
            "shared_samples": check_old["shared_samples"],
            "errors": check_old["errors"],
        },
        "ai_sentence_ratio_values": sorted(
            {str(r.meta.get("ai_sentence_ratio")) for r in normalized}
        ),
    }
    if check_segments is not None:
        results["disjointness_vs_segment_cache"] = {
            "checked": True,
            "against": f"opai_bench/{CONFIG} {SEGMENTS_FILENAME} (U4, n=500)",
            "disjoint": check_segments["disjoint"],
            "verified": check_segments["verified"],
            "shared_samples": check_segments["shared_samples"],
            "errors": check_segments["errors"],
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
        {
            "item": f"{n_partial} partial (mixed-origin) rows",
            "reason": (
                "rows with 0 < ai_sentence_ratio < 1 carry no binary label; "
                "they are the U4 spine, not U1 evidence"
            ),
        },
    ]
    if excluded:
        drops.append(
            {
                "item": f"{len(excluded)} rows duplicating U1 human documents",
                "reason": (
                    "the OpAI-Bench train split repeats each pure-human v0 "
                    "document once per generator; these rows are byte-identical "
                    "to U1 rows (same document_hash_id, different record_id and "
                    "generator) and are excluded so the sample is disjoint from "
                    "U1 by content hash. Exclusion is by identity, never by "
                    "detector score."
                ),
            }
        )
    record = _base_record(RUN_ID, "command", "python scripts/measure_opai_bench_humans.py")
    record["results"] = results
    record["drops"] = drops
    record["badge"] = "available"
    path = _write_record(record, force)
    print(f"[opai] wrote {path.name} (sha256 {_sha256_file(path)})")

    # The normalised cache + manifest is the authoritative sample; the
    # raw checkpoint only duplicates it.
    checkpoint = default_cache_dir() / "opai_bench" / CONFIG / RAW_CHECKPOINT_FILENAME
    checkpoint.unlink(missing_ok=True)
    print(f"[opai] removed raw checkpoint {checkpoint.name}")
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
        f"[opai] done: n={results['rows_normalised']} "
        f"human={results['label_counts'].get('0')} ai={results['label_counts'].get('1')} "
        f"partial={results['label_counts'].get('None')} "
        f"auroc={results.get('auroc')} tpr@1%={results.get('tpr_at_1pct_fpr')} "
        f"tpr@5%={results.get('tpr_at_5pct_fpr')} "
        f"abstentions={results['detector_abstentions']} "
        f"k_fp={results['human_fpr_native']['k_fp']} "
        f"wilson_upper={results['human_fpr_native']['wilson_95_ci_upper']} "
        f"fpr_bar_passes={results['fpr_bar']['passes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
