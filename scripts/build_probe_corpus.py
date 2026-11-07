"""Build the frozen probe corpus v1.0.0 (U3, corpus half).

One-time build: fetches strided samples from the licensed datasets,
filters them into the 8 v1.0.0 slices, enforces content-hash
disjointness from every U1 validation sample, and writes the cache
files (corpus + holdback + manifest) under
``~/.cache/textforensics/probe-corpus/v1.0.0/``. The manifest is then
copied into the repo at ``docs/probe-corpus/v1.0.0/manifest.json`` by
hand after verification — this script never writes into the repo.

Sampling plan (deterministic striding, no randomness)
-----------------------------------------------------
* MAGE validation, n=401 strided over 56,792 rows — human-native
  (50 human rows) + ai-legacy-generator (50 machine rows; every MAGE
  generator is 2022-or-earlier, newest gpt-3.5-turbo) + benign-
  transformed bases (25 human + 25 machine rows not used elsewhere).
* RAID train, n=801 strided over 2,270,000 rows — ai-paraphrased
  (50 machine rows, attack=paraphrase) + ai-humanized (50 machine
  rows, attack=synonym; a lexical-evasion attack, i.e. machine text
  processed to look human). (n=601 yielded only 48 paraphrase rows:
  paraphrase is ~1/12 of attacks, so 601 strided rows is at the
  margin; 801 gives ~67 expected.)
* Beemo train, n=301 records strided over 2,187 records — human-short
  (50 human rows, kind=human, <100 words).
* OpAI-Bench dev, n=601 strided over 42,363 rows — mixed-origin
  (50 partial rows, version=v4, ai_sentence_ratio 0.5–0.55).
  (v4 is ~1/9 of rows; 503 strided rows would expect ~56, too
  close to 50 for comfort — 601 expects ~67.)
* DetectRL-X test, n=601 source rows strided over 48,000 (streaming
  pass over the cached, hash-verified file) — ai-current-generator
  (50 English machine rows; models deepseek-v3, gemini-2.5-flash,
  gpt-4o, qwen-max — current as of 2026-11-07). (English is ~1/8
  of source rows; 401 would expect ~50 with zero margin — 601
  expects ~75.)

The ``n`` values are deliberately off by one from the U1 sample sizes
(3000/400/100/500/400) so strided offsets almost never coincide with
a U1 offset; the content-hash exclusion is the real guarantee, the
``n`` choice only minimises wasted fetches.

Disjointness (research open question 4, decided: disjoint by content
hash). The exclusion set is every normalised row text in the cached
U1 samples (``~/.cache/textforensics/datasets/*/*.jsonl``). Any
candidate whose content hash is in that set — or already used by an
earlier slice — is dropped. The build refuses unless every slice
reaches exactly 50 items and the verified overlap is zero.

Licence gate. Every source passes ``require_licence`` before any row
is fetched (RAID MIT; MAGE Apache-2.0; Beemo MIT card + CC-BY-NC-4.0
carve-out; OpAI-Bench Apache-2.0; DetectRL-X non-commercial academic
research only). MixSet, DetectRL, M4, M4GT-Bench are not sourced.

Usage
-----
``python scripts/build_probe_corpus.py`` — full build (network).
``python scripts/build_probe_corpus.py --verify-only`` — verify the
existing cache files against the cached manifest (no network); this
is the freeze check: re-running the build from the manifest must
reproduce identical item hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime

from textforensics import probe_corpus as pc
from textforensics.datasets import (
    DatasetsServerClient,
    default_cache_dir,
    detectrl_x_raw_path,
    fetch_strided_sample,
    get_spec,
    map_row,
    sample_detectrl_x_rows,
    sample_offsets,
    verify_detectrl_x_file,
)

SLICE_N = 50
CACHE_VERSION_DIR = pc.default_probe_corpus_dir()

# (dataset key, config, split, n, expected_total) per fetch.
FETCH_PLAN: dict[str, tuple[str, str, str, int, int]] = {
    "mage": ("mage", "default", "validation", 401, 56_792),
    "raid": ("raid", "raid", "train", 801, 2_270_000),
    "beemo": ("beemo", "default", "train", 301, 2_187),
    "opai_bench": ("opai_bench", "default", "dev", 601, 42_363),
    "detectrl_x": ("detectrl_x", "binary", "test", 601, 48_000),
}


def _size_for(client: DatasetsServerClient, hf_id: str, config: str, split: str) -> int:
    """Live /size row count for one config/split; refuse on surprise."""
    size = client.size(hf_id)
    for entry in size.get("splits", []):
        if entry["config"] == config and entry["split"] == split:
            return int(entry["num_rows"])
    raise RuntimeError(f"datasets-server /size has no {config}/{split} for {hf_id}")


def _check_totals(client: DatasetsServerClient) -> None:
    """Refuse unless the server still reports the planned totals."""
    for key, (_, config, split, _, expected) in FETCH_PLAN.items():
        if key == "detectrl_x":
            continue  # whole-file dataset; counted from the file itself
        spec = get_spec(key)
        live = _size_for(client, spec.hf_id, config, split)
        if live != expected:
            raise RuntimeError(
                f"{key} {config}/{split}: server reports {live} rows, "
                f"plan expects {expected} — refusing to sample a stale plan"
            )
        print(f"  {key} {config}/{split}: total {live} (matches plan)")


def _u1_exclusion_hashes() -> set[str]:
    """Content hashes of every cached U1 sample row (the exclusion set)."""
    cache = default_cache_dir()
    excluded: set[str] = set()
    files = sorted(cache.glob("*/*/*.jsonl"))
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            text = json.loads(line)["text"]
            excluded.add(pc.content_sha256(text))
    print(f"  exclusion set: {len(excluded)} U1 row hashes from {len(files)} cache files")
    return excluded


def _pick(
    rows: list,
    want: int,
    predicate,
    excluded: set[str],
    used: set[str],
    label: str,
) -> list:
    """First ``want`` rows passing ``predicate`` and not excluded/used."""
    picked: list = []
    dropped_excluded = 0
    for row in rows:
        digest = pc.content_sha256(row.text)
        if digest in excluded:
            dropped_excluded += 1
            continue
        if digest in used:
            continue
        if not predicate(row):
            continue
        picked.append(row)
        used.add(digest)
        if len(picked) == want:
            break
    print(f"  {label}: picked {len(picked)}/{want} (dropped {dropped_excluded} U1 overlaps)")
    if len(picked) < want:
        raise RuntimeError(f"slice {label}: only {len(picked)} items, need {want}")
    return picked


def _to_item(row, slice_name: str, *, transform: str | None = None, base_hash: str | None = None):
    digest = pc.content_sha256(row.text)
    return pc.ProbeCorpusItem(
        item_id=pc.item_id(slice_name, digest),
        slice=slice_name,
        content_sha256=digest,
        word_count=pc.word_count(row.text),
        char_count=pc.char_count(row.text),
        lang="en",
        source_dataset=row.dataset,
        source_config=row.config,
        source_split=row.split,
        source_id=row.source_id,
        transform_name=transform,
        base_content_sha256=base_hash,
    )


def _label_entry(item: pc.ProbeCorpusItem, label, regime: str) -> dict:
    return {
        "item_id": item.item_id,
        "label": label,
        "regime": regime,
        "label_source": f"{item.source_dataset} mapper (see manifest sources)",
    }


def build() -> pc.ProbeCorpusManifest:
    """Fetch, filter, exclude, and write the cache files. Returns the manifest."""
    client = DatasetsServerClient()
    print("Checking /size totals against the plan...")
    _check_totals(client)
    excluded = _u1_exclusion_hashes()
    used: set[str] = set()
    items: list[pc.ProbeCorpusItem] = []
    labels: list[dict] = []
    corpus_texts: dict[str, str] = {}

    def _add(rows, slice_name: str, label, regime: str) -> None:
        for row in rows:
            item = _to_item(row, slice_name)
            items.append(item)
            labels.append(_label_entry(item, label, regime))
            corpus_texts[item.item_id] = row.text

    # --- MAGE validation (one fetch serves three slices) ---
    print("Fetching MAGE validation (n=401 strided)...")
    _, config, split, n, total = FETCH_PLAN["mage"]
    mage_rows = [
        mapped
        for raw in fetch_strided_sample(get_spec("mage"), config, split, n, total, client=client)
        for mapped in map_row("mage", raw, config, split)
    ]
    humans = _pick(mage_rows, SLICE_N, lambda r: r.label == 0, excluded, used, "human-native")
    _add(humans, "human-native", 0, "raw")
    legacy = _pick(
        mage_rows, SLICE_N, lambda r: r.label == 1, excluded, used, "ai-legacy-generator"
    )
    _add(legacy, "ai-legacy-generator", 1, "raw")

    # --- RAID train (one fetch serves two slices) ---
    print("Fetching RAID train (n=601 strided)...")
    _, config, split, n, total = FETCH_PLAN["raid"]
    raid_rows = [
        mapped
        for raw in fetch_strided_sample(get_spec("raid"), config, split, n, total, client=client)
        for mapped in map_row("raid", raw, config, split)
    ]
    paraphrased = _pick(
        raid_rows,
        SLICE_N,
        lambda r: r.label == 1 and r.meta.get("attack") == "paraphrase",
        excluded,
        used,
        "ai-paraphrased",
    )
    _add(paraphrased, "ai-paraphrased", 1, "raw")
    humanized = _pick(
        raid_rows,
        SLICE_N,
        lambda r: r.label == 1 and r.meta.get("attack") == "synonym",
        excluded,
        used,
        "ai-humanized",
    )
    _add(humanized, "ai-humanized", 1, "raw")

    # --- Beemo train ---
    print("Fetching Beemo train (n=301 records strided)...")
    _, config, split, n, total = FETCH_PLAN["beemo"]
    beemo_rows = [
        mapped
        for raw in fetch_strided_sample(get_spec("beemo"), config, split, n, total, client=client)
        for mapped in map_row("beemo", raw, config, split)
    ]
    short = _pick(
        beemo_rows,
        SLICE_N,
        lambda r: r.label == 0 and r.meta.get("kind") == "human" and pc.word_count(r.text) < 100,
        excluded,
        used,
        "human-short",
    )
    _add(short, "human-short", 0, "raw")

    # --- OpAI-Bench dev ---
    print("Fetching OpAI-Bench dev (n=503 strided)...")
    _, config, split, n, total = FETCH_PLAN["opai_bench"]
    opai_rows = [
        mapped
        for raw in fetch_strided_sample(
            get_spec("opai_bench"), config, split, n, total, client=client
        )
        for mapped in map_row("opai_bench", raw, config, split)
    ]
    mixed = _pick(
        opai_rows,
        SLICE_N,
        lambda r: r.label is None and r.meta.get("version") == "v4",
        excluded,
        used,
        "mixed-origin",
    )
    _add(mixed, "mixed-origin", None, "mixed-origin")

    # --- DetectRL-X test (streaming pass over the cached file) ---
    print("Sampling DetectRL-X test (n=401 source rows, streaming)...")
    _, config, split, n, total = FETCH_PLAN["detectrl_x"]
    dx_path = verify_detectrl_x_file(detectrl_x_raw_path())
    _, test_rows, counts = sample_detectrl_x_rows(dx_path, [], sample_offsets(total, n))
    if counts["test"] != total:
        raise RuntimeError(f"detectrl_x test count {counts['test']} != plan total {total}")
    dx_rows = [
        mapped
        for index, raw in test_rows
        for mapped in map_row("detectrl_x", raw, config, split, row_index=index)
    ]
    current = _pick(
        dx_rows,
        SLICE_N,
        lambda r: r.label == 1 and r.meta.get("lang") == "english",
        excluded,
        used,
        "ai-current-generator",
    )
    _add(current, "ai-current-generator", 1, "raw")

    # --- Benign-transformed: fresh MAGE bases, deterministic transforms ---
    print("Building benign-transformed slice from fresh MAGE bases...")
    base_pool = [
        r
        for r in mage_rows
        if pc.content_sha256(r.text) not in used and pc.content_sha256(r.text) not in excluded
    ]
    base_humans = [r for r in base_pool if r.label == 0][:25]
    base_machines = [r for r in base_pool if r.label == 1][:25]
    if len(base_humans) < 25 or len(base_machines) < 25:
        raise RuntimeError("benign-transformed: not enough fresh MAGE base rows")
    transformed = 0
    for base in base_humans + base_machines:
        base_hash = pc.content_sha256(base.text)
        for name in pc.BENIGN_TRANSFORMS:
            out = pc.apply_benign_transform(base.text, name)
            if out == base.text or pc.word_count(out) != pc.word_count(base.text):
                continue
            digest = pc.content_sha256(out)
            if digest in used or digest in excluded:
                continue
            item = pc.ProbeCorpusItem(
                item_id=pc.item_id("benign-transformed", digest),
                slice="benign-transformed",
                content_sha256=digest,
                word_count=pc.word_count(out),
                char_count=pc.char_count(out),
                lang="en",
                source_dataset=base.dataset,
                source_config=base.config,
                source_split=base.split,
                source_id=base.source_id,
                transform_name=name,
                base_content_sha256=base_hash,
            )
            items.append(item)
            labels.append(_label_entry(item, base.label, "raw"))
            corpus_texts[item.item_id] = out
            used.add(digest)
            transformed += 1
            break
        if transformed == SLICE_N:
            break
    print(f"  benign-transformed: built {transformed}/{SLICE_N}")
    if transformed < SLICE_N:
        raise RuntimeError("benign-transformed: not enough transformable base rows")

    # --- Write the cache files ---
    out_dir = CACHE_VERSION_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    corpus_path = out_dir / pc.CORPUS_FILE_NAME
    holdback_path = out_dir / pc.HOLDBACK_FILE_NAME
    manifest_path = out_dir / pc.MANIFEST_FILE_NAME
    ordered_items = sorted(items, key=lambda item: item.item_id)
    corpus_lines = [
        pc.canonical_json(
            {
                "item_id": item.item_id,
                "slice": item.slice,
                "text": corpus_texts[item.item_id],
                "source_dataset": item.source_dataset,
                "source_config": item.source_config,
                "source_split": item.source_split,
                "source_id": item.source_id,
            }
        )
        for item in ordered_items
    ]
    corpus_bytes = ("\n".join(corpus_lines) + "\n").encode("utf-8")
    holdback_lines = [
        pc.canonical_json(entry) for entry in sorted(labels, key=lambda entry: entry["item_id"])
    ]
    holdback_bytes = ("\n".join(holdback_lines) + "\n").encode("utf-8")
    corpus_path.write_bytes(corpus_bytes)
    holdback_path.write_bytes(holdback_bytes)

    sources = _sources_record()
    manifest = pc.build_manifest(
        items=ordered_items,
        created_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        holdback_sha256=hashlib.sha256(holdback_bytes).hexdigest(),
        corpus_file_sha256=hashlib.sha256(corpus_bytes).hexdigest(),
        sources=sources,
        current_generators={
            "as_of": pc.CURRENT_GENERATORS_AS_OF,
            "generators": list(pc.CURRENT_GENERATORS),
            "source": "DetectRL-X Binary file models (deepseek-v3, gemini-2.5-flash, "
            "gpt-4o, qwen-max), verified live 2026-11-07",
            "recheck": "monthly via the U3 cadence",
        },
        notes=[
            "human-non-native/esl slice CUT in v1.0.0: no licensed source in the "
            "resolved set labels ESL ground truth; resolving an ESL-labelled "
            "dataset (licence first) is a follow-up for the full U3 coordinator.",
            "Per-slice n=50 meets the drift-signal minimum; n>=100 per slice is "
            "required before any human-FPR claim is attached to that slice, so "
            "v1.0.0 carries no human-FPR claim on any slice.",
            "No 2026 source was found prescribing an exact probe-corpus size for "
            "AI-text detectors specifically; n=400 is judgement from statistical "
            "constraints (Wilson CI, n>=100 for 1% FPR), not a literature "
            "prescription.",
            "Corpus items are disjoint by content hash from every row measured "
            "for a U1 validation record; verified overlap is zero.",
            "Beemo (CC-BY-NC-4.0 carve-out) and DetectRL-X (non-commercial "
            "academic research only) items make this corpus non-redistributable; "
            "it lives in the local cache only, never in the repo.",
            "The freeze guarantee is items_sha256: re-running this build from "
            "the manifest reproduces identical item hashes (created_at_utc "
            "records the build date and is the only field that changes).",
        ],
    )
    pc.write_manifest(manifest_path, manifest)
    problems = pc.verify_corpus_files(corpus_path, holdback_path, manifest)
    if problems:
        raise RuntimeError(f"built corpus failed verification: {problems}")
    print(
        f"Corpus v{manifest.version}: {len(manifest.items)} items, slices {manifest.slice_counts()}"
    )
    print(f"items_sha256: {manifest.items_sha256}")
    print(f"holdback_sha256: {manifest.holdback_sha256}")
    print(f"corpus_file_sha256: {manifest.corpus_file_sha256}")
    print(f"Wrote {corpus_path}, {holdback_path}, {manifest_path}")
    return manifest


def _sources_record() -> dict:
    """Per-slice provenance: dataset, licence, sampling plan, filter."""
    specs = {key: get_spec(key) for key in ("mage", "raid", "beemo", "opai_bench", "detectrl_x")}
    record: dict = {}
    for slice_name, key, filter_rule in (
        ("human-native", "mage", "label == 0 (human)"),
        (
            "ai-legacy-generator",
            "mage",
            "label == 1 (machine); every MAGE generator is 2022-or-earlier, newest gpt-3.5-turbo",
        ),
        ("ai-paraphrased", "raid", "label == 1 and meta.attack == 'paraphrase'"),
        (
            "ai-humanized",
            "raid",
            "label == 1 and meta.attack == 'synonym' "
            "(lexical-evasion attack: machine text processed to look human)",
        ),
        ("human-short", "beemo", "label == 0, kind == 'human', word count < 100"),
        (
            "mixed-origin",
            "opai_bench",
            "label is None and meta.version == 'v4' (ai_sentence_ratio 0.5-0.55)",
        ),
        ("ai-current-generator", "detectrl_x", "label == 1 and meta.lang == 'english'"),
        (
            "benign-transformed",
            "mage",
            "fresh MAGE validation rows (25 human + 25 "
            "machine) with a deterministic benign transform applied; transform and "
            "base hash recorded per item",
        ),
    ):
        _, config, split, n, total = FETCH_PLAN[key]
        spec = specs[key]
        record[slice_name] = {
            "dataset": key,
            "hf_id": spec.hf_id,
            "config": config,
            "split": split,
            "licence": spec.licence,
            "licence_status": spec.licence_status,
            "sampling": {"method": "strided", "n": n, "total": total},
            "filter": filter_rule,
        }
    return record


def verify_only() -> None:
    """Freeze check: verify the existing cache files against the manifest."""
    out_dir = CACHE_VERSION_DIR
    manifest = pc.load_manifest(out_dir / pc.MANIFEST_FILE_NAME)
    problems = pc.verify_corpus_files(
        out_dir / pc.CORPUS_FILE_NAME, out_dir / pc.HOLDBACK_FILE_NAME, manifest
    )
    if problems:
        raise RuntimeError(f"corpus verification failed: {problems}")
    print(
        f"Corpus v{manifest.version} verifies: {len(manifest.items)} items, "
        f"slices {manifest.slice_counts()}"
    )
    print(f"items_sha256: {manifest.items_sha256}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify the existing cache files against the manifest (no network).",
    )
    args = parser.parse_args(argv)
    try:
        if args.verify_only:
            verify_only()
        else:
            build()
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
