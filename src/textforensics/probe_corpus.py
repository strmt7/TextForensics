"""Frozen probe corpus for the U3 drift observatory — corpus half only.

The probe corpus is the labelled, frozen anchor set the drift observatory
re-runs on its cadence. It is built once (``probe-corpus v1.0.0``) and never
edited in place: any change produces a new version, never a mutation of
this one (append-only versioning, research §7.6).

Design rules
------------
* Content-addressed. Every item is identified by the SHA-256 of its exact
  text bytes (UTF-8); the manifest records the SHA-256 of the canonical
  JSON of the whole item list. Re-running the build from the manifest
  must reproduce identical hashes — that is the freeze check.
* Labels live in a separate holdback file. The corpus file carries item
  id, slice, text and source metadata — never a binary label. The
  holdback file (``holdback.jsonl``) carries ``item_id -> label`` and is
  read only after scoring. Slice membership is a *selection* property
  (the cadence needs it to pick attacked slices for a monthly run); the
  binary ground-truth label is what is held back. Note the honest limit:
  slice membership leaks the coarse label for most slices (a
  ``human-native`` item is human); the holdback's job is to keep the
  exact label and its provenance out of the scoring path, and to keep
  the corpus file from being usable as a labelled training set.
* Corpus data lives in the local cache, never in the repo. Only the
  manifest (hashes, counts, slices, licences, sampling plan) is
  committed — under ``docs/probe-corpus/v1.0.0/manifest.json``. Corpus
  text is real text from licensed datasets; it is not a portable output
  and must not leak into case files, bundles, or docs. No raw corpus
  text appears in any report — item ids + hashes only.
* Licence gate. Every corpus source passes through the datasets
  licence gate (``textforensics.datasets.require_licence``) before any
  row is fetched. The sources used in v1.0.0 are exactly the resolved
  ones: RAID (MIT), MAGE (Apache-2.0), Beemo (MIT card + CC-BY-NC-4.0
  carve-out), OpAI-Bench (Apache-2.0), DetectRL-X (non-commercial
  academic research only — strictest reading governs). MixSet,
  DetectRL, M4 and M4GT-Bench have no licence anywhere and are NOT
  sourced. GhostWriter (per-domain licences) is a recorded alternate
  source, unused in v1.0.0.
* Disjoint from U1 validation samples. Corpus items are disjoint by
  content hash from every row measured for a U1 validation record (the
  cached U1 samples in ``~/.cache/textforensics/datasets``). The
  observatory is an independent check on the validation evidence, not
  a re-measurement of the same rows. The builder enforces this and
  records the verified overlap (zero) in the manifest.
* Slices. v1.0.0 ships 8 of the 9 prescribed slices at n=50 each
  (n=400 total). The ninth slice, human-non-native/ESL, is CUT in
  v1.0.0: no licensed source in the resolved set labels ESL ground
  truth, and inventing ESL labels from unlabelled text would be a lie.
  Cutting a slice is explicitly permitted by the research ("if budget
  forces cuts, cut *slices*, never below n=50 within a retained
  slice"). Resolving an ESL-labelled dataset (licence first) is a
  defined follow-up for the full U3 coordinator. Per-slice n=50 meets
  the drift-signal minimum; n>=100 per slice is required before any
  human-FPR claim is attached to that slice (Wilson CI arithmetic) —
  so v1.0.0 carries NO human-FPR claim on any slice.
* Current-generator slice. The current-generator list is dated
  ("current as of 2026-11-07") and re-checked monthly via the U3
  cadence; a fixed list is a staleness bug by construction (research
  §13 decision 8).
* No 2026 source was found prescribing an exact probe-corpus size for
  AI-text detectors specifically — n≈300–500 is judgement from
  statistical constraints (Wilson CI, n>=100 for 1% FPR), not a
  literature prescription. The report says so.

This module is the corpus half of U3 only. It does NOT implement
alerting, demotion, cadence, or any observatory run — those belong to
the full U3 coordinator (after U2 lands) and live in
``observatory.py`` / ``validation.py``, which this module never touches.
The per-run metric functions live in ``probe_metrics.py`` as pure
functions over supplied scores.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from textforensics.datasets import default_cache_dir

PROBE_CORPUS_VERSION = "1.0.0"
PROBE_CORPUS_DIR_NAME = "probe-corpus"
CORPUS_FILE_NAME = "corpus.jsonl"
HOLDBACK_FILE_NAME = "holdback.jsonl"
MANIFEST_FILE_NAME = "manifest.json"

# The 8 slices shipped in v1.0.0, in manifest order. The ninth
# prescribed slice (human-non-native/esl) is cut — see the module
# docstring. Slice names are stable identifiers; never rename one.
SLICES: tuple[str, ...] = (
    "human-native",
    "human-short",
    "ai-current-generator",
    "ai-legacy-generator",
    "ai-paraphrased",
    "ai-humanized",
    "mixed-origin",
    "benign-transformed",
)

# Per-slice minimum for drift-signal purposes (research §7.6).
MIN_SLICE_N = 50
# Per-slice minimum before any human-FPR claim on that slice.
MIN_SLICE_N_FOR_FPR_CLAIM = 100

# Current-generator list, dated. Source: DetectRL-X Binary file
# (models verified live 2026-11-07). Re-checked monthly via the U3
# cadence; this list going stale is a known failure mode, not a
# surprise.
CURRENT_GENERATORS_AS_OF = "2026-11-07"
CURRENT_GENERATORS: tuple[str, ...] = (
    "deepseek-v3",
    "gemini-2.5-flash",
    "gpt-4o",
    "qwen-max",
)

# Benign transforms for the benign-transformed slice. Each is a
# formatting-only change: it must never alter word count or meaning.
# A transform that leaves a given text byte-identical is skipped for
# that item (the builder tries the next one); the transform actually
# applied is recorded per item with its base-text hash. The first
# five fire only when the text already contains the targeted
# artifact (double spaces, newlines, curly quotes, compatibility
# characters, trailing whitespace) — clean single-paragraph ASCII
# text passes through all of them unchanged, which is why the list
# also carries high-coverage transforms (double space after a
# sentence-ending mark, curly apostrophes, unicode ellipsis/dash)
# and a universal last resort (trailing newline). Order matters: the
# builder tries them in this order and records the first one that
# changes the text.
BENIGN_TRANSFORMS: tuple[str, ...] = (
    "whitespace_collapse",
    "linebreak_normalise",
    "quote_straighten",
    "nfkc_normalise",
    "trailing_strip",
    "double_space_after_period",
    "apostrophe_curly",
    "ellipsis_unicode",
    "em_dash",
    "trailing_newline",
)

_HEX_64 = frozenset("0123456789abcdef")


def canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, tight separators, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_sha256(text: str) -> str:
    """SHA-256 of the exact item text bytes (UTF-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def word_count(text: str) -> int:
    """Word count: whitespace-split tokens. One definition, used everywhere."""
    return len(text.split())


def char_count(text: str) -> int:
    """Character count (Unicode code points)."""
    return len(text)


def item_id(slice_name: str, text_hash: str) -> str:
    """Stable, content-addressed item id: ``pc100-<slice>-<sha16>``."""
    return f"pc100-{slice_name}-{text_hash[:16]}"


def default_probe_corpus_dir(
    *, version: str = PROBE_CORPUS_VERSION, cache_dir: Path | None = None
) -> Path:
    """Local cache directory for one corpus version (never in the repo)."""
    base = cache_dir or default_cache_dir().parent
    return Path(base) / PROBE_CORPUS_DIR_NAME / version


def apply_benign_transform(text: str, name: str) -> str:
    """Apply one documented benign (formatting-only) transform.

    Pure function; raises ValueError on an unknown transform name.
    Every transform preserves word count — the caller must verify
    that, and must verify the result differs from the input (a
    no-op transform is skipped for that item, never recorded).
    """
    if name == "whitespace_collapse":
        return " ".join(text.split())
    if name == "linebreak_normalise":
        return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ")
    if name == "quote_straighten":
        return (
            text.replace("\u201c", '"')
            .replace("\u201d", '"')
            .replace("\u2018", "'")
            .replace("\u2019", "'")
        )
    if name == "nfkc_normalise":
        return unicodedata.normalize("NFKC", text)
    if name == "trailing_strip":
        return "\n".join(line.rstrip() for line in text.split("\n"))
    if name == "double_space_after_period":
        return re.sub(r"([.!?]) ", r"\1  ", text)
    if name == "apostrophe_curly":
        return text.replace("'", "\u2019")
    if name == "ellipsis_unicode":
        return text.replace("...", "\u2026")
    if name == "em_dash":
        return text.replace(" -- ", " \u2014 ")
    if name == "trailing_newline":
        return text if text.endswith("\n") else text + "\n"
    raise ValueError(f"unknown benign transform: {name!r}")


@dataclass(frozen=True)
class ProbeCorpusItem:
    """One frozen probe-corpus item (metadata only — no label, no text).

    ``text`` itself lives only in the cache corpus file; this record
    carries the content hash so the item is verifiable without the
    text. ``transform_name`` / ``base_content_sha256`` are set only
    for benign-transformed items (the transform applied + the hash of
    the untransformed base text).
    """

    item_id: str
    slice: str
    content_sha256: str
    word_count: int
    char_count: int
    lang: str
    source_dataset: str
    source_config: str
    source_split: str
    source_id: str
    transform_name: str | None = None
    base_content_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the manifest (canonical JSON sorts the keys)."""
        return {
            "item_id": self.item_id,
            "slice": self.slice,
            "content_sha256": self.content_sha256,
            "word_count": self.word_count,
            "char_count": self.char_count,
            "lang": self.lang,
            "source_dataset": self.source_dataset,
            "source_config": self.source_config,
            "source_split": self.source_split,
            "source_id": self.source_id,
            "transform_name": self.transform_name,
            "base_content_sha256": self.base_content_sha256,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProbeCorpusItem:
        """Parse one manifest item; unknown keys fail closed."""
        known = {
            "item_id",
            "slice",
            "content_sha256",
            "word_count",
            "char_count",
            "lang",
            "source_dataset",
            "source_config",
            "source_split",
            "source_id",
            "transform_name",
            "base_content_sha256",
        }
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"probe corpus item has unknown keys: {sorted(unknown)}")
        return cls(
            item_id=str(data["item_id"]),
            slice=str(data["slice"]),
            content_sha256=str(data["content_sha256"]),
            word_count=int(data["word_count"]),
            char_count=int(data["char_count"]),
            lang=str(data["lang"]),
            source_dataset=str(data["source_dataset"]),
            source_config=str(data["source_config"]),
            source_split=str(data["source_split"]),
            source_id=str(data["source_id"]),
            transform_name=data.get("transform_name"),
            base_content_sha256=data.get("base_content_sha256"),
        )


@dataclass(frozen=True)
class ProbeCorpusManifest:
    """The frozen manifest for one probe-corpus version.

    ``items_sha256`` is the SHA-256 of the canonical JSON of the
    item list (sorted by item_id) — the freeze fingerprint. Any
    change to any item changes it; a new corpus version gets a new
    manifest, never an edit of this one. ``holdback_sha256`` is the
    SHA-256 of the holdback file bytes; ``corpus_file_sha256`` the
    SHA-256 of the corpus file bytes. ``sources`` records, per slice,
    the dataset, licence, sampling plan and filter that produced the
    items, so a rebuild from this manifest reproduces identical
    hashes.
    """

    version: str
    created_at_utc: str
    items: tuple[ProbeCorpusItem, ...]
    items_sha256: str
    holdback_sha256: str
    corpus_file_sha256: str
    sources: dict[str, Any]
    current_generators: dict[str, Any]
    notes: tuple[str, ...] = ()

    def compute_items_sha256(self) -> str:
        """Recompute the freeze fingerprint from the item list."""
        ordered = sorted((item.to_dict() for item in self.items), key=lambda d: d["item_id"])
        return hashlib.sha256(canonical_json(ordered).encode("utf-8")).hexdigest()

    def slice_counts(self) -> dict[str, int]:
        """Item count per slice (slices with zero items included)."""
        counts = {name: 0 for name in SLICES}
        for item in self.items:
            counts[item.slice] = counts.get(item.slice, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the manifest file (canonical JSON sorts keys)."""
        return {
            "version": self.version,
            "created_at_utc": self.created_at_utc,
            "format": "textforensics.probe-corpus/v1",
            "items": [item.to_dict() for item in sorted(self.items, key=lambda i: i.item_id)],
            "items_sha256": self.items_sha256,
            "holdback_sha256": self.holdback_sha256,
            "corpus_file_sha256": self.corpus_file_sha256,
            "sources": self.sources,
            "current_generators": self.current_generators,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProbeCorpusManifest:
        """Parse a manifest dict; unknown top-level keys fail closed."""
        known = {
            "version",
            "created_at_utc",
            "format",
            "items",
            "items_sha256",
            "holdback_sha256",
            "corpus_file_sha256",
            "sources",
            "current_generators",
            "notes",
        }
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"probe corpus manifest has unknown keys: {sorted(unknown)}")
        if data.get("format") != "textforensics.probe-corpus/v1":
            raise ValueError(f"unsupported probe corpus format: {data.get('format')!r}")
        # Canonical order is sorted by item_id (what to_dict writes);
        # restore it so a round trip is exact.
        items = sorted(
            (ProbeCorpusItem.from_dict(item) for item in data["items"]),
            key=lambda item: item.item_id,
        )
        return cls(
            version=str(data["version"]),
            created_at_utc=str(data["created_at_utc"]),
            items=tuple(items),
            items_sha256=str(data["items_sha256"]),
            holdback_sha256=str(data["holdback_sha256"]),
            corpus_file_sha256=str(data["corpus_file_sha256"]),
            sources=dict(data["sources"]),
            current_generators=dict(data["current_generators"]),
            notes=tuple(str(note) for note in data.get("notes", [])),
        )


def build_manifest(
    *,
    items: list[ProbeCorpusItem],
    created_at_utc: str,
    holdback_sha256: str,
    corpus_file_sha256: str,
    sources: dict[str, Any],
    current_generators: dict[str, Any],
    notes: list[str],
    version: str = PROBE_CORPUS_VERSION,
) -> ProbeCorpusManifest:
    """Assemble a manifest, computing the freeze fingerprint.

    Items are stored in canonical order (sorted by item_id), so the
    in-memory manifest always equals its parsed file form.
    """
    manifest = ProbeCorpusManifest(
        version=version,
        created_at_utc=created_at_utc,
        items=tuple(sorted(items, key=lambda item: item.item_id)),
        items_sha256="",
        holdback_sha256=holdback_sha256,
        corpus_file_sha256=corpus_file_sha256,
        sources=sources,
        current_generators=current_generators,
        notes=tuple(notes),
    )
    fingerprint = manifest.compute_items_sha256()
    return ProbeCorpusManifest(
        version=manifest.version,
        created_at_utc=manifest.created_at_utc,
        items=manifest.items,
        items_sha256=fingerprint,
        holdback_sha256=manifest.holdback_sha256,
        corpus_file_sha256=manifest.corpus_file_sha256,
        sources=manifest.sources,
        current_generators=manifest.current_generators,
        notes=manifest.notes,
    )


def verify_manifest(manifest: ProbeCorpusManifest) -> list[str]:
    """Check a manifest's self-consistency (no cache needed).

    Returns the list of problems; empty means valid. Checks: the
    freeze fingerprint recomputes; the version is the shipped one;
    every slice present in ``SLICES`` holds at least ``MIN_SLICE_N``
    items; no slice outside ``SLICES`` appears; item ids are unique;
    every content hash is 64 lowercase hex; transformed items record
    both a transform name and a base hash, and only transformed items
    do; word/char counts are positive.
    """
    problems: list[str] = []
    if manifest.version != PROBE_CORPUS_VERSION:
        problems.append(f"version {manifest.version!r} != {PROBE_CORPUS_VERSION!r}")
    if manifest.items_sha256 != manifest.compute_items_sha256():
        problems.append("items_sha256 does not match the item list (manifest tampered or stale)")
    for name, digest in (
        ("holdback_sha256", manifest.holdback_sha256),
        ("corpus_file_sha256", manifest.corpus_file_sha256),
        ("items_sha256", manifest.items_sha256),
    ):
        if len(digest) != 64 or not set(digest) <= _HEX_64:
            problems.append(f"{name} is not a 64-char lowercase hex SHA-256")
    counts = manifest.slice_counts()
    for name in SLICES:
        if counts[name] < MIN_SLICE_N:
            problems.append(f"slice {name!r} has {counts[name]} items, below minimum {MIN_SLICE_N}")
    seen: set[str] = set()
    for item in manifest.items:
        if item.item_id in seen:
            problems.append(f"duplicate item_id: {item.item_id}")
        seen.add(item.item_id)
        if item.slice not in SLICES:
            problems.append(f"item {item.item_id} has unknown slice {item.slice!r}")
        if len(item.content_sha256) != 64 or not set(item.content_sha256) <= _HEX_64:
            problems.append(f"item {item.item_id} has a malformed content_sha256")
        if item.word_count <= 0 or item.char_count <= 0:
            problems.append(f"item {item.item_id} has a non-positive count")
        if item.transform_name is None and item.base_content_sha256 is not None:
            problems.append(f"item {item.item_id} has a base hash but no transform")
        if item.transform_name is not None:
            if item.transform_name not in BENIGN_TRANSFORMS:
                problems.append(
                    f"item {item.item_id} has unknown transform {item.transform_name!r}"
                )
            if item.base_content_sha256 is None:
                problems.append(f"item {item.item_id} has a transform but no base hash")
        expected_id = item_id(item.slice, item.content_sha256)
        if item.item_id != expected_id:
            problems.append(
                f"item {item.item_id} does not match its content-addressed id {expected_id}"
            )
    return problems


def load_corpus_texts(corpus_path: Path) -> dict[str, str]:
    """Read the corpus file: ``item_id -> text``. No labels live here."""
    texts: dict[str, str] = {}
    for line in Path(corpus_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        item = str(record["item_id"])
        if item in texts:
            raise ValueError(f"corpus file has duplicate item_id: {item}")
        texts[item] = str(record["text"])
    return texts


def load_holdback(holdback_path: Path) -> dict[str, dict[str, Any]]:
    """Read the holdback file: ``item_id -> {label, regime, ...}``.

    Call this only after scoring. The label may be ``None`` for
    mixed-origin items (no binary label exists for them); the *key*
    must still be present for every corpus item.
    """
    labels: dict[str, dict[str, Any]] = {}
    for line in Path(holdback_path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        item = str(record["item_id"])
        if item in labels:
            raise ValueError(f"holdback file has duplicate item_id: {item}")
        label = record["label"]
        if label is not None and label not in (0, 1):
            raise ValueError(f"holdback entry {item} has bad label {label!r}")
        labels[item] = record
    return labels


def verify_corpus_files(
    corpus_path: Path, holdback_path: Path, manifest: ProbeCorpusManifest
) -> list[str]:
    """Verify cache files against the manifest (needs the cache).

    Re-hashes every corpus text and the holdback file bytes, checks
    the corpus file hash, checks every manifest item has exactly one
    text and one holdback entry, and checks the holdback covers the
    manifest exactly. Returns the list of problems; empty means the
    frozen corpus verifies.
    """
    problems = list(verify_manifest(manifest))
    corpus_bytes = Path(corpus_path).read_bytes()
    if hashlib.sha256(corpus_bytes).hexdigest() != manifest.corpus_file_sha256:
        problems.append("corpus file SHA-256 does not match the manifest")
    holdback_bytes = Path(holdback_path).read_bytes()
    if hashlib.sha256(holdback_bytes).hexdigest() != manifest.holdback_sha256:
        problems.append("holdback file SHA-256 does not match the manifest")
    try:
        texts = load_corpus_texts(corpus_path)
    except (ValueError, KeyError) as exc:
        return problems + [f"corpus file unreadable: {exc}"]
    try:
        labels = load_holdback(holdback_path)
    except (ValueError, KeyError) as exc:
        return problems + [f"holdback file unreadable: {exc}"]
    manifest_ids = {item.item_id for item in manifest.items}
    if set(texts) != manifest_ids:
        problems.append(
            "corpus file item ids do not match the manifest "
            f"(extra: {sorted(set(texts) - manifest_ids)[:3]}, "
            f"missing: {sorted(manifest_ids - set(texts))[:3]})"
        )
    if set(labels) != manifest_ids:
        problems.append("holdback entries do not cover the manifest items exactly")
    for item in manifest.items:
        text = texts.get(item.item_id)
        if text is None:
            continue
        if content_sha256(text) != item.content_sha256:
            problems.append(f"item {item.item_id} text hash mismatch (corpus tampered)")
        if word_count(text) != item.word_count or char_count(text) != item.char_count:
            problems.append(f"item {item.item_id} counts do not match its text")
    return problems


def load_manifest(path: Path) -> ProbeCorpusManifest:
    """Read and parse a manifest file."""
    return ProbeCorpusManifest.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def write_manifest(path: Path, manifest: ProbeCorpusManifest) -> None:
    """Write a manifest as sorted, indented JSON + trailing newline.

    The freeze fingerprint (``items_sha256``) is computed over the
    canonical JSON of the item list, not over the file bytes, so the
    file formatting is free — indented JSON keeps per-item diffs
    readable and gives each hash its own line (the detect-secrets
    baseline audit keys entries by filename + line number).
    """
    Path(path).write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
