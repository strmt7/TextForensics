"""Tests for the frozen probe corpus (U3, corpus half).

All fixtures are synthetic: no live data, no network, no cache.
The committed manifest is verified structurally by
``test_committed_manifest`` only when it exists (it is written by
the corpus build, not by this module).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from textforensics import probe_corpus as pc


def _item(
    slice_name: str = "human-native",
    text: str = "Some human text here.",
    **overrides,
) -> pc.ProbeCorpusItem:
    digest = pc.content_sha256(text)
    fields = {
        "item_id": pc.item_id(slice_name, digest),
        "slice": slice_name,
        "content_sha256": digest,
        "word_count": pc.word_count(text),
        "char_count": pc.char_count(text),
        "lang": "en",
        "source_dataset": "mage",
        "source_config": "default",
        "source_split": "validation",
        "source_id": f"mage:{digest[:16]}",
    }
    fields.update(overrides)
    return pc.ProbeCorpusItem(**fields)


def _manifest(items, **overrides) -> pc.ProbeCorpusManifest:
    fields = {
        "created_at_utc": "2026-11-07T00:00:00Z",
        "holdback_sha256": "0" * 64,
        "corpus_file_sha256": "1" * 64,
        "sources": {"human-native": {"dataset": "mage", "licence": "Apache-2.0"}},
        "current_generators": {
            "as_of": pc.CURRENT_GENERATORS_AS_OF,
            "generators": list(pc.CURRENT_GENERATORS),
        },
        "notes": ["synthetic fixture"],
    }
    fields.update(overrides)
    return pc.build_manifest(items=list(items), **fields)


def _full_manifest() -> pc.ProbeCorpusManifest:
    items = [
        _item(slice_name=name, text=f"Probe text for slice {name} number {i}.")
        for name in pc.SLICES
        for i in range(pc.MIN_SLICE_N)
    ]
    return _manifest(items)


def test_word_count_and_hashes_are_stable():
    text = "one  two\nthree"
    assert pc.word_count(text) == 3
    assert pc.char_count(text) == len(text)
    assert pc.content_sha256(text) == hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert pc.content_sha256(text) == pc.content_sha256(text)


def test_item_id_is_content_addressed():
    digest = pc.content_sha256("abc")
    assert pc.item_id("human-native", digest) == f"pc100-human-native-{digest[:16]}"


def test_benign_transforms_preserve_words_and_change_bytes():
    text = "“Hello”  world!\nSecond line.  "
    for name in pc.BENIGN_TRANSFORMS:
        out = pc.apply_benign_transform(text, name)
        assert pc.word_count(out) == pc.word_count(text), name
    assert pc.apply_benign_transform("a  b", "whitespace_collapse") == "a b"
    assert pc.apply_benign_transform("a\nb", "linebreak_normalise") == "a b"
    assert pc.apply_benign_transform("\u201chi\u201d", "quote_straighten") == '"hi"'
    assert pc.apply_benign_transform("a  \nb", "trailing_strip") == "a\nb"
    assert pc.apply_benign_transform("ﬁsh", "nfkc_normalise") == "fish"
    assert pc.apply_benign_transform("Hi there. You ok.", "double_space_after_period") == (
        "Hi there.  You ok."
    )
    assert pc.apply_benign_transform("don't", "apostrophe_curly") == "don\u2019t"
    assert pc.apply_benign_transform("wait...", "ellipsis_unicode") == "wait\u2026"
    assert pc.apply_benign_transform("a -- b", "em_dash") == "a \u2014 b"
    assert pc.apply_benign_transform("abc", "trailing_newline") == "abc\n"
    assert pc.apply_benign_transform("abc\n", "trailing_newline") == "abc\n"
    # Every transform preserves word count on a realistic text, and at
    # least one of them changes any ordinary English text (the builder
    # relies on this: it records the first transform that changes the
    # text, and skips the item only if none does).
    realistic = "Don't wait... the first sentence ends here. A second one follows -- truly."
    changed = [
        name
        for name in pc.BENIGN_TRANSFORMS
        if pc.apply_benign_transform(realistic, name) != realistic
    ]
    assert changed, "no benign transform fires on ordinary text"
    for name in changed:
        assert pc.word_count(pc.apply_benign_transform(realistic, name)) == pc.word_count(realistic)
    with pytest.raises(ValueError):
        pc.apply_benign_transform(text, "not-a-transform")


def test_manifest_round_trip_and_fingerprint():
    manifest = _full_manifest()
    assert manifest.items_sha256 == manifest.compute_items_sha256()
    assert pc.verify_manifest(manifest) == []
    data = json.loads(pc.canonical_json(manifest.to_dict()))
    assert pc.ProbeCorpusManifest.from_dict(data) == manifest


def test_verify_manifest_catches_tamper():
    manifest = _full_manifest()
    tampered = pc.ProbeCorpusManifest(
        version=manifest.version,
        created_at_utc=manifest.created_at_utc,
        items=manifest.items,
        items_sha256="f" * 64,
        holdback_sha256=manifest.holdback_sha256,
        corpus_file_sha256=manifest.corpus_file_sha256,
        sources=manifest.sources,
        current_generators=manifest.current_generators,
        notes=manifest.notes,
    )
    problems = pc.verify_manifest(tampered)
    assert any("items_sha256" in p for p in problems)


def test_verify_manifest_catches_small_slice():
    items = [
        _item(slice_name=name, text=f"Text {name} {i}.") for name in pc.SLICES for i in range(10)
    ]
    manifest = _manifest(items)
    problems = pc.verify_manifest(manifest)
    assert any("below minimum" in p for p in problems)


def test_verify_manifest_catches_duplicate_and_bad_transform():
    first = _item(text="Same text.")
    second = _item(slice_name="human-short", text="Same text.")
    # Same text in two slices: identical content hash but different
    # item id (slice is part of the id) — allowed. A true duplicate
    # (same slice + same text) must be caught.
    dup = _item(text="Same text.")
    manifest = _manifest([first, dup, second])
    problems = pc.verify_manifest(manifest)
    assert any("duplicate item_id" in p for p in problems)

    bad = _item(
        slice_name="benign-transformed",
        text="Transformed text here.",
        transform_name="whitespace_collapse",
        base_content_sha256=None,
    )
    manifest = _manifest([bad])
    assert any("no base hash" in p for p in pc.verify_manifest(manifest))


def test_item_from_dict_rejects_unknown_keys():
    with pytest.raises(ValueError):
        pc.ProbeCorpusItem.from_dict({**_item().to_dict(), "surprise": 1})


def test_manifest_from_dict_rejects_unknown_format():
    data = _full_manifest().to_dict()
    data["format"] = "something-else/v9"
    with pytest.raises(ValueError):
        pc.ProbeCorpusManifest.from_dict(data)


def test_corpus_files_verify_exact_match(tmp_path: Path):
    # Build items from real texts, then write matching files: the
    # freeze check must pass end to end.
    items: list[pc.ProbeCorpusItem] = []
    corpus_lines: list[str] = []
    for name in pc.SLICES:
        for i in range(pc.MIN_SLICE_N):
            text = f"Exact probe text {name} {i}."
            items.append(_item(slice_name=name, text=text))
            corpus_lines.append(json.dumps({"item_id": items[-1].item_id, "text": text}))
    holdback_lines = [
        json.dumps({"item_id": item.item_id, "label": 0, "regime": "raw"}) for item in items
    ]
    corpus_bytes = ("\n".join(corpus_lines) + "\n").encode("utf-8")
    holdback_bytes = ("\n".join(holdback_lines) + "\n").encode("utf-8")
    manifest = pc.build_manifest(
        items=items,
        created_at_utc="2026-11-07T00:00:00Z",
        holdback_sha256=hashlib.sha256(holdback_bytes).hexdigest(),
        corpus_file_sha256=hashlib.sha256(corpus_bytes).hexdigest(),
        sources={name: {"dataset": "mage"} for name in pc.SLICES},
        current_generators={"as_of": pc.CURRENT_GENERATORS_AS_OF},
        notes=[],
    )
    corpus_path = tmp_path / pc.CORPUS_FILE_NAME
    holdback_path = tmp_path / pc.HOLDBACK_FILE_NAME
    corpus_path.write_bytes(corpus_bytes)
    holdback_path.write_bytes(holdback_bytes)
    assert pc.verify_corpus_files(corpus_path, holdback_path, manifest) == []
    assert pc.load_holdback(holdback_path).keys() == {item.item_id for item in items}
    assert set(pc.load_corpus_texts(corpus_path)) == {item.item_id for item in items}
    # Tamper with one text byte: verification must fail.
    tampered = corpus_bytes.replace(b"Exact probe", b"Exacx probe", 1)
    corpus_path.write_bytes(tampered)
    assert pc.verify_corpus_files(corpus_path, holdback_path, manifest) != []


def test_holdback_labels_are_separate_from_corpus(tmp_path: Path):
    corpus_path = tmp_path / pc.CORPUS_FILE_NAME
    corpus_path.write_text(
        '{"item_id": "pc100-human-native-abc", "text": "hi"}\n', encoding="utf-8"
    )
    texts = pc.load_corpus_texts(corpus_path)
    assert "label" not in json.loads(
        (tmp_path / pc.CORPUS_FILE_NAME).read_text(encoding="utf-8").splitlines()[0]
    )
    assert texts == {"pc100-human-native-abc": "hi"}
    holdback_path = tmp_path / pc.HOLDBACK_FILE_NAME
    holdback_path.write_text(
        '{"item_id": "pc100-human-native-abc", "label": 0, "regime": "raw"}\n',
        encoding="utf-8",
    )
    assert pc.load_holdback(holdback_path)["pc100-human-native-abc"]["label"] == 0


def test_rebuild_from_manifest_reproduces_hashes(tmp_path: Path):
    # Frozen means: the same item list always yields the same
    # fingerprint, and a changed item always changes it.
    manifest = _full_manifest()
    again = pc.build_manifest(
        items=list(manifest.items),
        created_at_utc=manifest.created_at_utc,
        holdback_sha256=manifest.holdback_sha256,
        corpus_file_sha256=manifest.corpus_file_sha256,
        sources=manifest.sources,
        current_generators=manifest.current_generators,
        notes=list(manifest.notes),
    )
    assert again.items_sha256 == manifest.items_sha256
    changed = list(manifest.items)
    changed[0] = _item(text="A different text entirely.")
    rebuilt = pc.build_manifest(
        items=changed,
        created_at_utc=manifest.created_at_utc,
        holdback_sha256=manifest.holdback_sha256,
        corpus_file_sha256=manifest.corpus_file_sha256,
        sources=manifest.sources,
        current_generators=manifest.current_generators,
        notes=list(manifest.notes),
    )
    assert rebuilt.items_sha256 != manifest.items_sha256


def test_committed_manifest_is_self_consistent():
    """The committed manifest (written by the build) must verify.

    Skipped until the build has run — the module tests above cover
    the mechanics with synthetic fixtures.
    """
    path = Path("docs/probe-corpus/v1.0.0/manifest.json")
    if not path.exists():
        pytest.skip("committed manifest not built yet")
    manifest = pc.load_manifest(path)
    assert manifest.version == pc.PROBE_CORPUS_VERSION
    assert pc.verify_manifest(manifest) == []
    counts = manifest.slice_counts()
    assert set(counts) == set(pc.SLICES)
    assert sum(counts.values()) == len(manifest.items)
    assert all(count >= pc.MIN_SLICE_N for count in counts.values())
