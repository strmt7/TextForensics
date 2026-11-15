"""W5 Worker F kill tests for probe_corpus (audit-w5-f).

Kill evidence for the four runtime survivors in
``textforensics.probe_corpus.write_manifest`` (line 588):
``json.dumps(manifest.to_dict(), indent=2, sort_keys=True,
ensure_ascii=True)``. The byte-exact assertion kills every formatting
mutant: indent 2->3 / 2->1, sort_keys True->False, ensure_ascii
True->False. The manifest carries a non-ASCII source name (exercises
ensure_ascii) and keys whose insertion order is not sorted (exercises
sort_keys); the nested item list exercises indent.
"""

import json
from pathlib import Path

from textforensics.probe_corpus import (
    ProbeCorpusItem,
    ProbeCorpusManifest,
    write_manifest,
)


def _manifest() -> ProbeCorpusManifest:
    item = ProbeCorpusItem(
        item_id="item-001",
        slice="human",
        content_sha256="a" * 64,
        word_count=12,
        char_count=80,
        lang="en",
        source_dataset="caf\xe9-corpus",
        source_config="plain",
        source_split="test",
        source_id="src-1",
    )
    return ProbeCorpusManifest(
        version="1",
        created_at_utc="2026-11-15T00:00:00Z",
        items=(item,),
        items_sha256="b" * 64,
        holdback_sha256="c" * 64,
        corpus_file_sha256="d" * 64,
        sources={"human": {"dataset": "caf\xe9-corpus", "licence": "CC0"}},
        current_generators={},
        notes=("caf\xe9 note",),
    )


def test_write_manifest_is_byte_exact_sorted_indented_ascii(tmp_path: Path):
    """write_manifest writes sorted, 2-space, ASCII-escaped JSON + newline."""
    manifest = _manifest()
    path = tmp_path / "manifest.json"
    write_manifest(path, manifest)
    expected = json.dumps(manifest.to_dict(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    assert path.read_bytes() == expected.encode("ascii")
    # Spot-check the distinguishing bytes: escaped non-ASCII, sorted keys.
    raw = path.read_bytes()
    assert b"caf\\u00e9-corpus" in raw
    assert raw.index(b'"corpus_file_sha256"') < raw.index(b'"created_at_utc"')
    assert b'\n  "corpus_file_sha256"' in raw
