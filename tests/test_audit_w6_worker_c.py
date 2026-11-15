"""W6 Worker C regression tests (ENG-08 / CORE-08): CRLF-safe hashing.

ENG-08 — one repository-controlled representation for hash-covered text
(canonical LF); hashes are generated from persisted bytes, never resealed
to host-specific CRLF. A Windows checkout with ``autocrlf`` on must hash
the same content to the same digest as Linux.

CORE-08 — the dataset cache manifest must record the digest of the
persisted bytes actually written to the cache (post-write, read-back),
not the digest of the in-memory string.

The Windows behaviour is simulated on Linux, because no Windows host is
available here:

* text hashes: the same logical text is hashed once with CRLF newlines
  (the Windows representation) and once with LF (the Linux one); the
  digests must be identical;
* writers: the platform newline translation a Windows text-mode write
  performs (``\\n`` -> ``\\r\\n``) is injected by patching the stdlib
  text-mode entry points the writers use, so a writer that still goes
  through text mode persists CRLF and fails, while a bytes writer is
  unaffected;
* cache manifest: the bytes writer is patched to convert LF -> CRLF
  before persisting (simulating a host write path that transforms
  bytes), so a manifest hashed from the in-memory buffer desyncs from
  disk and fails, while a post-write read-back digest stays in sync.

Each red-first test below FAILED on the pre-fix tree and passes after
the fix (see the part-report for the exact pre-fix counts).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from textforensics import datasets as datasets_mod
from textforensics.benchmark import (
    _compute_content_hash,
    _compute_sample_hashes,
    fingerprint_dataset,
)
from textforensics.datasets import (
    DatasetFetchError,
    NormalizedRow,
    get_spec,
    map_row,
    read_sample_cache,
    write_sample_cache,
)
from textforensics.ledger import canonical_text_bytes, canonical_text_sha256, text_sha256

LF_TEXT = "first line\nsecond line\nthird line"
CRLF_TEXT = "first line\r\nsecond line\r\nthird line"
CR_TEXT = "first line\rsecond line\rthird line"


def _row(text: str, label: int = 0) -> NormalizedRow:
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


# ---------------------------------------------------------------------------
# ENG-08: canonical LF for hash-covered text
# ---------------------------------------------------------------------------


class TestEng08CanonicalTextHash:
    def test_canonical_text_bytes_normalizes_crlf_and_cr_to_lf(self):
        assert canonical_text_bytes(CRLF_TEXT) == LF_TEXT.encode("utf-8")
        assert canonical_text_bytes(CR_TEXT) == LF_TEXT.encode("utf-8")
        assert canonical_text_bytes(LF_TEXT) == LF_TEXT.encode("utf-8")
        assert canonical_text_bytes("") == b""

    def test_text_sha256_crlf_equals_lf(self):
        # Same logical text, Windows representation vs Linux representation.
        assert text_sha256(CRLF_TEXT) == text_sha256(LF_TEXT)
        assert text_sha256(CR_TEXT) == text_sha256(LF_TEXT)
        assert text_sha256(CRLF_TEXT) == hashlib.sha256(LF_TEXT.encode("utf-8")).hexdigest()

    def test_canonical_text_sha256_matches_text_sha256(self):
        assert canonical_text_sha256(CRLF_TEXT) == text_sha256(LF_TEXT)
        assert canonical_text_sha256(LF_TEXT) == text_sha256(LF_TEXT)

    def test_compute_content_hash_crlf_equals_lf(self):
        assert _compute_content_hash(CRLF_TEXT) == _compute_content_hash(LF_TEXT)
        assert _compute_content_hash(CR_TEXT) == _compute_content_hash(LF_TEXT)

    def test_sample_hashes_stable_across_crlf_representation(self, tmp_path: Path):
        # Two JSONL files holding the same rows: one stores the text
        # values with LF newlines, the other with CRLF newlines (as a
        # Windows-origin file would), and the second file itself uses
        # CRLF line endings. The per-row content hashes must agree.
        rows_lf = [
            {"text": LF_TEXT, "label": 0},
            {"text": "plain row", "label": 1},
        ]
        rows_crlf = [
            {"text": CRLF_TEXT, "label": 0},
            {"text": "plain row", "label": 1},
        ]
        lf_path = tmp_path / "lf.jsonl"
        crlf_path = tmp_path / "crlf.jsonl"
        lf_path.write_bytes(
            b"".join((json.dumps(r, ensure_ascii=False) + "\n").encode("utf-8") for r in rows_lf)
        )
        crlf_path.write_bytes(
            b"".join(
                (json.dumps(r, ensure_ascii=False) + "\r\n").encode("utf-8") for r in rows_crlf
            )
        )
        hashes_lf, count_lf = _compute_sample_hashes(lf_path)
        hashes_crlf, count_crlf = _compute_sample_hashes(crlf_path)
        assert count_lf == count_crlf == 2
        assert hashes_crlf == hashes_lf

    def test_fingerprint_content_hashes_stable_across_crlf(self, tmp_path: Path):
        rows_lf = [{"text": LF_TEXT, "label": 0}]
        rows_crlf = [{"text": CRLF_TEXT, "label": 0}]
        lf_path = tmp_path / "lf.jsonl"
        crlf_path = tmp_path / "crlf.jsonl"
        lf_path.write_bytes((json.dumps(rows_lf[0], ensure_ascii=False) + "\n").encode("utf-8"))
        crlf_path.write_bytes(
            (json.dumps(rows_crlf[0], ensure_ascii=False) + "\r\n").encode("utf-8")
        )
        fp_lf = fingerprint_dataset(lf_path, "test")
        fp_crlf = fingerprint_dataset(crlf_path, "test")
        assert fp_crlf.content_hashes == fp_lf.content_hashes
        # The file-bytes digest is a different, persisted-bytes hash: the
        # two files really do hold different bytes, so it may differ.
        assert fp_lf.sample_count == fp_crlf.sample_count == 1

    def test_mage_source_id_stable_across_crlf(self):
        row_lf = {"text": LF_TEXT, "label": 1, "src": "x_human"}
        row_crlf = {"text": CRLF_TEXT, "label": 1, "src": "x_human"}
        mapped_lf = map_row("mage", row_lf, "default", "train")
        mapped_crlf = map_row("mage", row_crlf, "default", "train")
        assert mapped_lf[0].source_id == mapped_crlf[0].source_id
        assert mapped_lf[0].source_id.startswith("mage:")

    def test_case_input_hash_crlf_equals_lf_and_replay_matches(self):
        # The case-file input hash is produced by report.py and
        # consumed by the casefile replay check; both must use the
        # canonical-LF digest, so a CRLF text seals and replays
        # exactly like its LF twin.
        from textforensics.casefile import replay_case_file, seal_case_file
        from textforensics.report import build_forensic_bundle

        bundle_lf = build_forensic_bundle(LF_TEXT).to_dict()
        bundle_crlf = build_forensic_bundle(CRLF_TEXT).to_dict()
        assert bundle_crlf["content_sha256"] == bundle_lf["content_sha256"] == text_sha256(LF_TEXT)
        case_crlf = seal_case_file(bundle_crlf)
        replay = replay_case_file(case_crlf, text=CRLF_TEXT)
        assert replay["valid"] is True, replay["errors"]
        assert replay["checks"]["text"]["status"] == "matched"


# ---------------------------------------------------------------------------
# ENG-08: hash-covered writers must persist LF bytes, never host CRLF
# ---------------------------------------------------------------------------


def _patch_text_mode_to_crlf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate Windows text-mode newline translation (``\\n`` -> ``\\r\\n``).

    Patches the stdlib text-mode entry points the hash-covered
    writers use: ``tempfile.NamedTemporaryFile`` (case files),
    ``pathlib.Path.write_text`` (sealed-bundle seal record, bundle
    manifest, fingerprint, provenance graph, hash chain) and
    ``pathlib.Path.open`` in text-write mode (decision ledger). A
    writer that goes through text mode then persists CRLF and fails
    the assertions below; a bytes writer is unaffected.
    """
    real_ntf = tempfile.NamedTemporaryFile

    def crlf_ntf(*args, **kwargs):  # type: ignore[no-untyped-def]
        mode = kwargs.get("mode", "w+b")
        if isinstance(mode, str) and "b" not in mode:
            kwargs["newline"] = "\r\n"
        return real_ntf(*args, **kwargs)

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", crlf_ntf)

    real_write_text = Path.write_text

    def crlf_write_text(self, data, encoding=None, errors=None, newline=None):  # type: ignore[no-untyped-def]
        return real_write_text(
            self, data.replace("\n", "\r\n"), encoding=encoding, errors=errors, newline=newline
        )

    monkeypatch.setattr(Path, "write_text", crlf_write_text)

    real_open = Path.open

    def crlf_open(self, mode="r", *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(mode, str) and "b" not in mode and any(c in mode for c in "wa+"):
            kwargs.setdefault("newline", "\r\n")
        return real_open(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", crlf_open)


def _bundle_dict() -> dict:
    from textforensics.report import build_forensic_bundle

    text = (
        "The committee met on Tuesday to review the quarterly figures and "
        "discuss the outlook for the coming year. The chair opened the meeting "
        "with a summary of the previous session, and the members agreed to "
        "focus on three items: revenue, staffing, and the maintenance budget. "
        "Revenue grew modestly in the first quarter, driven by new contracts "
        "in the northern region. Staffing remains tight, and the hiring plan "
        "was approved with minor changes. The maintenance budget was reduced "
        "after a review of the supplier quotes. The meeting ended with a plan "
        "to reconvene in four weeks to review progress on each item."
    )
    return build_forensic_bundle(text).to_dict()


class TestEng08WritersPersistLf:
    def test_write_case_file_persists_lf_under_simulated_autocrlf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        from textforensics.casefile import verify_case_file_path, write_case_file

        _patch_text_mode_to_crlf(monkeypatch)
        target = tmp_path / "case.json"
        write_case_file(target, _bundle_dict())
        raw = target.read_bytes()
        assert b"\r\n" not in raw
        assert b"\r" not in raw
        # The persisted file still verifies: LF bytes are the canonical form.
        assert verify_case_file_path(target)["valid"] is True

    def test_write_sealed_bundle_record_persists_lf_under_simulated_autocrlf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        from textforensics.casefile import seal_case_file
        from textforensics.sealed_bundle import verify_sealed_bundle, write_sealed_bundle

        _patch_text_mode_to_crlf(monkeypatch)
        case = seal_case_file(
            _bundle_dict(),
            deterministic=True,
            fixed_timestamp="2026-11-07T00:00:00+00:00",
        )
        bundle_path = tmp_path / "bundle.zip"
        record_path = tmp_path / "bundle.seal.json"
        write_sealed_bundle(case, bundle_path, record_path)
        record_raw = record_path.read_bytes()
        assert b"\r\n" not in record_raw
        assert b"\r" not in record_raw
        assert bundle_path.read_bytes()  # the archive itself is bytes-written
        # The LF-written seal record round-trips: cross-checking the
        # bundle against the record read back from disk passes.
        record = json.loads(record_raw.decode("utf-8"))
        result = verify_sealed_bundle(bundle_path.read_bytes(), seal_record=record)
        assert result["exit_code"] == 0, json.dumps(result, indent=2)
        assert result["seal_record"]["errors"] == []

    def test_pack_bundle_manifest_persists_lf_under_simulated_autocrlf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        from textforensics.bundle import pack_bundle, verify_bundle
        from textforensics.casefile import write_case_file

        _patch_text_mode_to_crlf(monkeypatch)
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        write_case_file(case_dir / "case.json", _bundle_dict())
        out = tmp_path / "bundle.tar.gz"
        pack_bundle(case_dir, out)
        manifest_raw = (tmp_path / "bundle.tar.gz.manifest.json").read_bytes()
        assert b"\r\n" not in manifest_raw
        assert b"\r" not in manifest_raw
        assert verify_bundle(out).valid is True

    def test_fingerprint_and_ledger_writers_persist_lf_under_simulated_autocrlf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        # The same text-mode defect class in the other digest-carrying
        # writers: the dataset fingerprint, the decision ledger, the
        # provenance graph and the ledger hash chain.
        from textforensics.benchmark import fingerprint_dataset, save_fingerprint
        from textforensics.ledger import (
            CalibrationChain,
            DecisionLedger,
            ProvenanceGraph,
            save_graph,
            save_ledger,
        )

        _patch_text_mode_to_crlf(monkeypatch)
        src = tmp_path / "data.jsonl"
        src.write_bytes((json.dumps({"text": LF_TEXT, "label": 0}) + "\n").encode("utf-8"))
        fp = fingerprint_dataset(src, "test")
        fp_path = tmp_path / "fp.json"
        save_fingerprint(fp, fp_path)
        assert b"\r\n" not in fp_path.read_bytes()

        from types import SimpleNamespace

        ledger = DecisionLedger()
        ledger.record(
            LF_TEXT,
            SimpleNamespace(
                detector_id="d", detector_version="1", verdict="ai", score=0.5, runtime_ms=1.0
            ),
        )
        ledger_path = tmp_path / "ledger.jsonl"
        save_ledger(list(ledger._records), ledger_path)
        assert b"\r\n" not in ledger_path.read_bytes()

        graph_path = tmp_path / "graph.json"
        save_graph(ProvenanceGraph(), graph_path)
        assert b"\r\n" not in graph_path.read_bytes()

        chain = CalibrationChain()
        chain.append("a" * 64)
        chain_path = tmp_path / "chain.json"
        chain.save_to_file(chain_path)
        assert b"\r\n" not in chain_path.read_bytes()


# ---------------------------------------------------------------------------
# CORE-08: the manifest records the digest of the persisted bytes
# ---------------------------------------------------------------------------


class TestCore08PersistedBytesManifest:
    def test_manifest_records_persisted_bytes_when_write_transforms_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        # Simulate a host write path that transforms bytes (what a
        # text-mode/CRLF write does on Windows): the writer converts
        # LF -> CRLF before persisting. The manifest must record the
        # digest of the bytes actually on disk, so re-validation passes.
        real_write = datasets_mod._atomic_write_bytes

        def crlf_write(path, data):  # type: ignore[no-untyped-def]
            real_write(path, data.replace(b"\n", b"\r\n"))

        monkeypatch.setattr(datasets_mod, "_atomic_write_bytes", crlf_write)
        spec = get_spec("beemo")
        rows = [_row("hello world", 0), _row("machine text here", 1)]
        path, manifest_file = write_sample_cache(spec, "default", "train", rows, cache_dir=tmp_path)
        persisted = path.read_bytes()
        assert b"\r\n" in persisted  # the simulation really transformed the bytes
        manifest = json.loads(manifest_file.read_bytes().decode("utf-8"))
        assert manifest["file_sha256"] == hashlib.sha256(persisted).hexdigest()
        assert read_sample_cache(spec, "default", "train", cache_dir=tmp_path) == rows

    def test_crlf_rewrite_is_refused_on_revalidation(self, tmp_path: Path):
        # Rewriting the cache file with CRLF changes the persisted bytes
        # without updating the manifest: re-validation must refuse
        # (fail closed) — the manifest hash no longer describes disk.
        spec = get_spec("beemo")
        rows = [_row("hello world", 0), _row("machine text here", 1)]
        path, _ = write_sample_cache(spec, "default", "train", rows, cache_dir=tmp_path)
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        with pytest.raises(DatasetFetchError, match="digest"):
            read_sample_cache(spec, "default", "train", cache_dir=tmp_path)

    def test_manifest_digest_matches_persisted_bytes(self, tmp_path: Path):
        spec = get_spec("beemo")
        rows = [_row("héllo wörld — ünïcode", 0), _row("machine text here", 1)]
        path, manifest_file = write_sample_cache(spec, "default", "train", rows, cache_dir=tmp_path)
        raw = path.read_bytes()
        assert b"\r\n" not in raw
        manifest = json.loads(manifest_file.read_bytes().decode("utf-8"))
        assert manifest["file_sha256"] == hashlib.sha256(raw).hexdigest()

    def test_cache_preserves_crlf_inside_row_text_verbatim(self, tmp_path: Path):
        # Canonicalisation applies to HASHES, never to dataset evidence:
        # row text is stored and read back byte-for-byte, CRLF included.
        spec = get_spec("beemo")
        rows = [_row(CRLF_TEXT, 0)]
        write_sample_cache(spec, "default", "train", rows, cache_dir=tmp_path)
        assert read_sample_cache(spec, "default", "train", cache_dir=tmp_path) == rows
