"""Kill tests for the audit-W4 Worker-F datasets runtime survivors.

Each test names the mutant(s) it kills as (line, col) + operator +
occurrence from the cosmic-ray inventory (phase 1 + phase 2 FULL).
The file must pass unmutated in the scratch worktree and is the proof
instrument for the hand re-prove (audit-w4-f-reprove.py --module
datasets --src-rel textforensics/datasets.py --test-file
tests/test_audit_w4_worker_f_datasets.py --reasons
audit-w4-f-equiv-reasons-datasets.json).

Two runtime survivors are NOT killed here but classified equivalent
(see the reasons file): write/read ``NotEq_IsNot`` on the filename
check (occ 6 / occ 7) — ``Path(x).name is x`` holds for every
single-component name, so ``is not`` coincides with ``!=``.
"""

import hashlib
import json
import os
from pathlib import Path

import pytest

from textforensics.datasets import (
    DATASETS_SERVER_BASE,
    DatasetFetchError,
    NormalizedRow,
    _atomic_write_bytes,
    cache_path,
    get_spec,
    manifest_path,
    read_sample_cache,
    write_sample_cache,
)

_DELETE = object()


def _spec():
    return get_spec("beemo")


def _row(text, label=0):
    return NormalizedRow(
        text=text,
        label=label,
        dataset="mage",
        config="default",
        split="train",
        source_id="r0",
        regime="raw",
        meta={},
    )


def _write(root, rows, **kwargs):
    return write_sample_cache(_spec(), "default", "train", rows, cache_dir=root, **kwargs)


def _read(root, **kwargs):
    return read_sample_cache(_spec(), "default", "train", cache_dir=root, **kwargs)


def _rewrite_manifest(manifest_file, **changes):
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    for key, value in changes.items():
        if value is _DELETE:
            manifest.pop(key, None)
        else:
            manifest[key] = value
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")


def _manual_cache(root, line_texts, *, rows=None):
    """Write cache bytes + a matching manifest by hand."""
    spec = _spec()
    path = cache_path(spec.key, "default", "train", cache_dir=root)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = ("\n".join(line_texts) + "\n").encode("utf-8")
    path.write_bytes(raw)
    if rows is None:
        rows = len([line for line in line_texts if line.strip()])
    manifest = {
        "dataset": spec.key,
        "hf_id": spec.hf_id,
        "config": "default",
        "split": "train",
        "licence": spec.licence,
        "fetched_from": DATASETS_SERVER_BASE,
        "fetch_date": "2026-11-15",
        "rows": rows,
        "file": path.name,
        "file_sha256": hashlib.sha256(raw).hexdigest(),
    }
    manifest_path(spec.key, "default", "train", cache_dir=root).write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return path


def _jsonl_row(text, label=0):
    return json.dumps(_row(text, label).to_jsonl(), ensure_ascii=False, sort_keys=True)


# ---------------------------------------------------------------------------
# _atomic_write_bytes
# ---------------------------------------------------------------------------


def test_atomic_write_dir_fsync_oserror_swallowed(tmp_path, monkeypatch):
    """(308,15) ExceptionReplacer#0: an OSError from opening the parent
    directory for fsync is swallowed (``except OSError: pass``) — the
    write still succeeds."""
    path = tmp_path / "train.jsonl"
    real_open = os.open

    def open_wrapper(p, flags, *args, **kwargs):
        if Path(p) == tmp_path:
            raise OSError("injected dir-open failure")
        return real_open(p, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_wrapper)
    _atomic_write_bytes(path, b"data")
    assert path.read_bytes() == b"data"


def test_atomic_write_replace_failure_cleans_up_temp_file(tmp_path, monkeypatch):
    """(310,11) ExceptionReplacer#1: when the replace fails, the outer
    ``except Exception`` handler must still unlink the temp file — even
    when the inner finally's unlink fails first (a PermissionError from
    the inner unlink must not leave the temp file behind)."""
    path = tmp_path / "train.jsonl"
    real_unlink = os.unlink
    calls = {"n": 0}

    def unlink_once(p):
        calls["n"] += 1
        if calls["n"] == 1:
            raise PermissionError("injected unlink failure")
        return real_unlink(p)

    def replace_fails(src, dst):
        raise OSError("injected replace failure")

    monkeypatch.setattr(os, "replace", replace_fails)
    monkeypatch.setattr(os, "unlink", unlink_once)
    with pytest.raises(PermissionError):
        _atomic_write_bytes(path, b"data")
    assert list(tmp_path.glob(f".{path.name}.*.tmp")) == []


def test_atomic_write_dir_fsync_non_oserror_propagates(tmp_path, monkeypatch):
    """(311,11) AddNot#5 + IsNot_Is#1: a non-OSError from the dir-fsync
    step propagates unchanged (the outer cleanup runs only when
    ``temp_path is not None`` — here it is None, so no unlink is
    attempted)."""
    path = tmp_path / "train.jsonl"
    real_open = os.open

    def open_wrapper(p, flags, *args, **kwargs):
        if Path(p) == tmp_path:
            raise ValueError("injected non-OSError")
        return real_open(p, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_wrapper)
    with pytest.raises(ValueError):
        _atomic_write_bytes(path, b"data")


# ---------------------------------------------------------------------------
# write_sample_cache
# ---------------------------------------------------------------------------


def test_write_accepts_keyword_arguments(tmp_path):
    """(2050,4) Mul_Div#14: ``write_sample_cache(spec, config, split,
    normalized, *, cache_dir=...)`` — the ``*`` -> ``/`` mutant makes
    ``spec``/``config``/``split``/``normalized`` positional-only, so
    calling them as keywords must work (and fails under the mutant)."""
    rows = [_row("hello", 0)]
    path, manifest_file = write_sample_cache(
        spec=_spec(), config="default", split="train", normalized=rows, cache_dir=tmp_path
    )
    assert path.exists()
    assert manifest_file.exists()


def test_write_cache_lines_sorted_keys(tmp_path):
    """(2084,70) ReplaceTrueWithFalse#17: cache lines are dumped with
    ``sort_keys=True`` — the first key is ``config`` (alphabetical),
    not ``text`` (``to_jsonl`` insertion order)."""
    rows = [_row("hello", 0)]
    path, _ = _write(tmp_path, rows)
    first_line = path.read_text(encoding="utf-8").splitlines()[0]
    assert first_line.startswith('{"config":')


def test_write_filename_with_slash_rejected(tmp_path):
    """(2081,24) ReplaceOrWithAnd#21 + (2081,36) NotEq_Gt#10: a
    filename containing a separator (``a/b``) must raise the plain-name
    ValueError (the ``and`` mutant skips the check; the ``>`` mutant
    does not see ``a/b`` as greater than ``b``)."""
    rows = [_row("hello", 0)]
    with pytest.raises(ValueError, match="filename must be a plain file name"):
        _write(tmp_path, rows, filename="a/b")


def test_write_filename_trailing_component_rejected(tmp_path):
    """(2081,36) NotEq_Lt#10: ``b/a`` must raise the plain-name
    ValueError (the ``<`` mutant does not see ``b/a`` as less than
    ``a``)."""
    rows = [_row("hello", 0)]
    with pytest.raises(ValueError, match="filename must be a plain file name"):
        _write(tmp_path, rows, filename="b/a")


def test_write_non_ascii_stays_utf8(tmp_path):
    """(2084,53) ReplaceFalseWithTrue#4: cache lines are written with
    ``ensure_ascii=False`` — non-ASCII text stays raw UTF-8, not
    ``\\uXXXX`` escapes."""
    rows = [_row("héllo wörld", 0)]
    path, _ = _write(tmp_path, rows)
    raw = path.read_bytes()
    assert "héllo".encode() in raw
    assert b"\\u00e9" not in raw


def test_write_empty_rows_writes_empty_cache(tmp_path):
    """(2085,42) AddNot#96: an empty row list writes an empty cache
    file (``"\\n" if lines else ""`` — the trailing newline is added
    only when there are lines)."""
    path, manifest_file = _write(tmp_path, [])
    assert path.read_bytes() == b""
    assert json.loads(manifest_file.read_text(encoding="utf-8"))["rows"] == 0


def test_write_manifest_fetched_from_default_and_override(tmp_path):
    """(2097,37) ReplaceOrWithAnd#22: ``fetched_from or
    DATASETS_SERVER_BASE`` defaults to the base URL when no override
    is given, and honours an explicit override."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest["fetched_from"] == DATASETS_SERVER_BASE
    _, manifest_file2 = _write(
        tmp_path, rows, filename="other.jsonl", fetched_from="https://example.com"
    )
    manifest2 = json.loads(manifest_file2.read_text(encoding="utf-8"))
    assert manifest2["fetched_from"] == "https://example.com"


def test_write_manifest_bytes_exact(tmp_path):
    """(2108,50) NumberReplacer#158/#159 (indent 2 -> 3 / 1) +
    (2108,63) ReplaceTrueWithFalse#18 (sort_keys True -> False): the
    manifest bytes are exactly ``json.dumps(..., indent=2,
    sort_keys=True)`` plus a trailing newline."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    expected = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    assert manifest_file.read_bytes() == expected


# ---------------------------------------------------------------------------
# read_sample_cache
# ---------------------------------------------------------------------------


def test_read_accepts_keyword_arguments(tmp_path):
    """(2117,4) Mul_Div#15: ``read_sample_cache(spec, config, split,
    *, cache_dir=...)`` — the ``*`` -> ``/`` mutant makes ``spec`` /
    ``config`` / ``split`` positional-only, so calling them as
    keywords must work (and fails under the mutant)."""
    rows = [_row("hello", 0)]
    _write(tmp_path, rows)
    back = read_sample_cache(spec=_spec(), config="default", split="train", cache_dir=tmp_path)
    assert [r.text for r in back] == ["hello"]


def test_read_filename_with_slash_rejected(tmp_path):
    """(2138,24) ReplaceOrWithAnd#23 + (2138,36) NotEq_Gt#11: a
    filename containing a separator must raise the plain-name
    ValueError on read as well as on write."""
    rows = [_row("hello", 0)]
    _write(tmp_path, rows)
    with pytest.raises(ValueError, match="filename must be a plain file name"):
        _read(tmp_path, filename="a/b")


def test_read_filename_trailing_component_rejected(tmp_path):
    """(2138,36) NotEq_Lt#11: ``b/a`` must raise the plain-name
    ValueError on read."""
    rows = [_row("hello", 0)]
    _write(tmp_path, rows)
    with pytest.raises(ValueError, match="filename must be a plain file name"):
        _read(tmp_path, filename="b/a")


def test_read_round_trip(tmp_path):
    """(2149,7) AddNot#102: an existing cache reads back (the
    ``not path.exists()`` guard raises only for a missing cache)."""
    rows = [_row("hello", 0), _row("machine", 1)]
    _write(tmp_path, rows)
    back = _read(tmp_path)
    assert [r.text for r in back] == ["hello", "machine"]
    assert [r.label for r in back] == [0, 1]


def test_read_corrupt_manifest_raises_dataset_error(tmp_path):
    """(2152,15) ExceptionReplacer#13: an unreadable manifest raises
    DatasetFetchError, not the raw exception."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    manifest_file.write_text("not json{", encoding="utf-8")
    with pytest.raises(DatasetFetchError, match="unreadable"):
        _read(tmp_path)


def test_read_digest_mismatch_raises(tmp_path):
    """(2162,41) ReplaceOrWithAnd#24 + (2162,53) NotEq_Is#8: a manifest
    whose ``file_sha256`` does not match the persisted bytes raises
    DatasetFetchError (the ``and`` mutant skips the check; the ``is``
    mutant never sees two distinct str objects as identical)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, file_sha256="0" * 64)
    with pytest.raises(DatasetFetchError, match="digest mismatch"):
        _read(tmp_path)


def test_read_digest_mismatch_high_declared_raises(tmp_path):
    """(2162,53) NotEq_Lt#12: a declared digest above every hex string
    (``z`` * 64) must still raise (the ``<`` mutant does not see it as
    less than the actual digest)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, file_sha256="z" * 64)
    with pytest.raises(DatasetFetchError, match="digest mismatch"):
        _read(tmp_path)


def test_read_digest_mismatch_low_declared_raises(tmp_path):
    """(2162,53) NotEq_Gt#12: a declared digest below every hex string
    (``!`` * 64) must still raise (the ``>`` mutant does not see it as
    greater than the actual digest)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, file_sha256="!" * 64)
    with pytest.raises(DatasetFetchError, match="digest mismatch"):
        _read(tmp_path)


def test_read_manifest_without_file_name_ok(tmp_path):
    """(2168,11) AddNot#105 + IsNot_Is#28: a manifest without a
    ``file`` entry reads fine (the check runs only when
    ``declared_file is not None``)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, file=_DELETE)
    back = _read(tmp_path)
    assert [r.text for r in back] == ["hello"]


def test_read_manifest_wrong_file_name_raises(tmp_path):
    """(2168,55) NotEq_Is#9: a manifest naming a different file raises
    DatasetFetchError (the ``is`` mutant never sees two distinct str
    objects as identical)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, file="other.jsonl")
    with pytest.raises(DatasetFetchError, match="names"):
        _read(tmp_path)


def test_read_manifest_file_name_high_raises(tmp_path):
    """(2168,55) NotEq_Lt#13: a manifest file name above the real one
    (``z.jsonl``) must still raise (the ``<`` mutant does not see it
    as less)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, file="z.jsonl")
    with pytest.raises(DatasetFetchError, match="names"):
        _read(tmp_path)


def test_read_manifest_file_name_low_raises(tmp_path):
    """(2168,55) NotEq_Gt#13: a manifest file name below the real one
    (``a.jsonl``) must still raise (the ``>`` mutant does not see it
    as greater)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, file="a.jsonl")
    with pytest.raises(DatasetFetchError, match="names"):
        _read(tmp_path)


def test_read_manifest_without_row_count_ok(tmp_path):
    """(2174,11) AddNot#106 + IsNot_Is#29 + (2200,7) AddNot#108 +
    IsNot_Is#30: a manifest without a ``rows`` entry reads fine (both
    row-count checks run only when ``declared_rows is not None``)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, rows=_DELETE)
    back = _read(tmp_path)
    assert [r.text for r in back] == ["hello"]


def test_read_manifest_bool_row_count_raises(tmp_path):
    """(2175,44) ReplaceOrWithAnd#25: a bool row count must raise the
    non-integer error (the ``and`` mutant lets it through to a
    different row-count-mismatch error)."""
    rows = [_row("hello", 0)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, rows=True)
    with pytest.raises(DatasetFetchError, match="non-integer row count"):
        _read(tmp_path)


def test_read_empty_line_between_rows_skipped(tmp_path):
    """(2186,12) ReplaceContinueWithBreak#0: an empty line in the
    middle of the cache is skipped, not treated as end-of-file."""
    lines = [_jsonl_row("first", 0), "", _jsonl_row("second", 1)]
    _manual_cache(tmp_path, lines)
    back = _read(tmp_path)
    assert [r.text for r in back] == ["first", "second"]


def test_read_matching_large_row_count_ok(tmp_path):
    """(2200,51) NotEq_IsNot#10: a manifest whose row count matches a
    300-row cache reads fine (the ``is not`` mutant sees two distinct
    int objects above the small-int cache as non-identical)."""
    rows = [_row(f"text {i}", i % 2) for i in range(300)]
    _write(tmp_path, rows)
    back = _read(tmp_path)
    assert len(back) == 300


def test_read_row_count_high_raises(tmp_path):
    """(2200,51) NotEq_Lt#14: a manifest declaring more rows than the
    file holds (5 vs 2) must raise (the ``<`` mutant does not see 5 as
    less than 2)."""
    rows = [_row("hello", 0), _row("machine", 1)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, rows=5)
    with pytest.raises(DatasetFetchError, match="row count mismatch"):
        _read(tmp_path)


def test_read_row_count_low_raises(tmp_path):
    """(2200,51) NotEq_Gt#14: a manifest declaring fewer rows than the
    file holds (1 vs 2) must raise (the ``>`` mutant does not see 1 as
    greater than 2)."""
    rows = [_row("hello", 0), _row("machine", 1)]
    _, manifest_file = _write(tmp_path, rows)
    _rewrite_manifest(manifest_file, rows=1)
    with pytest.raises(DatasetFetchError, match="row count mismatch"):
        _read(tmp_path)
