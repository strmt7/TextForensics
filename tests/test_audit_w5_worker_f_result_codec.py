"""W5 Worker F kill tests for result_codec (audit-w5-f).

Kill evidence for the 57 killable runtime survivors in
textforensics.result_codec (27 more are equivalents; see
hidden_files/audit-w5-f-equiv-reasons-result_codec.json):

* ``_migrate_result`` (lines 189, 210): a downgrade (v2 -> v1) with a
  registered callback must migrate (Eq_Gt / Eq_GtE return the data
  unchanged instead); same-version with DISTINCT string objects must
  return the data (Eq_Is mistakes identity for equality); a callback
  returning the wrong schema must raise (NotEq_Lt).
* ``*`` -> ``/`` (Mul_Div) signature mutants: the mutant makes the
  PRECEDING parameters positional-only, so the kill is passing them
  by keyword (``data=``, ``schema_name=``, ``path=``) -- same lesson
  as ollama/atomic_io/report.
* ``encode`` ExceptionReplacer (line 310): a lone surrogate in a
  string value makes the UTF-8 encode raise UnicodeEncodeError (a
  ValueError), which must surface as CodecError.
* ``iter_encode`` chunk_size validation (line 331): "x", True, -1, 0
  must raise; 1 must work.
* ``iter_encode`` / ``stream_encode`` default chunk_size (65536):
  exact-size payloads distinguish 65535 (splits a 65536-byte payload)
  and 65537 (keeps a 65537-byte payload whole); the first ``readinto``
  on a stream returns exactly the first chunk.
* ``_iter_encode_chunks`` ensure_ascii / allow_nan (lines 340-346):
  called directly (``_prepare`` rejects NaN eagerly, so the encoder
  itself is only reachable directly): non-ASCII stays raw UTF-8 in
  both the canonical and the non-canonical branch; NaN raises
  CodecError in both branches (also kills the ExceptionReplacer at
  line 361).
* ``_iter_encode_chunks`` step (line 352): chunk_size=1 must work
  (``max(1, ...)`` -> ``max(0, ...)`` makes the step 0 and the range
  raise); the slice-end mutants (line 356) lose bytes on multi-step
  pieces, killed by a full-bytes round-trip at chunk_size=16.
* ``decode`` ExceptionReplacer (line 416) is NOT killable -- see the
  reasons file (strict_json_loads already rejects every non-finite
  value, so the handler is dead).
* ``_ChunkedReader``: readable() is True; _fill must not pull while
  pending data exists (raising iterator); the exhausted flag must stop
  further pulls (spy iterator); readinto on an empty buffer returns 0
  without pulling; a non-empty buffer reads; an exhausted reader
  returns 0; read(0) is empty; read(1) is one byte; read(5) over
  3-byte chunks is exactly 5 bytes (the take-slice mutants over-read
  on the second iteration, except Sub_RShift which spins forever and
  is failed by the read deadline); read() after a partial readinto includes
  the pending bytes; read() marks the reader exhausted.
"""

import threading

import pytest

from textforensics.result_codec import (
    CodecConfig,
    CodecError,
    ResultCodec,
    VersionMigrationError,
    _ChunkedReader,
    _migrate_result,
)

SCHEMA = "forensic-bundle"


def _codec(**overrides):
    return ResultCodec(CodecConfig(**overrides))


def _payload(k):
    """A dict whose canonical encoding is exactly k+55 bytes."""
    return {"data": "x" * k}


# ---------------------------------------------------------------------------
# _migrate_result
# ---------------------------------------------------------------------------


def test_migrate_downgrade_runs_callback():
    """A v2 -> v1 migration with a registered callback must migrate.

    Kills Eq_Gt / Eq_GtE (189): both mutants return the data unchanged
    for a downgrade instead of running the callback.
    """
    data = {"schema": "v2", "x": 1}
    out = _migrate_result(data, "v2", "v1", {"v2": {"v1": lambda d: {**d, "schema": "v1"}}})
    assert out["schema"] == "v1"


def test_migrate_same_version_distinct_objects_returns_data():
    """Same version (distinct string objects) returns the data.

    Kills Eq_Is (189): ``is`` mistakes identity for equality, so the
    mutant looks up a callback and raises instead of returning.
    """
    a = "".join(["v", "1"])
    b = "".join(["v", "1"])
    assert a == b and a is not b
    assert _migrate_result({"schema": "v1"}, a, b) == {"schema": "v1"}


def test_migrate_wrong_target_schema_raises():
    """A callback returning the wrong schema must raise.

    Kills NotEq_Lt (210): "v9" < "v2" is False, so the mutant returns
    the mislabelled dict instead of raising.
    """
    with pytest.raises(VersionMigrationError, match="did not produce the target"):
        _migrate_result(
            {"schema": "v1"},
            "v1",
            "v2",
            {"v1": {"v2": lambda d: {**d, "schema": "v9"}}},
        )


# ---------------------------------------------------------------------------
# Keyword-only signatures (Mul_Div * -> /)
# ---------------------------------------------------------------------------


def test_prepare_for_encode_keyword_args():
    """_prepare_for_encode accepts data/schema_name as keywords."""
    out = _codec()._prepare_for_encode(data={"x": 1}, schema_name=SCHEMA, validate=False)
    assert out["schema"] == "textforensics.forensic-bundle/v2"


def test_encode_keyword_args():
    """encode accepts data/schema_name as keywords."""
    assert _codec().encode(data={"x": 1}, schema_name=SCHEMA, validate=False)


def test_iter_encode_keyword_args():
    """iter_encode accepts data/schema_name as keywords."""
    chunks = list(_codec().iter_encode(data={"x": 1}, schema_name=SCHEMA, validate=False))
    assert b"".join(chunks)


def test_iter_encode_chunks_keyword_args():
    """_iter_encode_chunks accepts data/chunk_size as keywords."""
    chunks = list(_codec()._iter_encode_chunks(data={"x": 1}, chunk_size=16))
    assert b"".join(chunks) == b'{"x":1}'


def test_decode_keyword_args():
    """decode accepts data/schema_name as keywords."""
    assert _codec().decode(data=b'{"x": 1}', schema_name=SCHEMA, validate=False) == {"x": 1}


def test_encode_file_keyword_args(tmp_path):
    """encode_file accepts data/path/schema_name as keywords."""
    path = tmp_path / "out.json"
    _codec().encode_file(data={"x": 1}, path=path, schema_name=SCHEMA, validate=False)
    assert path.read_bytes()


def test_stream_encode_keyword_args():
    """stream_encode accepts data/schema_name as keywords."""
    stream = _codec().stream_encode(data={"x": 1}, schema_name=SCHEMA, validate=False)
    assert stream.read() == b'{"schema":"textforensics.forensic-bundle/v2","x":1}'


# ---------------------------------------------------------------------------
# encode / iter_encode behaviour
# ---------------------------------------------------------------------------


def test_encode_lone_surrogate_is_codec_error():
    """A lone surrogate must surface as CodecError, not UnicodeEncodeError.

    Kills ExceptionReplacer (310): the .encode("utf-8") raises
    UnicodeEncodeError (a ValueError), which encode must map.
    """
    with pytest.raises(CodecError, match="Non-finite numeric value"):
        _codec().encode({"text": "\ud800"}, SCHEMA, validate=False)


@pytest.mark.parametrize("bad", ["x", True, -1, 0])
def test_iter_encode_rejects_bad_chunk_size(bad):
    """iter_encode rejects a non-int, bool, negative or zero chunk_size.

    Kills OrWithAnd occ 2 ("x": the mutant evaluates ``"x" <= 0`` and
    raises TypeError instead of CodecError), OrWithAnd occ 3 (True),
    LtE_Eq (-1), LtE_Lt (0) and NumberReplacer <=-1 (0).
    """
    with pytest.raises(CodecError, match="chunk_size must be a positive integer"):
        _codec().iter_encode({"x": 1}, SCHEMA, chunk_size=bad)


def test_iter_encode_chunk_size_one_works():
    """iter_encode with chunk_size=1 works (step stays 1).

    Kills NumberReplacer occ 5 (352: max(1, ...) -> max(0, ...) makes
    the step 0 and the range raise) and LtE NumberReplacer occ 3
    (331: chunk_size=1 must not raise).
    """
    data = {"x": 1}
    assert b"".join(_codec().iter_encode(data, SCHEMA, chunk_size=1, validate=False)) == (
        _codec().encode(data, SCHEMA, validate=False)
    )


def test_iter_encode_default_chunk_splits_at_65536():
    """A 65536-byte payload yields one default chunk; 65537 yields two.

    Kills NumberReplacer occ 1 (319: 65536 -> 65535 splits the 65536
    payload) and occ 0 (65536 -> 65537 keeps the 65537 payload whole).
    """
    codec = _codec()
    full_65536 = codec.encode(_payload(65481), SCHEMA, validate=False)
    assert len(full_65536) == 65536
    assert [len(c) for c in codec.iter_encode(_payload(65481), SCHEMA, validate=False)] == [65536]
    full_65537 = codec.encode(_payload(65482), SCHEMA, validate=False)
    assert len(full_65537) == 65537
    assert [len(c) for c in codec.iter_encode(_payload(65482), SCHEMA, validate=False)] == [
        65536,
        1,
    ]


def test_stream_encode_default_chunk_size_via_readinto():
    """The first readinto on a default stream returns exactly 65536 bytes.

    Kills NumberReplacer occ 10/11 (494: 65536 -> 65537/65535 change
    the first chunk the reader pulls).
    """
    stream = _codec().stream_encode(_payload(69945), SCHEMA, validate=False)
    buf = bytearray(70000)
    assert stream.readinto(buf) == 65536


def test_iter_encode_chunks_keeps_all_bytes():
    """Chunked encoding reassembles to exactly the encode() bytes.

    Kills Add_BitOr / Add_BitXor (356): at chunk_size=16 the step is 4
    and the mutants slice [start:start|step] / [start:start^step],
    which drops half the bytes of every multi-step piece.
    """
    data = {"data": "x" * 100}
    codec = _codec()
    assert b"".join(codec.iter_encode(data, SCHEMA, chunk_size=16, validate=False)) == (
        codec.encode(data, SCHEMA, validate=False)
    )


@pytest.mark.parametrize("canonical", [True, False])
def test_iter_encode_chunks_keeps_raw_utf8(canonical):
    """Non-ASCII stays raw UTF-8 (both canonical and plain branches).

    Kills ReplaceFalseWithTrue occ 3 (340, canonical ensure_ascii)
    and occ 5 (346, plain ensure_ascii).
    """
    codec = _codec(canonical_json=canonical)
    out = b"".join(codec._iter_encode_chunks({"text": "caf\xe9"}, chunk_size=64))
    assert "caf\xe9".encode() in out
    assert b"\\u00e9" not in out


@pytest.mark.parametrize("canonical", [True, False])
def test_iter_encode_chunks_nan_is_codec_error(canonical):
    """NaN in _iter_encode_chunks raises CodecError (both branches).

    Kills ReplaceFalseWithTrue occ 4 (343, canonical allow_nan) and
    occ 6 (346, plain allow_nan) -- the mutant writes a "NaN" token --
    and ExceptionReplacer occ 5 (361).
    """
    codec = _codec(canonical_json=canonical)
    with pytest.raises(CodecError, match="Non-finite numeric value"):
        list(codec._iter_encode_chunks({"x": float("nan")}, chunk_size=64))


# ---------------------------------------------------------------------------
# _ChunkedReader
# ---------------------------------------------------------------------------


class _SpyChunks:
    """Chunk iterator counting pulls."""

    def __init__(self, chunks):
        self._it = iter(chunks)
        self.pulls = 0

    def __iter__(self):
        return self

    def __next__(self):
        self.pulls += 1
        return next(self._it)


def test_reader_is_readable():
    """_ChunkedReader.readable() is True."""
    assert _ChunkedReader(iter([b"x"])).readable() is True


def test_fill_does_not_pull_while_pending():
    """_fill must not pull the next chunk while pending data exists.

    Kills OrWithAnd (528): the mutant pulls while pending is non-empty
    (and not exhausted), hitting the raising iterator.
    """

    def _one_then_raise():
        yield b"0123456789"
        raise RuntimeError("must not pull yet")

    reader = _ChunkedReader(_one_then_raise())
    assert reader.readinto(bytearray(5)) == 5
    assert reader.readinto(bytearray(5)) == 5


def test_exhausted_flag_stops_further_pulls():
    """After exhaustion _fill must not pull again (spy iterator).

    Kills ReplaceTrueWithFalse (533): the mutant leaves _exhausted
    False, so every further readinto pulls (and hits StopIteration).
    """
    spy = _SpyChunks([b"ab", b"cd"])
    reader = _ChunkedReader(spy)
    assert reader.readinto(bytearray(4)) == 2
    assert reader.readinto(bytearray(4)) == 2
    assert reader.readinto(bytearray(4)) == 0
    assert reader.readinto(bytearray(4)) == 0
    assert spy.pulls == 3


def test_readinto_empty_buffer_returns_zero_without_pulling():
    """readinto(b'') returns 0 and pulls no chunk (spy iterator).

    Kills Eq_Lt (536: the early return never fires, so the mutant
    pulls a chunk) and NumberReplacer occ 13 (== -1: same reason),
    plus the return-value mutants occ 14/15 (return 1 / -1).
    """
    spy = _SpyChunks([b"ab"])
    reader = _ChunkedReader(spy)
    assert reader.readinto(bytearray(0)) == 0
    assert spy.pulls == 0


def test_readinto_nonempty_buffer_reads():
    """readinto on a non-empty buffer returns the available bytes.

    Kills AddNot, Eq_Gt, Eq_GtE, Eq_NotEq (536: all return 0
    immediately for a non-empty buffer) and NumberReplacer occ 12
    (== 1: a 1-byte buffer returns 0).
    """
    reader = _ChunkedReader(iter([b"0123"]))
    buf = bytearray(4)
    assert reader.readinto(buf) == 4
    assert bytes(buf) == b"0123"
    reader = _ChunkedReader(iter([b"0123"]))
    assert reader.readinto(bytearray(1)) == 1


def test_readinto_after_exhaustion_returns_zero():
    """readinto on an exhausted reader returns 0 (not 1 / -1).

    Kills Delete_Not / AddNot (539: both return 0 only when pending
    is non-empty -- here pending is empty, so they proceed and still
    return 0 via the empty take; the distinguishing case is the
    non-empty read above) and NumberReplacer occ 16/17 (540).
    """
    reader = _ChunkedReader(iter([b"ab"]))
    assert reader.readinto(bytearray(2)) == 2
    assert reader.readinto(bytearray(2)) == 0


def test_read_zero_returns_empty():
    """read(0) returns b'' without consuming anything.

    Kills Lt_LtE (547: size <= 0 reads everything) and NumberReplacer
    occ 20 (size < 1: same).
    """
    reader = _ChunkedReader(iter([b"0123"]))
    assert reader.read(0) == b""
    assert reader.read() == b"0123"


def test_read_one_returns_one_byte():
    """read(1) returns exactly one byte.

    Kills NumberReplacer occ 22 (555: size == 1 returns b'').
    """
    reader = _ChunkedReader(iter([b"0123"]))
    assert reader.read(1) == b"0"


def _read_with_timeout(reader, size, timeout=5.0):
    """Read with a hard deadline, on a daemon thread.

    A mutant that makes read() loop forever (ReplaceBinaryOperator
    Sub_RShift at line 563: ``size >> len(out)`` becomes 0, so the
    take is empty and ``out`` never grows) must FAIL this test, not
    hang the suite. The worker thread is a daemon, so the timeout
    failure does not block pytest teardown.
    """
    box = []

    def _run():
        try:
            box.append(reader.read(size))
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box.append(exc)

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise AssertionError(f"read({size}) did not return within {timeout}s")
    value = box[0]
    if isinstance(value, BaseException):
        raise value
    return value


def test_read_exact_size_over_small_chunks():
    """read(5) over 3-byte chunks returns exactly 5 bytes.

    Kills the six Sub_* mutants (563): on the second iteration the
    mutant takes pending[:size+len(out)] (and friends), over-reading
    to 6 bytes -- except Sub_RShift, which takes pending[:size >>
    len(out)] == pending[:0] and spins forever taking empty slices.
    That one is killed by the read deadline in _read_with_timeout.
    """
    reader = _ChunkedReader(iter([b"012", b"345", b"678"]))
    assert _read_with_timeout(reader, 5) == b"01234"


def test_read_all_includes_pending_bytes():
    """read() after a partial readinto returns the pending bytes too.

    Kills AddNot (549): the mutant skips the pending bytes.
    """
    reader = _ChunkedReader(iter([b"0123456789"]))
    assert reader.readinto(bytearray(2)) == 2
    assert reader.read() == b"23456789"


def test_read_all_marks_exhausted():
    """After read(), a further readinto pulls nothing (spy iterator).

    Kills ReplaceTrueWithFalse (553): the mutant leaves _exhausted
    False, so the next readinto pulls (and hits StopIteration).
    """
    spy = _SpyChunks([b"ab"])
    reader = _ChunkedReader(spy)
    assert reader.read() == b"ab"
    assert reader.readinto(bytearray(2)) == 0
    # read() pulled the chunk plus the terminating StopIteration (2);
    # the readinto must not pull again.
    assert spy.pulls == 2
