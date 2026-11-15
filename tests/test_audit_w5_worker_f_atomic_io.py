"""W5 Worker F kill tests for atomic_io (audit-w5-f).

Kill evidence for the 23 killable runtime survivors in
textforensics.atomic_io (3 more are domain-equivalent; see
hidden_files/audit-w5-f-equiv-reasons-atomic_io.json):

* ``atomic_write_bytes`` parents=True->False (line 61) and
  ``file_lock`` parents=True->False (line 101): nested paths must be
  created.
* ``atomic_write_bytes`` ExceptionReplacer on the best-effort directory
  fsync (line 82): an OSError from the directory fsync must be
  swallowed, not propagated.
* ``atomic_write_text`` ``*`` -> ``/`` (line 86): the mutant makes
  ``path``/``text`` positional-only, so the kill is passing them by
  keyword.
* ``file_lock`` Windows (``msvcrt``) branch, exercised on POSIX with a
  fake ``msvcrt`` module and ``os.name`` patched to ``"nt"``:
  the marker byte, the lock/unlock offsets and byte counts, and the
  branch selection itself (``os.name == "nt"`` -> ``<`` at lines 105
  and 122). The fake records every ``locking`` call as
  ``(mode, nbytes, file_position)``.
"""

import os
import sys
from pathlib import Path, PosixPath

import pytest

import textforensics.atomic_io as aio
from textforensics.atomic_io import atomic_write_bytes, atomic_write_text, file_lock


def test_atomic_write_bytes_creates_parent_dirs(tmp_path: Path):
    """atomic_write_bytes creates missing parent directories."""
    target = tmp_path / "a" / "b" / "file.bin"
    atomic_write_bytes(target, b"hello")
    assert target.read_bytes() == b"hello"


def test_atomic_write_text_encoding_is_keyword_only(tmp_path: Path):
    """atomic_write_text accepts path/text/encoding as keyword arguments.

    The ``*`` -> ``/`` mutant makes the PRECEDING parameters
    positional-only (``path, text, /, encoding``), so encoding stays
    callable by keyword -- the kill is passing ``path`` and ``text``
    by keyword, which the mutant rejects.
    """
    target = tmp_path / "file.txt"
    atomic_write_text(path=target, text="caf\xe9", encoding="utf-8")
    assert target.read_bytes() == "caf\xe9".encode()


def test_atomic_write_bytes_dir_fsync_failure_is_best_effort(tmp_path: Path, monkeypatch):
    """An OSError from the directory fsync must not fail the write."""
    real_fsync = os.fsync
    calls = {"n": 0}

    def _fsync(fd):
        calls["n"] += 1
        if calls["n"] == 2:  # the directory fsync (call 1 is the file fsync)
            raise OSError("simulated dir fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", _fsync)
    target = tmp_path / "file.bin"
    atomic_write_bytes(target, b"hello")
    assert target.read_bytes() == b"hello"
    assert calls["n"] == 2


class _FakeMsvcrt:
    """Minimal msvcrt stand-in recording locking(fd, mode, nbytes)."""

    LK_LOCK = 1
    LK_UNLCK = 0

    def __init__(self):
        self.calls: list[tuple[int, int, int]] = []

    def locking(self, fd, mode, nbytes):
        pos = os.lseek(fd, 0, os.SEEK_CUR)
        self.calls.append((mode, nbytes, pos))


@pytest.fixture
def nt_lock(monkeypatch, tmp_path: Path):
    """Fake the Windows branch: os.name='nt' + fake msvcrt in sys.modules.

    Patching os.name alone is not enough: pathlib.Path dispatches on
    os.name at construction, so Path(...) would try to build a
    WindowsPath and raise NotImplementedError on POSIX. The module's
    Path reference is therefore also pointed at PosixPath -- the
    branch logic under test (seek/tell/write/locking calls) runs
    unchanged.
    """
    fake = _FakeMsvcrt()
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    monkeypatch.setattr(aio, "Path", PosixPath)
    return fake, tmp_path


def test_nt_lock_writes_marker_and_locks_at_offset_zero(nt_lock):
    """NT lock writes the 1-byte marker and locks 1 byte at offset 0."""
    fake, tmp_path = nt_lock
    target = tmp_path / "guarded.txt"
    with file_lock(target):
        assert fake.calls == [(fake.LK_LOCK, 1, 0)]
    assert (tmp_path / "guarded.txt.lock").read_bytes() == b"\0"
    assert fake.calls == [(fake.LK_LOCK, 1, 0), (fake.LK_UNLCK, 1, 0)]


def test_nt_lock_does_not_rewrite_nonempty_marker(nt_lock):
    """NT lock leaves an existing 1-byte marker at exactly 1 byte."""
    fake, tmp_path = nt_lock
    lock_path = tmp_path / "guarded.txt.lock"
    lock_path.write_bytes(b"\0")
    with file_lock(tmp_path / "guarded.txt"):
        pass
    assert lock_path.read_bytes() == b"\0"


def test_nt_lock_creates_parent_dirs(nt_lock):
    """file_lock creates missing parent directories for the lock file."""
    fake, tmp_path = nt_lock
    with file_lock(tmp_path / "a" / "b" / "guarded.txt"):
        assert fake.calls[0] == (fake.LK_LOCK, 1, 0)


def test_nt_unlock_is_recorded(nt_lock):
    """NT unlock calls locking(LK_UNLCK, 1) at offset 0 on exit."""
    fake, tmp_path = nt_lock
    with file_lock(tmp_path / "guarded.txt"):
        pass
    assert (fake.LK_UNLCK, 1, 0) in fake.calls
