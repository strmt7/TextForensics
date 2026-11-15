"""Atomic file publication and cross-process file locking (W5, item 4/5).

Transaction semantics for state exports
---------------------------------------
Every writer in this module commits with *write-temp + fsync + atomic
rename* (``os.replace``), so a reader never observes a half-written
file:

* the new bytes are staged in a temporary file in the *same* directory
  (same filesystem, so the rename is atomic);
* the staged file is flushed and fsynced before the rename, and the
  containing directory is fsynced afterwards (best effort: a directory
  fsync is not available on every platform);
* any failure before the rename leaves a previous file at the target
  untouched and removes the staged file.

Bytes, not text, are the unit of publication: callers encode to UTF-8
first, so the bytes committed are exactly the bytes hashed or
compared elsewhere (W4/CORE-08 — a text-mode write can persist CRLF
while a digest was computed over LF).

A failed multi-output transaction must restore every output it already
committed: see :func:`probe_runs.perform_probe_run`, which snapshots
the registry bytes before mutating and restores them (via
:func:`atomic_write_bytes`) when a later step fails, so a failed save
never leaves a demotion/clearing whose cited run does not exist.

:func:`file_lock` serializes read-modify-write targets across local
processes (``fcntl.flock`` on POSIX, ``msvcrt.locking`` on Windows),
following the ledger's lock. The lock lives in a sidecar ``<path>.lock``
file so locking never modifies the guarded file itself. The lock file
intentionally persists: deleting it can race with a waiter on the same
inode. A caller that already holds a lock must not take it a second
time on the same path: on POSIX a second ``flock`` from the same
process on a different file description blocks against the first.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = ["atomic_write_bytes", "atomic_write_text", "file_lock"]


def atomic_write_bytes(path: str | Path, data: bytes) -> None:
    """Publish ``data`` at ``path`` atomically.

    Raises
    ------
    OSError
        If staging, syncing, or renaming fails. A previous file at
        ``path`` is left untouched and the staged file is removed.
    """
    target = Path(path)
    temp_path: str | None = None
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
        temp_path = None
    finally:
        if temp_path is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp_path)
    # Make the rename itself durable; best effort — a directory
    # fsync is unavailable on some platforms.
    try:
        dir_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def atomic_write_text(path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Publish ``text`` at ``path`` atomically (UTF-8 bytes, see module docstring)."""
    atomic_write_bytes(path, text.encode(encoding))


@contextmanager
def file_lock(path: str | Path) -> Iterator[None]:
    """Hold an exclusive cross-process lock for the file at ``path``.

    The lock is taken on a sidecar ``<path>.lock`` file, never on the
    guarded file itself. Only one local process (or thread, via its own
    file description) holds it at a time; a second acquirer blocks
    until the holder releases it.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(str(target) + ".lock")
    handle = lock_path.open("a+b")
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
