#!/usr/bin/env python3
"""Prefix probe: verify the live DetectRL-X download path on its first 100 MiB.

Fetches ``bytes=0-104857599`` of :data:`DETECTRL_X_URL` through the
shipped :func:`download_large_file` loader and compares the SHA-256 of
the fetched prefix against a constant derived from the already-verified
local cache file. This exercises resolve -> 302 -> CDN -> Range -> 206
on the live path in ~13 s / 100 MB without re-downloading the full
~879 MB file, and ``--force-curl`` exercises the curl fallback path
too.

Usage:
    python scripts/download_prefix_probe.py [--force-curl] [--dest-dir DIR]

Exit status is 0 when the prefix hash matches and 1 otherwise. Only
hashes, sizes and timings are printed -- never file content.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from textforensics.datasets import (  # noqa: E402
    DETECTRL_X_URL,
    DownloadError,
    download_large_file,
)

PREFIX_BYTES = 104_857_600  # 100 MiB
# SHA-256 of the first 100 MiB of the verified DetectRL-X cache file.
# Derived 2026-11-07 from ~/.cache/textforensics/datasets/detectrl_x/
# Binary/binary_general_open.json (878,631,989 bytes, full-file SHA-256
# 815be1667a5e7404d9e513ab339c214c713bd7ac4eb46f375fa0a26bf2dfc15f,
# verified 2026-11-07): hash its first 104,857,600 bytes.
PREFIX_SHA256 = (
    "5a82f50918742aef06eae846e2f47fdef5ddcda208f2d34a029eb46485c75d40"  # pragma: allowlist secret
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    """Run the prefix probe; return 0 on a hash match, 1 otherwise."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--force-curl",
        action="store_true",
        help="exercise the curl fallback path instead of urllib",
    )
    parser.add_argument(
        "--dest-dir",
        type=Path,
        default=None,
        help="directory for the fetched prefix (default: a fresh temp dir)",
    )
    parser.add_argument(
        "--stall-timeout-s",
        type=float,
        default=300.0,
        help="stall budget passed to the loader (default: 300 s, as for "
        "the DetectRL-X-class caller)",
    )
    args = parser.parse_args(argv)

    mode = "curl" if args.force_curl else "urllib"
    tmp_dir = None
    if args.dest_dir is None:
        tmp_dir = tempfile.TemporaryDirectory(prefix="tf-prefix-probe-")
        dest_dir = Path(tmp_dir.name)
    else:
        dest_dir = args.dest_dir
        dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "binary_general_open.json"
    # A stale prefix from an earlier run must not satisfy the probe.
    dest.unlink(missing_ok=True)
    Path(str(dest) + ".part").unlink(missing_ok=True)

    started = time.monotonic()
    try:
        download_large_file(
            DETECTRL_X_URL,
            dest,
            limit_bytes=PREFIX_BYTES,
            stall_timeout_s=args.stall_timeout_s,
            connect_timeout_s=30.0,
            retries=3,
            force_curl=args.force_curl,
        )
    except DownloadError as exc:
        elapsed = time.monotonic() - started
        print(f"mode={mode} url={DETECTRL_X_URL}")
        print(f"ERROR after {elapsed:.1f} s: {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started

    try:
        size = dest.stat().st_size
        actual = _sha256_file(dest)
    finally:
        if tmp_dir is not None:
            tmp_dir.cleanup()
    match = size == PREFIX_BYTES and actual == PREFIX_SHA256
    print(f"mode={mode} url={DETECTRL_X_URL}")
    print(f"bytes={size} expected_bytes={PREFIX_BYTES}")
    print(f"elapsed_s={elapsed:.1f} throughput_MiB_s={size / elapsed / (1 << 20):.2f}")
    print(f"expected_sha256={PREFIX_SHA256}")
    print(f"actual_sha256={actual}")
    print(f"result={'MATCH' if match else 'MISMATCH'}")
    return 0 if match else 1


if __name__ == "__main__":
    raise SystemExit(main())
