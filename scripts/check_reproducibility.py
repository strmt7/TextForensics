#!/usr/bin/env python3
"""Executable reproducibility check (ENG-03, W6).

Builds the TextForensics wheel + sdist TWICE from two independent
clean source copies (``git archive HEAD`` exports, so untracked and
uncommitted files cannot leak into either build), with
``SOURCE_DATE_EPOCH=1704067200`` and ``PYTHONHASHSEED=0``, using the
exact audited build profile (the pinned build/setuptools/wheel from
``requirements-tools-hashed.txt``, installed into a throwaway venv),
with build outputs outside both source trees. Then compares the
artifacts byte-for-byte, FATALLY: any difference exits non-zero and
the member-level diff is printed (which archive member differs and
how — never a blanket "timestamps" diagnosis).

This is the executable property behind the ``deterministic_builds``
claim in docs/CLAIMS.yaml: the claims gate runs
``python scripts/check_reproducibility.py`` and the reproducibility
workflow's build-reproducibility job runs it as its gating step.

Usage:
    python scripts/check_reproducibility.py [--source PATH]
        [--outdir PATH] [--keep] [--sde SECONDS]

Exit codes: 0 = both builds byte-identical; 1 = any difference, or
the builds could not be performed.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_LOCKFILE = REPO_ROOT / "requirements-tools-hashed.txt"
DEFAULT_SDE = 1704067200


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = dict(os.environ)
    merged["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        merged.update(env)
    return subprocess.run(cmd, cwd=str(cwd), env=merged, capture_output=True, text=True)


def _tools_lockfile_pins() -> dict[str, str]:
    """The pinned build profile, read from the tools lockfile."""
    import re

    pins: dict[str, str] = {}
    for match in re.finditer(
        r"^([A-Za-z0-9_.\-]+)==([^\s\\]+)",
        TOOLS_LOCKFILE.read_text(encoding="utf-8"),
        re.M,
    ):
        pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pins


def _git_toplevel(source: Path) -> Path:
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{source} is not inside a git checkout: {result.stderr.strip()}"
        )
    return Path(result.stdout.strip())


def _export_clean_copy(source_root: Path, dest: Path) -> None:
    """Export a pristine copy of HEAD into dest (no .git, no untracked files)."""
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(source_root), "archive", "HEAD"],
        capture_output=True,
        check=False,
    )
    if archive.returncode != 0:
        raise RuntimeError(
            f"git archive HEAD failed in {source_root}: {archive.stderr.decode(errors='replace')[-1000:]}"
        )
    with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r|") as tar:
        tar.extractall(dest)


def _normalize_mtimes(root: Path, epoch: int) -> None:
    """Set every file mtime under root to the source-date epoch.

    Wheel entries are already clamped by the wheel package when
    SOURCE_DATE_EPOCH is set, but sdist tar entries carry file mtimes,
    so both clean copies must start from identical mtimes for the
    byte comparison to be meaningful.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            os.utime(Path(dirpath) / name, (epoch, epoch))
        for name in dirnames:
            os.utime(Path(dirpath) / name, (epoch, epoch))


def _make_build_venv(workdir: Path) -> Path:
    """Create a venv with the pinned build tools (ENG-10 profile)."""
    venv = workdir / "build-venv"
    result = _run([sys.executable, "-m", "venv", str(venv)], cwd=workdir)
    if result.returncode != 0:
        raise RuntimeError(f"could not create build venv: {result.stderr[-1000:]}")
    python = venv / "bin" / "python"
    if not python.exists():  # Windows layout
        python = venv / "Scripts" / "python.exe"
    result = _run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--quiet",
            "--require-hashes",
            "-r",
            str(TOOLS_LOCKFILE),
        ],
        cwd=workdir,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "could not install pinned build tools from "
            f"requirements-tools-hashed.txt: {result.stderr[-1500:]}"
        )
    return python


def _build_once(build_python: Path, source_dir: Path, outdir: Path, epoch: int) -> dict[str, Path]:
    """Build wheel + sdist from source_dir into outdir; return artifacts."""
    outdir.mkdir(parents=True, exist_ok=True)
    env = {"SOURCE_DATE_EPOCH": str(epoch), "PYTHONHASHSEED": "0"}
    result = _run(
        [str(build_python), "-m", "build", "--no-isolation", "--outdir", str(outdir)],
        cwd=source_dir,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"build failed in {source_dir}:\n{result.stdout[-1500:]}\n{result.stderr[-1500:]}"
        )
    wheels = sorted(outdir.glob("*.whl"))
    sdists = sorted(outdir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError(f"expected exactly one wheel and one sdist in {outdir}: {wheels} {sdists}")
    return {"wheel": wheels[0], "sdist": sdists[0]}


def _wheel_members(path: Path) -> dict[str, tuple[int, int, tuple[int, ...]]]:
    """Map member name -> (compressed size, CRC32, ZIP date_time)."""
    members: dict[str, tuple[int, int, tuple[int, ...]]] = {}
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            members[info.filename] = (
                info.compress_size,
                info.CRC,
                info.date_time,
            )
    return members


def compare_wheels(first: Path, second: Path) -> list[str]:
    """Explain member-level differences between two wheels.

    Returns [] when the members are identical (same names, same
    compressed bytes, same CRCs, same recorded timestamps). The
    comparison is on content, not on a guess about timestamps: a
    differing member is reported by name with its CRCs.
    """
    diffs: list[str] = []
    a = _wheel_members(first)
    b = _wheel_members(second)
    for name in sorted(set(a) | set(b)):
        if name not in a:
            diffs.append(f"member {name!r} present only in {second.name}")
        elif name not in b:
            diffs.append(f"member {name!r} present only in {first.name}")
        elif a[name] != b[name]:
            diffs.append(
                f"member {name!r} differs: "
                f"{first.name} (size={a[name][0]}, crc={a[name][1]:08x}, date={a[name][2]}) vs "
                f"{second.name} (size={b[name][0]}, crc={b[name][1]:08x}, date={b[name][2]})"
            )
    return diffs


def _sdist_members(path: Path) -> dict[str, tuple[str, int, str, int]]:
    """Map member name -> (type, size, sha256 of content, mtime).

    Every member is compared, including directories: a directory
    mtime difference changes the tar bytes just as a file mtime does,
    and a file-only comparison would hide it.
    """
    members: dict[str, tuple[str, int, str, int]] = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.isfile():
                data = archive.extractfile(member).read()
                members[member.name] = (
                    "file",
                    member.size,
                    hashlib.sha256(data).hexdigest(),
                    member.mtime,
                )
            else:
                members[member.name] = (member.type, member.size, "", member.mtime)
    return members


def compare_sdists(first: Path, second: Path) -> list[str]:
    """Explain member-level differences between two sdists (see compare_wheels)."""
    diffs: list[str] = []
    a = _sdist_members(first)
    b = _sdist_members(second)
    for name in sorted(set(a) | set(b)):
        if name not in a:
            diffs.append(f"member {name!r} present only in {second.name}")
        elif name not in b:
            diffs.append(f"member {name!r} present only in {first.name}")
        elif a[name] != b[name]:
            kind = a[name][0]
            if kind == "file":
                diffs.append(
                    f"member {name!r} differs: "
                    f"{first.name} (size={a[name][1]}, sha256={a[name][2][:12]}..., mtime={a[name][3]}) vs "
                    f"{second.name} (size={b[name][1]}, sha256={b[name][2][:12]}..., mtime={b[name][3]})"
                )
            else:
                diffs.append(
                    f"member {name!r} ({kind}) differs: "
                    f"{first.name} (mtime={a[name][3]}) vs "
                    f"{second.name} (mtime={b[name][3]})"
                )
    return diffs


def check_reproducibility(
    source: Path, epoch: int, workdir: Path
) -> dict[str, object]:
    """Run the two-build comparison; return a report dict.

    Raises RuntimeError if the builds cannot be performed. The report
    carries ``identical`` (bool), the artifact hashes, and ``diffs``
    (list of member-level explanations, empty when identical).
    """
    source_root = _git_toplevel(source)
    copy_a = workdir / "copy-a"
    copy_b = workdir / "copy-b"
    _export_clean_copy(source_root, copy_a)
    _export_clean_copy(source_root, copy_b)
    _normalize_mtimes(copy_a, epoch)
    _normalize_mtimes(copy_b, epoch)
    build_python = _make_build_venv(workdir)
    out_a = workdir / "dist-a"
    out_b = workdir / "dist-b"
    artifacts_a = _build_once(build_python, copy_a, out_a, epoch)
    artifacts_b = _build_once(build_python, copy_b, out_b, epoch)
    diffs: list[str] = []
    for kind in ("wheel", "sdist"):
        hash_a = _sha256_file(artifacts_a[kind])
        hash_b = _sha256_file(artifacts_b[kind])
        if hash_a != hash_b:
            diffs.append(
                f"{kind} differs: {artifacts_a[kind].name} "
                f"sha256={hash_a} vs {hash_b}"
            )
            if kind == "wheel":
                diffs.extend(compare_wheels(artifacts_a[kind], artifacts_b[kind]))
            else:
                diffs.extend(compare_sdists(artifacts_a[kind], artifacts_b[kind]))
    pins = _tools_lockfile_pins()
    report: dict[str, object] = {
        "source_root": str(source_root),
        "source_date_epoch": epoch,
        "build_profile": {
            name: pins[name] for name in ("build", "setuptools", "wheel")
        },
        "wheel_a_sha256": _sha256_file(artifacts_a["wheel"]),
        "wheel_b_sha256": _sha256_file(artifacts_b["wheel"]),
        "sdist_a_sha256": _sha256_file(artifacts_a["sdist"]),
        "sdist_b_sha256": _sha256_file(artifacts_b["sdist"]),
        "identical": not diffs,
        "diffs": diffs,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=REPO_ROOT,
        help="source checkout to reproduce from (default: this repo)",
    )
    parser.add_argument(
        "--sde",
        type=int,
        default=DEFAULT_SDE,
        help=f"SOURCE_DATE_EPOCH for both builds (default {DEFAULT_SDE})",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=None,
        help="copy the four built artifacts and report.json here",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the working directory (under --outdir or a temp dir) for inspection",
    )
    args = parser.parse_args(argv)

    tmp = tempfile.TemporaryDirectory(prefix="w6b-repro-")
    workdir = Path(tmp.name)
    try:
        report = check_reproducibility(args.source, args.sde, workdir)
    except RuntimeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        tmp.cleanup()
        return 1

    if args.outdir is not None:
        args.outdir.mkdir(parents=True, exist_ok=True)
        # Keep the two builds apart: both produce the same file names,
        # so a flat copy would overwrite build A with build B.
        for label, name in (("build-a", "dist-a"), ("build-b", "dist-b")):
            dest_dir = args.outdir / label
            dest_dir.mkdir(parents=True, exist_ok=True)
            for artifact in (workdir / name).glob("*"):
                shutil.copy2(artifact, dest_dir / artifact.name)
        (args.outdir / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if report["identical"]:
        print(
            "PASS: two clean builds are byte-identical "
            f"(wheel sha256={report['wheel_a_sha256']}, "
            f"sdist sha256={report['sdist_a_sha256']})"
        )
        return 0

    print("FAIL: two clean builds differ", file=sys.stderr)
    for diff in report["diffs"]:  # type: ignore[union-attr]
        print(f"  - {diff}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
