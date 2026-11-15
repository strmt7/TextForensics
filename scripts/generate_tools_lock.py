#!/usr/bin/env python3
"""Generate requirements-tools-hashed.txt from requirements-tools-pinned.txt.

Resolves the direct tools pins against requirements-pinned.txt as a
constraints file (so shared packages resolve to the main-lockfile
version), then hash-pins every resolved package via the PyPI JSON API
— the full transitive closure, not just the direct pins. Pip under
``--require-hashes`` refuses any unpinned transitive (ENG-10: the
original tools lockfile listed only 8 packages, so ``memory-profiler``
pulled an unpinned ``psutil`` resolved to a direct download URL and
every job installing the lockfile died at install time).

Usage:
    python3 scripts/generate_tools_lock.py [--output PATH]

Network access to PyPI is required (resolution + hash fetch). The
output is deterministic for a fixed resolution: packages sorted by
normalized name, hashes sorted.

Known exception (recorded, not hidden): ``docutils`` is NOT taken from
the main lockfile. The main lockfile pins docutils==0.23, but sphinx
8.2.3 requires docutils<0.22, so the tools resolution uses the latest
compatible docutils (0.21.2). The tools lockfile installs into separate
venvs from the main lockfile (docs / benchmark / reproducibility jobs),
so the two docutils versions never mix; the build profile
(build/setuptools/wheel) is identical in both lockfiles (ENG-10).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PINNED_FILE = REPO_ROOT / "requirements-tools-pinned.txt"
MAIN_PINNED_FILE = REPO_ROOT / "requirements-pinned.txt"
DEFAULT_OUTPUT = REPO_ROOT / "requirements-tools-hashed.txt"

PIN_RE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;#]+)\s*(?:#.*)?$")
WOULD_INSTALL_RE = re.compile(r"^Would install (.+)$", re.M)
TOKEN_RE = re.compile(r"^(.+)-([0-9][A-Za-z0-9.!+]*)$")

# Main-lockfile pins that must NOT constrain the tools resolution,
# with the reason (see the module docstring).
DROPPED_CONSTRAINTS = {
    # sphinx 8.2.3 requires docutils<0.22; the main lockfile pins 0.23.
    "docutils": "sphinx 8.2.3 requires docutils<0.22, main lockfile pins 0.23",
}


def _clean_constraints(main_pinned: Path) -> list[str]:
    """Extract ``name==version`` pins from the main lockfile.

    Drops comment/blank lines, the editable local-package line
    (``-e .[...]`` — not allowed as a constraint), and the documented
    exceptions in ``DROPPED_CONSTRAINTS``.
    """
    constraints: list[str] = []
    for line in main_pinned.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_RE.match(line)
        if not match:
            continue
        name = match.group(1).lower().replace("_", "-")
        if name in DROPPED_CONSTRAINTS:
            continue
        constraints.append(f"{match.group(1)}=={match.group(2)}")
    return constraints


def _read_direct_pins(pinned_file: Path) -> list[str]:
    pins: list[str] = []
    for line in pinned_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_RE.match(line)
        if not match:
            raise ValueError(f"not a == pin in {pinned_file}: {line!r}")
        pins.append(f"{match.group(1)}=={match.group(2)}")
    if not pins:
        raise ValueError(f"no pins in {pinned_file}")
    return pins


def _resolve(pins: list[str], constraints: list[str]) -> list[tuple[str, str]]:
    """Resolve pins with pip --dry-run; return [(name, version)] sorted.

    Resolution runs in a throwaway venv created for the purpose, so the
    generator works with any interpreter (including a system python
    whose pip is PEP 668 externally-managed) and never touches the
    ambient environment. Nothing is installed: --dry-run only resolves.
    """
    import tempfile

    with tempfile.TemporaryDirectory(prefix="w6b-tools-lock-resolve-") as tmp:
        tmp_path = Path(tmp)
        venv = tmp_path / "venv"
        result = subprocess.run(
            [sys.executable, "-m", "venv", str(venv)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"could not create resolution venv: {result.stderr[-1000:]}")
        python = venv / "bin" / "python"
        if not python.exists():  # Windows layout
            python = venv / "Scripts" / "python.exe"
        req_file = tmp_path / "pins.txt"
        con_file = tmp_path / "constraints.txt"
        req_file.write_text("\n".join(pins) + "\n", encoding="utf-8")
        con_file.write_text("\n".join(constraints) + "\n", encoding="utf-8")
        result = subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--dry-run",
                "-r",
                str(req_file),
                "-c",
                str(con_file),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "pip resolution failed:\n"
                f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
            )
        match = WOULD_INSTALL_RE.search(result.stdout)
        if not match:
            raise RuntimeError(
                "could not parse pip --dry-run output:\n"
                f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
            )
        resolved: list[tuple[str, str]] = []
        for token in match.group(1).split():
            token_match = TOKEN_RE.match(token)
            if not token_match:
                raise RuntimeError(f"cannot parse resolved token: {token!r}")
            name = token_match.group(1).lower().replace("_", "-")
            resolved.append((name, token_match.group(2)))
        resolved.sort()
        return resolved


def _pypi_files(name: str, version: str) -> list[dict]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    request = urllib.request.Request(
        url, headers={"User-Agent": "TextForensics-lockfile-gen/1.0"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    return data["urls"]


def generate(output: Path) -> list[tuple[str, str]]:
    """Regenerate the tools hashed lockfile; return the resolved pins."""
    pins = _read_direct_pins(PINNED_FILE)
    constraints = _clean_constraints(MAIN_PINNED_FILE)
    resolved = _resolve(pins, constraints)
    lines: list[str] = []
    lines.append("# requirements-tools-hashed.txt — HASH-PINNED LOCKFILE (Scorecard Pinned-Dependencies)")
    lines.append("# Generated from requirements-tools-pinned.txt via:")
    lines.append("#   python3 scripts/generate_tools_lock.py")
    lines.append("# Every package pins an exact version AND every downloadable file hash")
    lines.append("# (sha256) for that version, so `pip install --require-hashes -r")
    lines.append("# requirements-tools-hashed.txt` verifies each download against PyPI.")
    lines.append("# All files for the pinned version are listed (wheels + sdist) so the")
    lines.append("# same lockfile works across platforms and Python versions.")
    lines.append("#")
    lines.append(f"# {len(pins)} direct pins resolve to a {len(resolved)}-package closure")
    lines.append("# (direct pins + transitive dependencies, resolved against")
    lines.append("# requirements-pinned.txt as constraints, so shared packages match")
    lines.append("# the main lockfile — except docutils, see below). Regenerate after")
    lines.append("# any requirements-tools-pinned.txt change.")
    lines.append("#")
    lines.append("# Known exception: docutils is pinned to the latest version compatible")
    lines.append("# with sphinx 8.2.3 (<0.22), NOT the main lockfile's 0.23 — sphinx")
    lines.append("# 8.2.3 cannot install with docutils 0.23. The tools lockfile installs")
    lines.append("# into separate venvs from the main lockfile, so the versions never mix.")
    lines.append("# The build profile (build/setuptools/wheel) is identical in both")
    lines.append("# lockfiles (ENG-10).")
    lines.append("")
    missing: list[tuple[str, str, str]] = []
    for name, version in resolved:
        try:
            files = _pypi_files(name, version)
        except Exception as exc:  # noqa: BLE001 - record and continue
            missing.append((name, version, str(exc)))
            lines.append(f"# {name}=={version}: NO HASHES (fetch failed: {exc})")
            lines.append(f"{name}=={version}")
            continue
        if not files:
            missing.append((name, version, "no files"))
            lines.append(f"# {name}=={version}: NO HASHES (no files on PyPI)")
            lines.append(f"{name}=={version}")
            continue
        hashes = sorted(
            {f"    --hash=sha256:{f['digests']['sha256']}" for f in files if f["digests"].get("sha256")}
        )
        lines.append(f"{name}=={version} \\")
        for index, hash_line in enumerate(hashes):
            suffix = " \\" if index < len(hashes) - 1 else ""
            lines.append(hash_line + suffix)
    if missing:
        raise RuntimeError(f"could not fetch hashes for: {missing}")
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="where to write the hashed lockfile",
    )
    args = parser.parse_args(argv)
    resolved = generate(args.output)
    print(f"wrote {args.output} ({len(resolved)} packages)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
