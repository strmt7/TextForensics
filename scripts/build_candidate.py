#!/usr/bin/env python3
"""Build a complete unpublished release candidate from a source SHA.

W10 rehearsal builder (the "first build" role): reproduces the exact
asset set ``.github/workflows/release.yml`` assembles -- wheel, sdist,
source tarball, CycloneDX + SPDX SBOMs (Syft, the version the workflow
pins), signed release notes, detached cosign signatures + bundles for
every payload, and SHA256SUMS -- plus a typed candidate manifest
(``candidate-manifest.json``) recording version, source SHA, tag, every
asset digest, the build inputs, and the signer policy.

The build is fully self-contained and shares no state with any other
build: a fresh checkout (``git archive <sha>``), a fresh venv built
from the system Python with the hash-pinned tools lockfile
(``requirements-tools-hashed.txt``: build 1.6.1, setuptools 84.2.1,
wheel 0.48.0 -- the exact release build profile, ENG-10), fixed
``SOURCE_DATE_EPOCH`` / ``PYTHONHASHSEED``, and all working files under
an absolute workdir on workspace disk outside any repo.

Signing is LOCAL-KEY rehearsal signing with a real Ed25519 key pair
generated in the workdir (never committed, never leaves the workdir).
The signatures are created with ``openssl pkeyutl`` and verified with
the REAL ``cosign verify-blob --key`` path -- see the documented
environment limitation below. The CI publication path signs keyless
via GitHub OIDC; that identity cannot be exercised on this VM (no OIDC
token) and is recorded in the manifest as the *expected* keyless
identity policy, not as a signature that exists. The second verifier
(``scripts/verify_candidate_second.py``) verifies the local-key
signatures with cosign and separately reports the keyless / provenance
/ CI items as unavailable-with-reason rather than passing them.

ENVIRONMENT LIMITATION (measured, not assumed): cosign v3.1.4
``sign-blob`` mandates ``--bundle``, and bundle creation POSTs to
Rekor (``/api/v1/log/entries``) and to the Sigstore timestamp
authority (``timestamp.sigstore.dev``). On this VM both POSTs time out
(curl: exit 000 after 30 s; cosign: ``context deadline exceeded``),
while GETs to the same hosts succeed (Rekor ``/api/v1/log``: HTTP 200
in ~1 s) and POSTs to ``api.github.com`` succeed (404 in 0.6 s) -- so
the egress proxy blocks POSTs to Sigstore hosts specifically, not
POSTs in general. Docker is not a route either (no daemon socket).
``cosign verify-blob --key --signature`` without a bundle ALSO queries
Rekor by default and fails the same way; it succeeds with
``--insecure-ignore-tlog``, which is semantically correct for
rehearsal signatures that were never submitted to Rekor (no
publication by design) and is recorded as such wherever it is used.
The keyless bundle path itself IS proven on this VM: cosign's own
release bundle verifies with ``verify-blob --bundle`` (see the W10-C
report for the exact command and output).

Provenance (DSSE/SLSA) bundles are NOT produced here: they come from
``actions/attest-build-provenance`` in CI and cannot be reproduced
locally. The manifest records them as unavailable with that reason.

Usage:
    python scripts/build_candidate.py --sha <full-sha> --workdir <abs path>
        [--repo <path to git repo>] [--cosign <path>] [--syft <path>]
        [--source-date-epoch 1704067200]

Exit codes: 0 built and manifest written; 1 build/verification of the
build failed; 2 the builder itself could not run (missing tool/input).

No remote writes are performed: no tag, no release, no push, no
registry contact. The candidate directory is unpublished by design.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

SOURCE_DATE_EPOCH = "1704067200"
MANIFEST_FORMAT = "textforensics-candidate-manifest/1"

# Expected keyless signer identity for the CI publication path, from
# docs/verification/promotion-boundary.md: the release workflow running
# on main. This is a HUMAN-ONLY decision still open (ENG-06 boundary);
# the value below is the policy the release workflow would assert, and
# is recorded here as an expectation, not as a verified signature.
EXPECTED_KEYLESS_IDENTITY = (
    "https://github.com/strmt7/TextForensics/.github/workflows/release.yml@refs/heads/main"
)
EXPECTED_KEYLESS_ISSUER = "https://token.actions.githubusercontent.com"

PAYLOAD_NAMES = (
    "wheel",
    "sdist",
    "source_tarball",
    "sbom_cdx",
    "sbom_spdx",
    "notes",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess:
    """Run a child; raise on failure with the tail of its output.

    stdin is DEVNULL: no child may block on an interactive prompt
    (cosign treats an empty COSIGN_PASSWORD as unset and prompts)."""
    proc = subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=1800,
        stdin=subprocess.DEVNULL if input_text is None else None,
    )
    if proc.returncode != 0:
        tail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
        detail = tail[-1] if tail else f"exit {proc.returncode}"
        raise RuntimeError(f"command failed ({' '.join(argv[:3])}...): {detail}")
    return proc


def read_version(checkout: Path) -> str:
    import tomllib

    with (checkout / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def fresh_checkout(repo: Path, sha: str, dest: Path) -> Path:
    """Extract exactly <sha> via git archive (no working-tree state).

    Starts from an empty directory: a previous build in the same
    directory leaves egg-info/ and build/ behind, and rebuilding over
    those leftovers produces a different wheel."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", sha],
        capture_output=True,
        timeout=600,
    )
    if archive.returncode != 0 or not archive.stdout:
        raise RuntimeError(f"git archive {sha} failed: {archive.stderr.decode()[:300]}")
    tar_path = dest.parent / (dest.name + ".tar")
    tar_path.write_bytes(archive.stdout)
    with tarfile.open(tar_path, "r") as archive_file:
        archive_file.extractall(dest, filter="data")
    tar_path.unlink()
    # Normalise mtimes so the sdist build does not depend on extraction time.
    epoch = int(SOURCE_DATE_EPOCH)
    for path in dest.rglob("*"):
        if path.is_symlink():
            continue
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    return dest


def fresh_venv(python: str, venv_dir: Path, tools_lockfile: Path) -> Path:
    """Create a venv from the system interpreter and install the pinned
    tools lockfile (hash-verified). Shares no packages with any other venv."""
    run([python, "-m", "venv", str(venv_dir)])
    venv_python = venv_dir / "bin" / "python"
    env = dict(os.environ)
    env["PIP_NO_CACHE_DIR"] = "1"
    env["TMPDIR"] = str(venv_dir.parent)
    # Retry with backoff: the egress proxy intermittently times out on
    # PyPI downloads (observed: consecutive venv setups failed with
    # ProxyError while the proxy was degraded, then recovered).
    last_error: Exception | None = None
    for attempt in (1, 2, 3):
        try:
            run(
                [
                    str(venv_python),
                    "-m",
                    "pip",
                    "install",
                    "--require-hashes",
                    "-r",
                    str(tools_lockfile),
                ],
                env=env,
            )
            return venv_python
        except RuntimeError as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(15 * attempt)
    raise RuntimeError(
        f"pip install of the tools lockfile failed after 3 attempts: {last_error}"
    ) from last_error


def build_distributions(venv_python: Path, checkout: Path, dist_dir: Path) -> list[Path]:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    env["PYTHONHASHSEED"] = "0"
    env["TMPDIR"] = str(dist_dir.parent)
    env["PIP_NO_CACHE_DIR"] = "1"
    # Clear the dist dir: a previous (failed) run may have left artifacts.
    for stale in dist_dir.iterdir():
        if stale.is_file():
            stale.unlink()
    run(
        [
            str(venv_python),
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            str(dist_dir),
        ],
        cwd=checkout,
        env=env,
    )
    built = sorted(dist_dir.iterdir())
    if len(built) != 2 or not any(p.suffix == ".whl" for p in built):
        raise RuntimeError(f"expected wheel + sdist, got: {[p.name for p in built]}")
    return built


def build_source_tarball(repo: Path, sha: str, version: str, dist_dir: Path) -> Path:
    target = dist_dir / f"textforensics-{version}-source.tar.gz"
    proc = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar.gz", "-o", str(target), sha],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git archive tarball failed: {proc.stderr[:300]}")
    return target


def build_notes(
    venv_python: Path, repo: Path, sha: str, candidate_dir: Path, workdir: Path
) -> tuple[Path, Path]:
    """Generate release notes with publish_release.py changelog.

    The changelog reads git history, so it runs in a detached worktree
    at exactly the candidate SHA (not in the git-archive checkout,
    which carries no .git directory, and not in the caller's repo,
    whose HEAD may be any branch). The worktree is removed afterwards.
    The notes embed a generation timestamp, so they are NOT
    byte-reproducible across runs; the second verifier compares them
    modulo the ``Generated:`` line instead of by digest.
    """
    wt = workdir / "notes-worktree"
    if wt.exists():
        run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)])
    run(["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), sha])
    try:
        notes_out = candidate_dir.parent / "release-notes.md"
        run(
            [
                str(venv_python),
                "scripts/publish_release.py",
                "changelog",
                "--output",
                str(notes_out),
            ],
            cwd=wt,
        )
    finally:
        run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)])
    notes = notes_out
    target = candidate_dir / "release-notes.md"
    shutil.copyfile(notes, target)
    checksum = candidate_dir / "release-notes.md.sha256"
    checksum.write_text(f"{sha256_file(target)}  release-notes.md\n", encoding="utf-8")
    return target, checksum


def build_sboms(syft: str, dist_dir: Path, candidate_dir: Path) -> tuple[Path, Path]:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    cdx = candidate_dir / "textforensics-sbom.cdx.json"
    spdx = candidate_dir / "textforensics-sbom.spdx.json"
    run([syft, str(dist_dir), "-o", f"cyclonedx-json={cdx}"], env=env)
    run([syft, str(dist_dir), "-o", f"spdx-json={spdx}"], env=env)
    for payload in (cdx, spdx):
        json.loads(payload.read_text(encoding="utf-8"))
    return cdx, spdx


def generate_keypair(key_dir: Path) -> tuple[Path, Path]:
    """Ephemeral local Ed25519 key pair (openssl). The private key is
    unencrypted PEM held only in the workdir and never committed; it is
    a throwaway rehearsal key, deleted with the workdir. The public key
    is a PEM PKIX key in exactly the format ``cosign verify-blob --key``
    accepts (proven in the W10-C report)."""
    key_dir.mkdir(parents=True, exist_ok=True)
    # A previous (failed) run may have left a key pair; remove any stale
    # pair first so generation never prompts.
    for stale in (key_dir / "cosign.key", key_dir / "cosign.pub"):
        if stale.exists():
            stale.unlink()
    key = key_dir / "cosign.key"
    pub = key_dir / "cosign.pub"
    run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)])
    run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)])
    return key, pub


def sign_all(key: Path, payloads: list[Path]) -> None:
    """Sign every payload with the ephemeral Ed25519 key (openssl
    ``pkeyutl -sign -rawin``), writing a base64 ``.sig`` file per
    payload -- the exact format ``cosign verify-blob --signature``
    reads. No ``.bundle`` files are produced: cosign v3.1.4 mandates
    ``--bundle`` for sign-blob, and bundle creation POSTs to Rekor and
    the Sigstore TSA, which this VM's egress proxy blocks (see the
    module docstring)."""
    for payload in payloads:
        raw = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(payload)],
            capture_output=True,
            timeout=120,
            stdin=subprocess.DEVNULL,
        )
        if raw.returncode != 0:
            raise RuntimeError(
                f"openssl sign failed for {payload.name}: {raw.stderr.decode()[:200]}"
            )
        import base64

        sig_path = payload.with_suffix(payload.suffix + ".sig")
        sig_path.write_bytes(base64.b64encode(raw.stdout) + b"\n")


def write_sha256sums(candidate_dir: Path) -> Path:
    sums = candidate_dir / "SHA256SUMS"
    lines = []
    for path in sorted(candidate_dir.iterdir()):
        if path.name == "SHA256SUMS" or not path.is_file():
            continue
        lines.append(f"{sha256_file(path)}  {path.name}\n")
    sums.write_text("".join(lines), encoding="utf-8")
    return sums


def build_manifest(
    candidate_dir: Path, *, version: str, sha: str, tag: str, build_info: dict, signer: dict
) -> dict:
    assets = []
    for path in sorted(candidate_dir.iterdir()):
        if not path.is_file():
            continue
        assets.append(
            {
                "name": path.name,
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    return {
        "format": MANIFEST_FORMAT,
        "version": version,
        "source_sha": sha,
        "tag": tag,
        "build": build_info,
        "assets": assets,
        "checksums_file": "SHA256SUMS",
        "notes_checksum_file": "release-notes.md.sha256",
        "signer": signer,
        "provenance": {
            "bundles": [],
            "unavailable": (
                "DSSE/SLSA provenance bundles are produced only by "
                "actions/attest-build-provenance in CI (release workflow); "
                "they cannot be produced locally and are absent from this "
                "unpublished rehearsal candidate."
            ),
        },
        "confirmation": {
            "env": "RELEASE_CONFIRMATION",
            "value": "RELEASE",
            "note": "Promotion requires this exact value; anything else refuses.",
        },
    }


def main(argv: list[str] | None = None) -> int:
    global SOURCE_DATE_EPOCH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True, help="Full candidate source SHA")
    parser.add_argument(
        "--repo", default=None, help="Path to a git repo to archive from (default: this repo)"
    )
    parser.add_argument(
        "--workdir", required=True, help="Absolute workdir on workspace disk, outside any repo"
    )
    parser.add_argument("--cosign", default="cosign", help="cosign binary")
    parser.add_argument("--syft", default="syft", help="syft binary")
    parser.add_argument(
        "--python", default="/usr/bin/python3.12", help="System Python for the fresh venv"
    )
    parser.add_argument("--source-date-epoch", default=SOURCE_DATE_EPOCH)
    args = parser.parse_args(argv)

    SOURCE_DATE_EPOCH = args.source_date_epoch

    repo = Path(args.repo) if args.repo else Path(__file__).resolve().parent.parent
    workdir = Path(args.workdir)
    if not workdir.is_absolute():
        print("error: --workdir must be an absolute path", file=sys.stderr)
        return 2
    cosign = shutil.which(args.cosign) or args.cosign
    if not cosign or not shutil.which(cosign):
        for candidate in (
            Path.home() / "workspace" / ".local" / "bin" / "cosign",
            Path.home() / ".local" / "bin" / "cosign",
        ):
            if candidate.exists():
                cosign = str(candidate)
                break
    syft = shutil.which(args.syft) or args.syft
    if not syft or not shutil.which(syft):
        for candidate in (
            Path.home() / "workspace" / ".local" / "bin" / "syft",
            Path.home() / ".local" / "bin" / "syft",
        ):
            if candidate.exists():
                syft = str(candidate)
                break
    for tool, path in (("cosign", cosign), ("syft", syft)):
        if not path or not shutil.which(path):
            print(
                f"error: {tool} binary not found: {args.cosign if tool == 'cosign' else args.syft}",
                file=sys.stderr,
            )
            return 2

    workdir.mkdir(parents=True, exist_ok=True)
    checkout = workdir / "checkout"
    venv_dir = workdir / "venv"
    candidate_dir = workdir / "candidate"
    candidate_dir.mkdir(parents=True, exist_ok=True)
    try:
        print(f"fresh checkout of {args.sha} ...")
        fresh_checkout(repo, args.sha, checkout)
        version = read_version(checkout)
        tag = f"v{version}"
        print(f"version {version}, tag {tag}")
        print("fresh venv + pinned tools lockfile ...")
        venv_python = fresh_venv(args.python, venv_dir, checkout / "requirements-tools-hashed.txt")
        versions = {}
        for mod in ("build", "setuptools", "wheel"):
            proc = run([str(venv_python), "-m", "pip", "show", mod])
            for line in proc.stdout.splitlines():
                if line.startswith("Version:"):
                    versions[mod] = line.split(":", 1)[1].strip()
        print("building wheel + sdist ...")
        dist_dir = workdir / "dist"
        dist_dir.mkdir(parents=True, exist_ok=True)
        built = build_distributions(venv_python, checkout, dist_dir)
        print("building source tarball ...")
        source = build_source_tarball(repo, args.sha, version, dist_dir)
        print("generating release notes ...")
        notes, notes_checksum = build_notes(venv_python, repo, args.sha, candidate_dir, workdir)
        for path in (*built, source):
            shutil.copyfile(path, candidate_dir / path.name)
        print("generating SBOMs with Syft ...")
        syft_proc = run([syft, "version"])
        syft_version = next(
            (
                ln.split(":", 1)[1].strip()
                for ln in syft_proc.stdout.splitlines()
                if ln.startswith("Version:")
            ),
            "unknown",
        )
        cdx, spdx = build_sboms(syft, dist_dir, candidate_dir)
        print("signing payloads with an ephemeral local Ed25519 key ...")
        key, pub = generate_keypair(workdir / "keys")
        payloads = [candidate_dir / p.name for p in (*built, source)] + [cdx, spdx, notes]
        sign_all(key, payloads)
        print("writing SHA256SUMS ...")
        write_sha256sums(candidate_dir)
        pub_sha = sha256_file(pub)
        cosign_proc = run([cosign, "version"])
        cosign_version = next(
            (
                ln.split(":", 1)[1].strip()
                for ln in cosign_proc.stdout.splitlines()
                if ln.startswith("GitVersion:")
            ),
            "unknown",
        )
        manifest = build_manifest(
            candidate_dir,
            version=version,
            sha=args.sha,
            tag=tag,
            build_info={
                "source_date_epoch": int(SOURCE_DATE_EPOCH),
                "python": run([str(venv_python), "--version"]).stdout.strip(),
                "build": versions.get("build"),
                "setuptools": versions.get("setuptools"),
                "wheel": versions.get("wheel"),
                "syft": syft_version,
                "cosign": cosign_version,
                "git": run(["git", "--version"]).stdout.strip(),
            },
            signer={
                "mode": "local-key",
                "public_key_sha256": pub_sha,
                "public_key_file": "keys/cosign.pub (workdir only, never published)",
                "expected_keyless_identity": EXPECTED_KEYLESS_IDENTITY,
                "expected_keyless_issuer": EXPECTED_KEYLESS_ISSUER,
                "note": (
                    "Rehearsal signatures are local-key (ephemeral Ed25519 "
                    "key in the workdir, signed with openssl pkeyutl, "
                    "base64 .sig per payload). No .bundle files exist: "
                    "cosign v3.1.4 sign-blob mandates --bundle, and bundle "
                    "creation POSTs to Rekor and the Sigstore TSA, which "
                    "this VM's egress proxy blocks (POSTs time out; GETs "
                    "succeed). The verifier checks these signatures with "
                    "the real cosign verify-blob --key --signature "
                    "--insecure-ignore-tlog path (correct here: rehearsal "
                    "signatures are never Rekor-logged by design). The CI "
                    "publication path signs keyless; its expected "
                    "identity/issuer are recorded above as policy, and no "
                    "keyless bundle exists for this candidate. The exact "
                    "keyless identity is a human-only decision still open "
                    "(docs/verification/promotion-boundary.md)."
                ),
            },
        )
        manifest_path = workdir / "candidate-manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(f"candidate: {candidate_dir}")
        print(f"manifest:  {manifest_path}")
        for asset in manifest["assets"]:
            print(f"  {asset['sha256']}  {asset['name']}")
        return 0
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
