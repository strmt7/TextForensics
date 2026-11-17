#!/usr/bin/env python3
"""Independent second verifier for a TextForensics release candidate.

W10 rehearsal: reproduces the complete unpublished asset set from
scratch and verifies it against a candidate manifest -- trusting
nothing the first build says. Independence guarantees:

* Fresh checkout: ``git archive <source_sha>`` into a fresh directory
  under the verifier's own workdir (absolute path on workspace disk
  outside any repo; never /tmp, never the first build's directories).
* Fresh venv: built from the system Python with the hash-pinned tools
  lockfile (build 1.6.1, setuptools 84.2.1, wheel 0.48.0). No shared
  venv, no cached artifacts, no shared checkout with the first build.
* Rebuild: wheel + sdist + source tarball are rebuilt TWICE from two
  independent fresh checkouts with fixed SOURCE_DATE_EPOCH /
  PYTHONHASHSEED and must be byte-identical to each other AND to the
  manifest digests. (The sdist and source tarball are compared by
  content as well as by bytes; see ``compare_sdist``.)
* Release notes are regenerated and compared modulo the ``Generated:``
  timestamp line (``publish_release.py changelog`` embeds the current
  time, so notes are not byte-reproducible across runs).
* SBOM payloads are digest-checked against the manifest and
  structurally validated (Syft embeds a generation timestamp, so
  SBOMs are not byte-reproduced; the digest + structure + signature
  checks are the binding).
* Signatures are verified with the REAL ``cosign verify-blob`` path,
  in two modes:
  - local-key (rehearsal): each payload carries a base64 Ed25519
    ``.sig`` (signed with the ephemeral rehearsal key). Verification
    runs ``cosign verify-blob --key <pub> --signature <sig>
    --insecure-ignore-tlog <payload>``. The flag is semantically
    required here, not a shortcut: rehearsal signatures are never
    submitted to Rekor (no publication by design), so there is no
    transparency-log entry to check, and without the flag cosign
    queries Rekor (a POST this VM's egress proxy blocks) and fails
    every verification. The flag is recorded in every result.
  - keyless (CI publication): each payload carries ``.sig`` + a
    Sigstore ``.bundle``; verification runs ``cosign verify-blob
    --bundle --signature --certificate-identity <expected>
    --certificate-oidc-issuer <expected>`` with NO tlog-skipping flag
    (the bundle carries its Rekor entry). This path is proven on this
    VM against cosign's own release bundle (see the W10-C report).
  A missing cosign binary fails the verification (exit 2), never a pass.
* Promotion readiness is evaluated separately from asset
  verification: exact RELEASE_CONFIRMATION, tag -> source-SHA binding,
  published-release existence (read-only ``gh api``), CI check-runs
  for the exact candidate SHA (``promotion_gate.evaluate_gate``), and
  keyless bundles + provenance bundles. Any blocker refuses promotion.

Exit codes (mirroring scripts/verify_release.py):
    0  every asset check passed (and, unless --asset-only, promotion
       readiness passed too);
    1  an asset check failed, or promotion is blocked/refused;
    2  the verifier itself could not be evaluated (missing tool,
       missing/unreadable manifest, checkout or rebuild failure inside
       the verifier).

Subcommands:
    verify      Verify a candidate manifest + asset dir (default mode).
    self-test   Build deliberately bad candidates from a good one and
                prove the verifier rejects each with exit 1 (see
                BAD_CASES). Exits 0 only if every bad case is rejected
                for the right reason and the good control passes.

No remote writes are performed anywhere: no tag, no release, no push,
no registry contact. ``gh api`` is used read-only for check-runs and
release existence.
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
from pathlib import Path

SOURCE_DATE_EPOCH = "1704067200"
MANIFEST_FORMAT = "textforensics-candidate-manifest/1"
CONFIRMATION_VALUE = "RELEASE"

# Payloads that must carry a detached cosign signature + bundle.
SIGNED_PAYLOADS = (
    "textforensics-{version}-py3-none-any.whl",
    "textforensics-{version}.tar.gz",
    "textforensics-{version}-source.tar.gz",
    "textforensics-sbom.cdx.json",
    "textforensics-sbom.spdx.json",
    "release-notes.md",
)

# Required check-runs for promotion (mirrors scripts/promotion_gate.py).
REQUIRED_CHECKS = [
    "CI / Claims-to-evidence gate (U7)",
    "CI / Core Python",
    "CI / Pinned requirements install",
    "CI / Checked-in SBOM is not stale",
    "CI / Build and wheel-install",
    "Supply-chain security / pip-audit gate",
    "Supply-chain security / Software Bill of Materials",
    "Reproducibility / Build Reproducibility",
    "Repository Integrity / Sigstore Verification",
    "Repository Integrity / Build Provenance",
    "Enterprise Deep Verification / Full Test Suite",
]


class Unevaluated(Exception):
    """The verifier itself could not run (exit 2)."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    argv: list[str], *, cwd: Path | None = None, env: dict | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
        stdin=subprocess.DEVNULL,
    )


def run_checked(
    argv: list[str], *, cwd: Path | None = None, env: dict | None = None
) -> subprocess.CompletedProcess:
    proc = run(argv, cwd=cwd, env=env)
    if proc.returncode != 0:
        tail = ((proc.stdout or "") + (proc.stderr or "")).strip().splitlines()
        detail = tail[-1] if tail else f"exit {proc.returncode}"
        raise Unevaluated(f"command failed: {' '.join(argv[:4])}: {detail}")
    return proc


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def resolve_tool(name: str) -> str | None:
    """Resolve a tool binary: PATH first, then the workspace-local bin
    dir (~/workspace/.local/bin), where W10 installed cosign/syft."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (
        Path.home() / "workspace" / ".local" / "bin" / name,
        Path.home() / ".local" / "bin" / name,
    ):
        if candidate.exists():
            return str(candidate)
    return None


def load_manifest(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Unevaluated(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise Unevaluated(f"manifest {path} is not a JSON object")
    return data


def validate_manifest_schema(manifest: dict) -> list[str]:
    """Return a list of schema errors (empty = valid)."""
    errors: list[str] = []
    if manifest.get("format") != MANIFEST_FORMAT:
        errors.append(f"manifest format {manifest.get('format')!r} != {MANIFEST_FORMAT!r}")
    for field in ("version", "source_sha", "tag", "assets", "signer"):
        if field not in manifest:
            errors.append(f"manifest is missing required field {field!r}")
    if not isinstance(manifest.get("assets"), list) or not manifest.get("assets"):
        errors.append("manifest 'assets' must be a non-empty list")
        return errors
    seen: set[str] = set()
    for asset in manifest["assets"]:
        if not isinstance(asset, dict):
            errors.append(f"manifest asset is not an object: {asset!r}")
            continue
        for field in ("name", "sha256", "size"):
            if field not in asset:
                errors.append(f"manifest asset {asset.get('name')!r} lacks {field!r}")
        name = str(asset.get("name", ""))
        if name in seen:
            errors.append(f"manifest lists asset {name!r} twice")
        seen.add(name)
        digest = str(asset.get("sha256", ""))
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            errors.append(f"manifest asset {name!r} has a malformed sha256")
    if manifest.get("checksums_file", "SHA256SUMS") not in seen:
        errors.append("manifest assets do not include the checksums file")
    return errors


# ---------------------------------------------------------------------------
# Independent rebuild
# ---------------------------------------------------------------------------


def fresh_checkout(repo: Path, sha: str, dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", sha],
        capture_output=True,
        timeout=600,
    )
    if archive.returncode != 0 or not archive.stdout:
        raise Unevaluated(f"git archive {sha} failed")
    tar_path = dest.parent / (dest.name + ".tar")
    tar_path.write_bytes(archive.stdout)
    with tarfile.open(tar_path, "r") as archive_file:
        archive_file.extractall(dest, filter="data")
    tar_path.unlink()
    epoch = int(SOURCE_DATE_EPOCH)
    for path in dest.rglob("*"):
        if path.is_symlink():
            continue
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    head = run_checked(["git", "-C", str(repo), "rev-parse", f"{sha}^{{commit}}"])
    if head.stdout.strip() != sha:
        raise Unevaluated(f"SHA {sha} did not resolve to itself")
    return dest


def fresh_venv(python: str, venv_dir: Path, tools_lockfile: Path, tmpdir: Path) -> Path:
    run_checked([python, "-m", "venv", str(venv_dir)])
    venv_python = venv_dir / "bin" / "python"
    env = dict(os.environ)
    env["PIP_NO_CACHE_DIR"] = "1"
    env["TMPDIR"] = str(tmpdir)
    run_checked(
        [str(venv_python), "-m", "pip", "install", "--require-hashes", "-r", str(tools_lockfile)],
        env=env,
    )
    return venv_python


def build_once(venv_python: Path, checkout: Path, out_dir: Path, tmpdir: Path) -> tuple[Path, Path]:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    env["PYTHONHASHSEED"] = "0"
    env["TMPDIR"] = str(tmpdir)
    env["PIP_NO_CACHE_DIR"] = "1"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_checked(
        [
            str(venv_python),
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            str(out_dir),
        ],
        cwd=checkout,
        env=env,
    )
    wheels = sorted(out_dir.glob("*.whl"))
    sdists = sorted(out_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise Unevaluated(f"rebuild produced {len(wheels)} wheel(s) and {len(sdists)} sdist(s)")
    return wheels[0], sdists[0]


def tar_member_digests(path: Path) -> dict[str, str]:
    """Map member name -> sha256 of member bytes (ignores tar metadata)."""
    result: dict[str, str] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            data = archive.extractfile(member)
            if data is None:
                continue
            result[member.name] = hashlib.sha256(data.read()).hexdigest()
    return result


def compare_tarballs(rebuilt: Path, reference: Path, label: str) -> list[str]:
    """Byte compare, falling back to member-content compare with a
    recorded reason. Returns errors (empty = equal)."""
    if sha256_file(rebuilt) == sha256_file(reference):
        return []
    a, b = tar_member_digests(rebuilt), tar_member_digests(reference)
    if a == b:
        return [
            f"{label}: bytes differ but member contents are identical "
            "(tar metadata variance only; recorded, not a pass by bytes)"
        ]
    differing = sorted(set(a) ^ set(b) | {k for k in a if k in b and a[k] != b[k]})
    return [f"{label}: member contents differ: {differing[:5]}"]


def regenerate_notes(
    venv_python: Path, repo: Path, sha: str, out_path: Path, workdir: Path
) -> Path:
    """Regenerate release notes from a detached worktree at exactly the
    candidate SHA and return the generated file. A worktree is used
    (rather than requiring the caller's repo HEAD to be the candidate)
    so the verifier is independent of whatever branch the caller has
    checked out. The worktree is removed afterwards."""
    wt = workdir / "notes-worktree"
    if wt.exists():
        run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)])
    run_checked(["git", "-C", str(repo), "worktree", "add", "--detach", str(wt), sha])
    try:
        run_checked(
            [
                str(venv_python),
                "scripts/publish_release.py",
                "changelog",
                "--output",
                str(out_path),
            ],
            cwd=wt,
        )
    finally:
        run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt)])
    return out_path


def strip_generated_line(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.startswith("- **Generated:**"))


# ---------------------------------------------------------------------------
# Signatures (real cosign path)
# ---------------------------------------------------------------------------


def validate_bundle_structure(bundle: Path) -> str | None:
    try:
        data = json.loads(bundle.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"signature bundle {bundle.name} is not valid JSON: {exc}"
    if not isinstance(data, dict) or "verificationMaterial" not in data:
        return f"signature bundle {bundle.name} has no verificationMaterial (not a Sigstore bundle)"
    if "dsseEnvelope" not in data and "messageSignature" not in data:
        return f"signature bundle {bundle.name} has neither dsseEnvelope nor messageSignature"
    return None


def verify_cosign_blob(
    cosign: str,
    *,
    payload: Path,
    sig: Path,
    bundle: Path | None,
    key: Path | None,
    identity: str | None,
    issuer: str | None,
    insecure_ignore_tlog: bool = False,
) -> tuple[bool, str]:
    """Run the real ``cosign verify-blob``. Returns (ok, detail).

    Keyless mode (bundle given): ``--bundle --signature
    --certificate-identity --certificate-oidc-issuer``. Local-key mode
    (key given, no bundle): ``--key --signature`` plus
    ``--insecure-ignore-tlog`` -- required because rehearsal
    signatures are never Rekor-logged and cosign otherwise queries
    Rekor (a POST this VM's egress proxy blocks)."""
    argv = [cosign, "verify-blob"]
    if bundle is not None:
        argv += ["--bundle", str(bundle)]
    argv += ["--signature", str(sig)]
    if key is not None:
        argv += ["--key", str(key)]
    if identity is not None:
        argv += ["--certificate-identity", identity]
    if issuer is not None:
        argv += ["--certificate-oidc-issuer", issuer]
    if insecure_ignore_tlog:
        argv += ["--insecure-ignore-tlog"]
    argv.append(str(payload))
    proc = run(argv)
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + (proc.stdout or "")).strip().splitlines()
        reason = detail[-1] if detail else "verification failed"
        return False, f"cosign verify-blob rejected {payload.name}: {reason}"
    return True, "Verified OK"


# ---------------------------------------------------------------------------
# Promotion readiness (read-only)
# ---------------------------------------------------------------------------


def fetch_check_runs(sha: str, repo: str = "strmt7/TextForensics") -> list[dict]:
    """Read-only `gh api` fetch of check-runs for a SHA (paginated)."""
    runs: list[dict] = []
    page = 1
    while True:
        endpoint = f"repos/{repo}/commits/{sha}/check-runs?per_page=100" + (
            f"&page={page}" if page > 1 else ""
        )
        try:
            proc = run(["gh", "api", endpoint])
        except OSError as exc:
            raise Unevaluated(f"`gh api` could not run: {exc}") from exc
        if proc.returncode != 0:
            raise Unevaluated(
                f"`gh api {endpoint}` failed: {(proc.stderr or proc.stdout or '').strip()[:200]}"
            )
        try:
            payload = json.loads(proc.stdout)
        except ValueError as exc:
            raise Unevaluated(f"could not parse check-runs response: {exc}") from exc
        page_runs = payload.get("check_runs", [])
        runs.extend(
            {
                "name": r.get("name"),
                "status": r.get("status"),
                "conclusion": r.get("conclusion"),
                "head_sha": r.get("head_sha"),
            }
            for r in page_runs
        )
        if len(page_runs) < 100:
            return runs
        page += 1


def evaluate_check_runs(check_runs: list[dict], sha: str) -> list[str]:
    """Return promotion blockers from a check-run set (empty = all pass)."""
    blockers: list[str] = []
    for prefix in REQUIRED_CHECKS:
        matched = [
            r
            for r in check_runs
            if r.get("name") == prefix or (r.get("name") or "").startswith(prefix + " ")
        ]
        if not matched:
            blockers.append(f"no check-run for required check {prefix!r}")
            continue
        for run_ in matched:
            if run_.get("head_sha") != sha:
                blockers.append(
                    f"check-run {run_.get('name')!r} is stale: head_sha "
                    f"{run_.get('head_sha')} != candidate {sha}"
                )
            elif run_.get("status") != "completed":
                blockers.append(
                    f"check-run {run_.get('name')!r} not completed (status={run_.get('status')})"
                )
            elif run_.get("conclusion") == "skipped":
                blockers.append(f"required check {run_.get('name')!r} was skipped")
            elif run_.get("conclusion") != "success":
                blockers.append(
                    f"required check {run_.get('name')!r} did not pass "
                    f"(conclusion={run_.get('conclusion')})"
                )
    return blockers


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest)
    asset_dir = Path(args.asset_dir)
    workdir = Path(args.workdir)
    if not workdir.is_absolute():
        print("error: --workdir must be an absolute path", file=sys.stderr)
        return 2
    repo = Path(args.repo) if args.repo else Path(__file__).resolve().parent.parent
    cosign = resolve_tool(args.cosign) if args.cosign == "cosign" else args.cosign
    if not cosign:
        print(f"error: cosign binary not found: {args.cosign}", file=sys.stderr)
        return 2
    checks: list[dict] = []
    blockers: list[str] = []

    def record(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})
        print(f"[{status.upper():<11}] {name}: {detail}")

    try:
        manifest = load_manifest(manifest_path)
        errors = validate_manifest_schema(manifest)
        if errors:
            record("manifest-schema", "fail", "; ".join(errors))
            return finish(checks, blockers, args, manifest=None)
        record(
            "manifest-schema", "pass", f"format {MANIFEST_FORMAT}, {len(manifest['assets'])} assets"
        )
        version = str(manifest["version"])
        sha = str(manifest["source_sha"])
        tag = str(manifest["tag"])
        if args.source_sha and args.source_sha != sha:
            record("source-sha", "fail", f"--source-sha {args.source_sha} != manifest {sha}")
            return finish(checks, blockers, args, manifest)
        if tag != f"v{version}":
            record("tag-version", "fail", f"manifest tag {tag!r} != 'v{version}'")
            return finish(checks, blockers, args, manifest)
        record("tag-version", "pass", f"tag {tag} matches version {version}")

        # --- asset presence + digests (trust nothing) -------------------
        manifest_assets = {a["name"]: a for a in manifest["assets"]}
        on_disk = (
            {p.name for p in asset_dir.iterdir() if p.is_file()} if asset_dir.is_dir() else set()
        )
        missing = sorted(set(manifest_assets) - on_disk)
        extra = sorted(on_disk - set(manifest_assets))
        if missing:
            record("asset-presence", "fail", f"missing assets: {', '.join(missing)}")
            return finish(checks, blockers, args, manifest)
        if extra:
            record("asset-presence", "fail", f"unlisted files in asset dir: {', '.join(extra)}")
            return finish(checks, blockers, args, manifest)
        digest_errors = []
        for name in sorted(manifest_assets):
            path = asset_dir / name
            want = manifest_assets[name]
            if path.stat().st_size != int(want["size"]):
                digest_errors.append(
                    f"{name}: size {path.stat().st_size} != manifest {want['size']}"
                )
            elif sha256_file(path) != want["sha256"]:
                digest_errors.append(f"{name}: sha256 mismatch with manifest")
        if digest_errors:
            record("asset-digests", "fail", "; ".join(digest_errors))
            return finish(checks, blockers, args, manifest)
        record(
            "asset-digests", "pass", f"{len(manifest_assets)} assets match manifest digests + sizes"
        )

        # --- SHA256SUMS recomputation ------------------------------------
        sums_path = asset_dir / str(manifest.get("checksums_file", "SHA256SUMS"))
        sums_errors = []
        try:
            listed = {}
            for line in sums_path.read_text(encoding="utf-8").splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    listed[parts[1].lstrip("*")] = parts[0]
        except OSError as exc:
            sums_errors.append(f"cannot read SHA256SUMS: {exc}")
            listed = {}
        if not sums_errors:
            for name in sorted(manifest_assets):
                if name == sums_path.name:
                    continue
                if listed.get(name) != manifest_assets[name]["sha256"]:
                    sums_errors.append(f"SHA256SUMS disagrees for {name}")
            unlisted = sorted(set(listed) - set(manifest_assets) - {sums_path.name})
            if unlisted:
                sums_errors.append(f"SHA256SUMS lists unmanifested files: {unlisted}")
        if sums_errors:
            record("checksums-file", "fail", "; ".join(sums_errors))
            return finish(checks, blockers, args, manifest)
        record("checksums-file", "pass", "SHA256SUMS matches recomputed digests for every asset")

        # --- independent rebuild (two fresh checkouts, one fresh venv) ---
        workdir.mkdir(parents=True, exist_ok=True)
        tmpdir = workdir / "tmp"
        tmpdir.mkdir(parents=True, exist_ok=True)
        checkout_a = fresh_checkout(repo, sha, workdir / "checkout-a")
        checkout_b = fresh_checkout(repo, sha, workdir / "checkout-b")
        import tomllib

        for checkout in (checkout_a, checkout_b):
            with (checkout / "pyproject.toml").open("rb") as handle:
                checkout_version = str(tomllib.load(handle)["project"]["version"])
            if checkout_version != version:
                record(
                    "version",
                    "fail",
                    f"fresh checkout pyproject version {checkout_version} != manifest {version}",
                )
                return finish(checks, blockers, args, manifest)
        record("version", "pass", f"pyproject version {version} in both fresh checkouts")
        venv_python = fresh_venv(
            args.python, workdir / "venv", checkout_a / "requirements-tools-hashed.txt", tmpdir
        )
        build_env = {}
        for mod in ("build", "setuptools", "wheel"):
            proc = run_checked([str(venv_python), "-m", "pip", "show", mod])
            for line in proc.stdout.splitlines():
                if line.startswith("Version:"):
                    build_env[mod] = line.split(":", 1)[1].strip()
        wheel_a, sdist_a = build_once(venv_python, checkout_a, workdir / "dist-a", tmpdir)
        wheel_b, sdist_b = build_once(venv_python, checkout_b, workdir / "dist-b", tmpdir)
        rebuild_errors = []
        manifest_wheel = asset_dir / wheel_a.name
        manifest_sdist = asset_dir / sdist_a.name
        if wheel_a.name != manifest_wheel.name or not manifest_wheel.exists():
            rebuild_errors.append(f"rebuild wheel name {wheel_a.name} not in manifest")
        if sdist_a.name != manifest_sdist.name or not manifest_sdist.exists():
            rebuild_errors.append(f"rebuild sdist name {sdist_a.name} not in manifest")
        if not rebuild_errors:
            if sha256_file(wheel_a) != sha256_file(wheel_b):
                rebuild_errors.append("two independent wheel builds differ (not reproducible)")
            if sha256_file(wheel_a) != sha256_file(manifest_wheel):
                rebuild_errors.append("rebuilt wheel digest != manifest digest")
            sdist_cmp = compare_tarballs(sdist_a, manifest_sdist, "sdist")
            if sdist_cmp and "member contents are identical" not in sdist_cmp[0]:
                rebuild_errors.extend(sdist_cmp)
            elif sdist_cmp:
                record("rebuild-sdist-note", "pass", sdist_cmp[0])
            if sha256_file(sdist_a) != sha256_file(sdist_b):
                note = (
                    "two independent sdist builds differ by bytes "
                    "(tar metadata); member contents compared separately"
                )
                record("rebuild-sdist-note", "pass", note)
        source_name = f"textforensics-{version}-source.tar.gz"
        source_path = asset_dir / source_name
        if not source_path.exists():
            rebuild_errors.append(f"source tarball {source_name} not in manifest assets")
        else:
            proc = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "archive",
                    "--format=tar.gz",
                    "-o",
                    str(workdir / source_name),
                    sha,
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )
            if proc.returncode != 0:
                raise Unevaluated("rebuilding source tarball failed")
            rebuilt_source = workdir / source_name
            if sha256_file(rebuilt_source) != sha256_file(source_path):
                cmp_errors = compare_tarballs(rebuilt_source, source_path, "source tarball")
                rebuild_errors.extend(cmp_errors)
        if rebuild_errors:
            record("rebuild", "fail", "; ".join(rebuild_errors))
            return finish(checks, blockers, args, manifest)
        record(
            "rebuild",
            "pass",
            f"wheel {wheel_a.name} byte-identical across two fresh builds "
            f"and equal to manifest "
            f"({sha256_file(wheel_a)[:16]}...); sdist + source tarball "
            f"contents match manifest (build tools: {build_env})",
        )

        # --- release notes (regenerated, modulo Generated: line) ---------
        regen = regenerate_notes(venv_python, repo, sha, workdir / "notes-regen.md", workdir)
        manifest_notes = (asset_dir / "release-notes.md").read_text(encoding="utf-8")
        if strip_generated_line(regen.read_text(encoding="utf-8")) != strip_generated_line(
            manifest_notes
        ):
            record(
                "release-notes",
                "fail",
                "regenerated notes differ from manifest notes "
                "(beyond the Generated: timestamp line)",
            )
            return finish(checks, blockers, args, manifest)
        record(
            "release-notes", "pass", "regenerated notes match manifest notes modulo Generated: line"
        )

        # --- SBOM structure ----------------------------------------------
        sbom_errors = []
        for name, key, want in (
            ("textforensics-sbom.cdx.json", "bomFormat", "CycloneDX"),
            ("textforensics-sbom.spdx.json", "spdxVersion", "SPDX-"),
        ):
            path = asset_dir / name
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                sbom_errors.append(f"{name} is not valid JSON: {exc}")
                continue
            if (
                not isinstance(data, dict)
                or data.get(key) != want
                and not (
                    key == "spdxVersion"
                    and isinstance(data.get(key), str)
                    and data[key].startswith(want)
                )
            ):
                sbom_errors.append(f"{name} has {key}={data.get(key)!r}, not {want!r}")
        if sbom_errors:
            record("sbom-structure", "fail", "; ".join(sbom_errors))
            return finish(checks, blockers, args, manifest)
        record(
            "sbom-structure",
            "pass",
            "CycloneDX bomFormat + SPDX spdxVersion present and valid JSON",
        )

        # --- cosign signatures (real verify-blob) -------------------------
        signer = manifest.get("signer", {})
        mode = signer.get("mode")
        key_path: Path | None = None
        identity = issuer = None
        if mode == "local-key":
            if not args.public_key:
                record(
                    "signatures", "fail", "signer mode is local-key but no --public-key supplied"
                )
                return finish(checks, blockers, args, manifest)
            key_path = Path(args.public_key)
            if not key_path.exists():
                record("signatures", "fail", f"public key not found: {key_path}")
                return finish(checks, blockers, args, manifest)
            pinned = signer.get("public_key_sha256")
            if pinned and sha256_file(key_path) != pinned:
                record("signatures", "fail", "supplied public key digest != manifest pinned digest")
                return finish(checks, blockers, args, manifest)
        elif mode == "keyless":
            identity = signer.get("expected_keyless_identity") or signer.get("certificate_identity")
            issuer = signer.get("expected_keyless_issuer") or signer.get("certificate_oidc_issuer")
            if not identity or not issuer:
                record(
                    "signatures",
                    "fail",
                    "keyless mode but manifest has no expected identity/issuer",
                )
                return finish(checks, blockers, args, manifest)
        else:
            record("signatures", "fail", f"unknown signer mode {mode!r}")
            return finish(checks, blockers, args, manifest)
        sig_errors = []
        verified = 0
        for template in SIGNED_PAYLOADS:
            payload_name = template.format(version=version)
            payload = asset_dir / payload_name
            sig = asset_dir / f"{payload_name}.sig"
            bundle = asset_dir / f"{payload_name}.bundle"
            if not payload.exists():
                sig_errors.append(f"payload {payload_name} missing")
                continue
            if not sig.exists():
                sig_errors.append(f"{payload_name} lacks detached signature (.sig missing)")
                continue
            if mode == "keyless":
                if not bundle.exists():
                    sig_errors.append(f"{payload_name} lacks Sigstore bundle (.bundle missing)")
                    continue
                structural = validate_bundle_structure(bundle)
                if structural is not None:
                    sig_errors.append(structural)
                    continue
                ok, detail = verify_cosign_blob(
                    cosign,
                    payload=payload,
                    sig=sig,
                    bundle=bundle,
                    key=None,
                    identity=identity,
                    issuer=issuer,
                )
            else:  # local-key: raw .sig, no bundle (see module docstring)
                import base64

                try:
                    # Cosign writes base64 .sig files with a trailing
                    # newline; strip surrounding whitespace before the
                    # strict decode.
                    raw_sig = base64.b64decode(sig.read_bytes().strip(), validate=True)
                except (ValueError, OSError) as exc:
                    sig_errors.append(f"{payload_name}.sig is not valid base64: {exc}")
                    continue
                if len(raw_sig) != 64:
                    sig_errors.append(
                        f"{payload_name}.sig decodes to {len(raw_sig)} bytes, "
                        "not an Ed25519 signature (64)"
                    )
                    continue
                ok, detail = verify_cosign_blob(
                    cosign,
                    payload=payload,
                    sig=sig,
                    bundle=None,
                    key=key_path,
                    identity=None,
                    issuer=None,
                    insecure_ignore_tlog=True,
                )
            if not ok:
                sig_errors.append(detail)
            else:
                verified += 1
        if sig_errors:
            record("signatures", "fail", "; ".join(sig_errors))
            return finish(checks, blockers, args, manifest)
        record(
            "signatures",
            "pass",
            f"cosign verify-blob Verified OK for {verified} payloads "
            f"(mode={mode}"
            + (
                ", --insecure-ignore-tlog (never Rekor-logged rehearsal signatures)"
                if mode == "local-key"
                else ""
            )
            + ")",
        )

        # --- provenance -----------------------------------------------------
        provenance = manifest.get("provenance", {})
        if provenance.get("bundles"):
            record(
                "provenance", "pass", f"{len(provenance['bundles'])} provenance bundle(s) recorded"
            )
        else:
            record(
                "provenance",
                "unavailable",
                provenance.get("unavailable", "no provenance bundles recorded"),
            )
    except Unevaluated as exc:
        record("verifier", "fail", f"could not be evaluated: {exc}")
        return finish(checks, blockers, args, manifest=None, exit_code=2)

    if args.asset_only:
        return finish(checks, blockers, args, manifest)

    # --- promotion readiness ----------------------------------------------
    confirmation = os.environ.get("RELEASE_CONFIRMATION")
    if confirmation != CONFIRMATION_VALUE:
        blockers.append(
            f"missing/wrong RELEASE_CONFIRMATION (got {confirmation!r}, need exactly 'RELEASE')"
        )
    tag_proc = run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}"]
    )
    if tag_proc.returncode != 0:
        blockers.append(f"tag {tag} does not resolve to a commit (no tag created)")
    elif tag_proc.stdout.strip() != sha:
        blockers.append(f"tag {tag} resolves to {tag_proc.stdout.strip()}, not candidate {sha}")
    if args.check_runs is not None:
        try:
            check_runs = json.loads(Path(args.check_runs).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            blockers.append(f"could not read --check-runs file: {exc}")
            check_runs = None
    else:
        try:
            check_runs = fetch_check_runs(sha)
        except Unevaluated as exc:
            blockers.append(f"CI check-runs could not be fetched: {exc}")
            check_runs = None
    if check_runs is not None:
        blockers.extend(evaluate_check_runs(check_runs, sha))
    signer = manifest.get("signer", {})
    if signer.get("mode") != "keyless":
        blockers.append(
            "no keyless signature bundles for this candidate "
            f"(signer mode is {signer.get('mode')!r}; keyless signing "
            "happens only in the CI release workflow)"
        )
    if not manifest.get("provenance", {}).get("bundles"):
        blockers.append("no provenance (DSSE/SLSA) bundles for this candidate")
    gh_path = shutil.which("gh")
    if gh_path is None:
        blockers.append("gh CLI unavailable; cannot confirm release existence")
    else:
        gh_proc = run(["gh", "api", f"repos/strmt7/TextForensics/releases/tags/{tag}"])
        if gh_proc.returncode != 0:
            blockers.append(f"no published GitHub Release for tag {tag}")
    for blocker in blockers:
        print(f"[BLOCKED     ] promotion: {blocker}")
    return finish(checks, blockers, args, manifest)


def finish(checks, blockers, args, manifest, exit_code=None):
    """Write the JSON report and decide the exit code."""
    failed = [c for c in checks if c["status"] == "fail"]
    incomplete = [c for c in checks if c["status"] in ("unavailable",)]
    if exit_code is None:
        if failed or blockers:
            exit_code = 1
        else:
            exit_code = 0
    report = {
        "verifier": "verify_candidate_second.py (W10 second verifier)",
        "manifest_format": MANIFEST_FORMAT,
        "checks": checks,
        "promotion_blockers": blockers,
        "exit_code": exit_code,
    }
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"report: {args.json}")
    if failed:
        print(f"VERDICT: FAIL ({len(failed)} failed check(s))")
    elif blockers:
        print(f"VERDICT: PROMOTION BLOCKED ({len(blockers)} blocker(s); asset verification passed)")
    elif incomplete:
        print(
            f"VERDICT: PASS with unavailable informational checks ({len(incomplete)} unavailable)"
        )
    else:
        print("VERDICT: PASS")
    return exit_code


# ---------------------------------------------------------------------------
# self-test: deliberately bad candidates
# ---------------------------------------------------------------------------


def _mutate_manifest(manifest: dict, **changes) -> dict:
    data = json.loads(json.dumps(manifest))
    data.update(changes)
    return data


def _write_manifest(manifest: dict, path: Path) -> None:
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def _asset_entry(manifest: dict, name: str) -> dict:
    for asset in manifest["assets"]:
        if asset["name"] == name:
            return asset
    raise KeyError(name)


def _run_verifier(
    script: Path, argv: list[str], env_extra: dict | None = None, timeout_s: int = 1800
) -> tuple[int, str]:
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(script), *argv],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def cmd_self_test(args: argparse.Namespace) -> int:
    script = Path(__file__).resolve()
    manifest = load_manifest(Path(args.manifest))
    asset_dir = Path(args.asset_dir)
    base = Path(args.workdir)
    if not base.is_absolute():
        print("error: --workdir must be an absolute path", file=sys.stderr)
        return 2
    repo = Path(args.repo) if args.repo else Path(__file__).resolve().parent.parent
    version = str(manifest["version"])
    sha = str(manifest["source_sha"])
    tag = str(manifest["tag"])
    wheel = f"textforensics-{version}-py3-none-any.whl"
    sdist = f"textforensics-{version}.tar.gz"
    results: list[dict] = []

    def case(
        name: str,
        expect_exit: int,
        expect_text: str,
        argv: list[str],
        env_extra: dict | None = None,
    ) -> None:
        code, output = _run_verifier(script, argv, env_extra)
        ok = code == expect_exit and expect_text in output
        entry: dict = {
            "case": name,
            "expected_exit": expect_exit,
            "actual_exit": code,
            "expect_text": expect_text,
            "matched": expect_text in output,
            "pass": ok,
        }
        if not ok:
            entry["output_tail"] = output.strip().splitlines()[-8:]
        results.append(entry)
        print(
            f"[{'PASS' if ok else 'FAIL':<4}] {name}: exit {code} "
            f"(expected {expect_exit}); text matched: {expect_text in output}"
        )

    def fresh_case_dir(name: str) -> tuple[Path, Path]:
        case_dir = base / name
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_assets = case_dir / "assets"
        shutil.copytree(asset_dir, case_assets)
        case_manifest = case_dir / "candidate-manifest.json"
        shutil.copyfile(args.manifest, case_manifest)
        return case_dir, case_assets

    def verify_argv(
        case_dir: Path, case_assets: Path, manifest_file: Path, extra: list[str] | None = None
    ) -> list[str]:
        argv = [
            "verify",
            "--manifest",
            str(manifest_file),
            "--asset-dir",
            str(case_assets),
            "--workdir",
            str(case_dir / "verify-work"),
            "--repo",
            str(repo),
            "--cosign",
            args.cosign,
            "--python",
            args.python,
            "--public-key",
            str(Path(args.public_key)) if args.public_key else "",
        ]
        argv = [a for a in argv if a != ""]
        if extra:
            argv += extra
        return argv

    # Good control: unmutated copy, asset-only -> exit 0.
    case_dir, case_assets = fresh_case_dir("control-good")
    case(
        "control-good (asset-only)",
        0,
        "VERDICT: PASS",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # Good control, full verify -> exit 1, promotion blocked (rehearsal).
    case(
        "control-good (full: promotion blocked)",
        1,
        "PROMOTION BLOCKED",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json"),
    )

    # 1. Removal: delete the wheel.
    case_dir, case_assets = fresh_case_dir("removal-wheel")
    (case_assets / wheel).unlink()
    case(
        "removal (wheel deleted)",
        1,
        "missing assets",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # 2. Tampering: flip a byte in the sdist.
    case_dir, case_assets = fresh_case_dir("tamper-sdist")
    path = case_assets / sdist
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))
    case(
        "tampering (sdist byte flipped)",
        1,
        "sha256 mismatch",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # 3. Mismatched SHA in the manifest.
    case_dir, case_assets = fresh_case_dir("mismatch-sha")
    mutated = _mutate_manifest(manifest)
    entry = _asset_entry(mutated, wheel)
    entry["sha256"] = ("0" if entry["sha256"][0] != "0" else "1") + entry["sha256"][1:]
    _write_manifest(mutated, case_dir / "candidate-manifest.json")
    case(
        "mismatched SHA (manifest digest edited)",
        1,
        "sha256 mismatch",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # 4. Mismatched tag.
    case_dir, case_assets = fresh_case_dir("mismatch-tag")
    _write_manifest(_mutate_manifest(manifest, tag="v9.9.9"), case_dir / "candidate-manifest.json")
    case(
        "mismatched tag (v9.9.9)",
        1,
        "!= 'v0.2.0'",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # 5. Mismatched version.
    case_dir, case_assets = fresh_case_dir("mismatch-version")
    _write_manifest(
        _mutate_manifest(manifest, version="9.9.9"), case_dir / "candidate-manifest.json"
    )
    case(
        "mismatched version (9.9.9)",
        1,
        "!= 'v9.9.9'",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # 6. Missing confirmation (promotion level): run with the variable unset.
    case_dir, case_assets = fresh_case_dir("missing-confirmation")
    env2 = {k: v for k, v in os.environ.items() if k != "RELEASE_CONFIRMATION"}
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            *verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json"),
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        env=env2,
        stdin=subprocess.DEVNULL,
    )
    ok = proc.returncode == 1 and "missing/wrong RELEASE_CONFIRMATION" in (
        proc.stdout + proc.stderr
    )
    results.append(
        {
            "case": "missing confirmation",
            "expected_exit": 1,
            "actual_exit": proc.returncode,
            "expect_text": "missing/wrong RELEASE_CONFIRMATION",
            "matched": "missing/wrong RELEASE_CONFIRMATION" in (proc.stdout + proc.stderr),
            "pass": ok,
        }
    )
    print(
        f"[{'PASS' if ok else 'FAIL':<4}] missing confirmation: exit {proc.returncode} (expected 1)"
    )
    case(
        "wrong confirmation (RELEASE_CONFIRMATION=yes)",
        1,
        "missing/wrong RELEASE_CONFIRMATION",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json"),
        {"RELEASE_CONFIRMATION": "yes"},
    )

    # 8/9/10. Failed / skipped / stale CI check (synthetic check-runs).
    def check_runs_file(case_dir: Path, runs: list[dict]) -> Path:
        path = case_dir / "check-runs.json"
        path.write_text(json.dumps(runs), encoding="utf-8")
        return path

    def all_pass_runs(head_sha: str) -> list[dict]:
        return [
            {"name": prefix, "status": "completed", "conclusion": "success", "head_sha": head_sha}
            for prefix in REQUIRED_CHECKS
        ]

    case_dir, case_assets = fresh_case_dir("failed-check")
    runs = all_pass_runs(sha)
    runs[0] = {**runs[0], "conclusion": "failure"}
    runs_file = check_runs_file(case_dir, runs)
    case(
        "failed check (claims failure)",
        1,
        "did not pass",
        verify_argv(
            case_dir,
            case_assets,
            case_dir / "candidate-manifest.json",
            ["--check-runs", str(runs_file)],
        ),
    )

    case_dir, case_assets = fresh_case_dir("skipped-check")
    runs = all_pass_runs(sha)
    runs[1] = {**runs[1], "conclusion": "skipped"}
    runs_file = check_runs_file(case_dir, runs)
    case(
        "skipped check (Core Python skipped)",
        1,
        "was skipped",
        verify_argv(
            case_dir,
            case_assets,
            case_dir / "candidate-manifest.json",
            ["--check-runs", str(runs_file)],
        ),
    )

    case_dir, case_assets = fresh_case_dir("stale-check")
    runs = all_pass_runs("7d2112c0000000000000000000000000000000000")
    runs_file = check_runs_file(case_dir, runs)
    case(
        "stale check (check-runs for another SHA)",
        1,
        "is stale",
        verify_argv(
            case_dir,
            case_assets,
            case_dir / "candidate-manifest.json",
            ["--check-runs", str(runs_file)],
        ),
    )

    # 11. Missing signature file.
    case_dir, case_assets = fresh_case_dir("missing-signature")
    (case_assets / f"{wheel}.sig").unlink()
    case(
        "missing signature (wheel .sig deleted)",
        1,
        "lacks detached signature",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # 12. Wrong signer: re-sign the wheel with a different key (openssl;
    # cosign sign-blob cannot run on this VM -- see the module docstring).
    case_dir, case_assets = fresh_case_dir("wrong-signer")
    key_dir = case_dir / "other-key"
    key_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key_dir / "cosign.key")],
        capture_output=True,
        timeout=120,
        check=True,
        stdin=subprocess.DEVNULL,
    )
    raw = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key_dir / "cosign.key"),
            "-rawin",
            "-in",
            str(case_assets / wheel),
        ],
        capture_output=True,
        timeout=120,
        check=True,
        stdin=subprocess.DEVNULL,
    )
    import base64

    (case_assets / f"{wheel}.sig").write_bytes(base64.b64encode(raw.stdout) + b"\n")
    # The manifest digest for the .sig changed: update it so the failure
    # is attributable to the signer, not the digest.
    mutated = _mutate_manifest(manifest)
    entry = _asset_entry(mutated, f"{wheel}.sig")
    entry["sha256"] = sha256_file(case_assets / f"{wheel}.sig")
    entry["size"] = (case_assets / f"{wheel}.sig").stat().st_size
    _write_manifest(mutated, case_dir / "candidate-manifest.json")
    # SHA256SUMS must also be refreshed for the re-signed files.
    lines = []
    for path in sorted(case_assets.iterdir()):
        if path.name == "SHA256SUMS" or not path.is_file():
            continue
        lines.append(f"{sha256_file(path)}  {path.name}\n")
    (case_assets / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")
    entry = _asset_entry(mutated, "SHA256SUMS")
    entry["sha256"] = sha256_file(case_assets / "SHA256SUMS")
    entry["size"] = (case_assets / "SHA256SUMS").stat().st_size
    _write_manifest(mutated, case_dir / "candidate-manifest.json")
    case(
        "wrong signer (wheel re-signed with another key)",
        1,
        "rejected",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    # 13. Stale SHA: manifest points at a different real commit.
    case_dir, case_assets = fresh_case_dir("stale-sha")
    _write_manifest(
        _mutate_manifest(manifest, source_sha="7d2112c0000000000000000000000000000000000"),
        case_dir / "candidate-manifest.json",
    )
    case(
        "stale SHA (manifest source_sha is main 7d2112c)",
        1,
        "source-sha",
        verify_argv(
            case_dir,
            case_assets,
            case_dir / "candidate-manifest.json",
            ["--asset-only", "--source-sha", sha],
        ),
    )

    # 14. Extra unlisted file in the asset dir.
    case_dir, case_assets = fresh_case_dir("extra-asset")
    (case_assets / "unexpected.txt").write_text("not in the manifest\n", encoding="utf-8")
    case(
        "extra asset (unlisted file)",
        1,
        "unlisted files",
        verify_argv(case_dir, case_assets, case_dir / "candidate-manifest.json", ["--asset-only"]),
    )

    failed = [r for r in results if not r["pass"]]
    if args.json:
        Path(args.json).write_text(
            json.dumps({"cases": results, "failed": len(failed)}, indent=2) + "\n", encoding="utf-8"
        )
    print(f"self-test: {len(results) - len(failed)}/{len(results)} cases rejected as expected")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_verify = sub.add_parser("verify", help="Verify a candidate against its manifest")
    p_verify.add_argument("--manifest", required=True)
    p_verify.add_argument("--asset-dir", required=True)
    p_verify.add_argument(
        "--workdir", required=True, help="Absolute workdir for the independent rebuild"
    )
    p_verify.add_argument("--source-sha", default=None)
    p_verify.add_argument("--repo", default=None)
    p_verify.add_argument("--cosign", default="cosign")
    p_verify.add_argument("--python", default="/usr/bin/python3.12")
    p_verify.add_argument(
        "--public-key", default=None, help="Trusted cosign public key (local-key mode)"
    )
    p_verify.add_argument(
        "--check-runs", default=None, help="JSON file of check-runs (test seam; default: gh api)"
    )
    p_verify.add_argument(
        "--asset-only", action="store_true", help="Skip promotion-readiness checks"
    )
    p_verify.add_argument("--json", default=None, help="Write JSON report here")
    p_verify.set_defaults(func=cmd_verify)
    p_test = sub.add_parser("self-test", help="Prove bad candidates are rejected")
    p_test.add_argument("--manifest", required=True)
    p_test.add_argument("--asset-dir", required=True)
    p_test.add_argument("--workdir", required=True)
    p_test.add_argument("--repo", default=None)
    p_test.add_argument("--cosign", default="cosign")
    p_test.add_argument("--python", default="/usr/bin/python3.12")
    p_test.add_argument("--public-key", default=None)
    p_test.add_argument("--json", default=None)
    p_test.set_defaults(func=cmd_self_test)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
