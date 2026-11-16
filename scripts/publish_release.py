#!/usr/bin/env python3
"""Release publishing helper for TextForensics.

Subcommands used by .github/workflows/release.yml:

  version     Print the package version from pyproject.toml.
  changelog   Generate release notes (changelog) from the commit history.
  sign-notes  Create signed release notes using cosign (keyless in CI).
              Publication mode REQUIRES cosign: when cosign is absent it
              FAILS (a SHA-256 checksum is not an authenticity signature and
              is never called one). ``--mode unsigned-preview`` writes a
              checksum only, marks the notes UNSIGNED PREVIEW, and the result
              is INELIGIBLE for upload.
  upload      Create the GitHub Release and attach artifacts together with
              their cosign signatures, checksums and provenance bundles.
              Fails closed unless: RELEASE_CONFIRMATION is exactly
              ``RELEASE``; every mandatory asset in the typed manifest is
              present and valid (names, versions, digests); the SBOM
              payloads are structurally valid SBOMs; every detached
              signature verifies with cosign verify-blob against the
              expected signer identity/issuer; the tag resolves to the
              artifact's source commit; and the notes were signed in
              publication mode. No remote-writing command is launched until
              every check passes. After `gh release create` succeeds, the
              upload is verified by reading the published release back
              (asset list + per-asset download) and comparing digests; a
              read-back failure is reported as a failed upload, never as
              a success.
              ``--dry-run`` (W10 rehearsal) runs this exact pre-publication
              path -- confirmation, typed manifest, checksums, SBOM
              structure, cosign signature verification, tag binding --
              and then stops: it prints the release plan and exits 0
              without launching `gh release create` or any other remote
              write. A dry run that fails any check exits 1 exactly as
              a real upload would, before any remote write.
  verify-upload
              Read-only re-verification of an already-published release:
              rebuilds the manifest, re-verifies checksums, SBOM structure,
              signatures and tag binding, then reads the published assets
              back and compares digests. Performs no remote writes.
  create-tag  Create the release tag at exactly the candidate source SHA
              and push it, then verify it on the remote. A tag that already
              resolves to a different commit is never moved. `--dry-run`
              plans the tag creation without any remote write (W10
              rehearsal). This is the ONLY place a release tag is created:
              `upload` still requires the tag to already resolve to the
              source SHA, so a tag can never be created by an undocumented
              manual step outside the boundary.

The script only shells out to git / cosign / gh; it performs no direct
network access of its own. Raw release content never leaves the machine
except through the explicitly invoked gh CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

CONFIRMATION_ENV = "RELEASE_CONFIRMATION"
CONFIRMATION_VALUE = "RELEASE"

# Canonical SBOM payload names produced by .github/workflows/release.yml.
SBOM_CDX_NAME = "textforensics-sbom.cdx.json"
SBOM_SPDX_NAME = "textforensics-sbom.spdx.json"


class ManifestError(Exception):
    """A mandatory asset is missing, misnamed, or fails validation."""


# ---------------------------------------------------------------------------
# pyproject.toml / git helpers
# ---------------------------------------------------------------------------


def read_version(pyproject: Path = Path("pyproject.toml")) -> str:
    """Read the package version from pyproject.toml."""
    if not pyproject.exists():
        print(f"ERROR: {pyproject} not found", file=sys.stderr)
        raise SystemExit(1)
    with pyproject.open("rb") as fh:
        data = tomllib.load(fh)
    version = data.get("project", {}).get("version")
    if not version or not isinstance(version, str):
        print("ERROR: [project] version missing from pyproject.toml", file=sys.stderr)
        raise SystemExit(1)
    return version


def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def find_cosign() -> str | None:
    """Return the cosign binary path, or None if cosign is not installed."""
    return shutil.which("cosign")


def run_cosign(*args: str) -> bool:
    """Run cosign if it is installed. Returns True on success.

    Raises subprocess.CalledProcessError if cosign is present but the
    command fails; callers that must fail closed without a traceback
    catch it.
    """
    if find_cosign() is None:
        return False
    subprocess.run(["cosign", *args], check=True)
    return True


def verify_cosign_blob(
    payload: Path,
    sig: Path,
    bundle: Path,
    identity: str,
    issuer: str,
) -> tuple[bool, str]:
    """Independently verify one detached keyless signature with cosign.

    Runs ``cosign verify-blob --bundle <bundle> --signature <sig>
    --certificate-identity <identity> --certificate-oidc-issuer
    <issuer> <payload>``. Cosign has refused keyless verification
    without an expected identity/issuer since 2.0: a signature from
    any other signer is a rejection, not a pass. Returns (True, "") on
    success, else (False, reason). Cosign itself checks the bundle's
    payload digest against the file, the certificate chain against the
    Sigstore root, and Rekor inclusion.
    """
    if find_cosign() is None:
        return False, (
            "cosign is not available; cannot verify the signature of "
            f"{payload.name} in publication mode"
        )
    result = subprocess.run(
        [
            "cosign",
            "verify-blob",
            "--bundle",
            str(bundle),
            "--signature",
            str(sig),
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
            str(payload),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else "verification failed"
        return False, f"cosign verify-blob rejected {payload.name}: {reason}"
    return True, ""


def validate_bundle_structure(bundle: Path) -> str | None:
    """Structural pre-check: a Sigstore bundle must be JSON carrying
    verificationMaterial and a dsseEnvelope or messageSignature. This
    catches garbage/stale bundle files before cosign is invoked; the
    cryptographic binding itself is cosign's job (verify_cosign_blob).
    Returns an error string, or None if the structure is plausible."""
    try:
        data = json.loads(bundle.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"signature bundle {bundle.name} is not valid JSON: {exc}"
    if not isinstance(data, dict) or "verificationMaterial" not in data:
        return f"signature bundle {bundle.name} has no verificationMaterial (not a Sigstore bundle)"
    if "dsseEnvelope" not in data and "messageSignature" not in data:
        return f"signature bundle {bundle.name} has neither dsseEnvelope nor messageSignature"
    return None


def latest_tag() -> str | None:
    """Return the most recent reachable tag, or None."""
    try:
        tag = run_git("describe", "--tags", "--abbrev=0")
        return tag or None
    except subprocess.CalledProcessError:
        return None


def tag_exists(tag: str) -> bool:
    """Check that a git tag resolves to a commit."""
    try:
        run_git("rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}")
        return True
    except subprocess.CalledProcessError:
        return False


def tag_commit(tag: str) -> str | None:
    """Return the commit a tag resolves to, or None if it does not resolve."""
    try:
        return run_git("rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}")
    except subprocess.CalledProcessError:
        return None


def commit_range(tag: str | None) -> list[str]:
    """Return 'hash subject' lines for commits since the given tag."""
    rev_range = f"{tag}..HEAD" if tag else "HEAD"
    try:
        log = run_git("log", "--no-decorate", "--pretty=format:%h %s", rev_range)
    except subprocess.CalledProcessError:
        # Unknown tag (or no history in range): fall back to full history.
        log = run_git("log", "--no-decorate", "--pretty=format:%h %s", "HEAD")
    return [line for line in log.splitlines() if line.strip()]


def classify(subject: str) -> str:
    """Bucket a conventional-commit subject into a changelog section."""
    lowered = subject.lower()
    if lowered.startswith(("feat", "feature", "add")):
        return "Features"
    if lowered.startswith("fix"):
        return "Fixes"
    if lowered.startswith(("perf", "bench", "optim")):
        return "Performance"
    if lowered.startswith(("doc", "readme")):
        return "Documentation"
    if lowered.startswith(("refactor", "clean")):
        return "Refactoring"
    return "Other Changes"


def compute_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Typed mandatory asset manifest (ENG-05 / ENG-06)
# ---------------------------------------------------------------------------


@dataclass
class AssetManifest:
    """Every asset that MUST accompany a release, with its verification
    material. Nothing here is optional: absence of any item fails the
    upload before any remote-writing command is launched.

    Every dist payload (wheel, sdist, source tarball, both SBOMs) and
    the release notes carry a detached cosign signature + bundle: the
    release workflow signs every file in dist/ before checksums are
    generated. Existence alone is never enough — see
    :func:`verify_signatures`, which verifies each signature with
    ``cosign verify-blob`` against the expected signer identity.
    Provenance bundles are DSSE attestations themselves (signed by the
    attestation action); they carry no separate .sig file."""

    wheel: Path
    wheel_sig: Path
    wheel_bundle: Path
    sdist: Path
    sdist_sig: Path
    sdist_bundle: Path
    source_tarball: Path
    source_sig: Path
    source_bundle: Path
    notes: Path
    notes_checksum: Path
    notes_sig: Path
    notes_bundle: Path
    sha256sums: Path
    sbom_cdx: Path
    sbom_cdx_sig: Path
    sbom_cdx_bundle: Path
    sbom_spdx: Path
    sbom_spdx_sig: Path
    sbom_spdx_bundle: Path
    provenance_bundles: list[Path] = field(default_factory=list)

    def payloads(self) -> list[Path]:
        """Payload files whose content SHA256SUMS must cover."""
        return [
            self.wheel,
            self.sdist,
            self.source_tarball,
            self.sbom_cdx,
            self.sbom_spdx,
            self.notes,
            *self.provenance_bundles,
        ]

    def verification_material(self) -> list[Path]:
        """Detached signatures/bundles/checksums for the payloads."""
        return [
            self.notes_checksum,
            self.notes_sig,
            self.notes_bundle,
            self.wheel_sig,
            self.wheel_bundle,
            self.sdist_sig,
            self.sdist_bundle,
            self.source_sig,
            self.source_bundle,
            self.sbom_cdx_sig,
            self.sbom_cdx_bundle,
            self.sbom_spdx_sig,
            self.sbom_spdx_bundle,
        ]

    def signed_pairs(self) -> list[tuple[Path, Path, Path]]:
        """(payload, signature, bundle) triples to verify with cosign."""
        return [
            (self.wheel, self.wheel_sig, self.wheel_bundle),
            (self.sdist, self.sdist_sig, self.sdist_bundle),
            (self.source_tarball, self.source_sig, self.source_bundle),
            (self.sbom_cdx, self.sbom_cdx_sig, self.sbom_cdx_bundle),
            (self.sbom_spdx, self.sbom_spdx_sig, self.sbom_spdx_bundle),
            (self.notes, self.notes_sig, self.notes_bundle),
        ]

    def all_assets(self) -> list[Path]:
        """The complete attached asset list (payloads + verification
        material + SHA256SUMS). SHA256SUMS itself is excluded: it is the
        manifest of checksums, generated AFTER the complete payload set
        is defined, and cannot checksum itself."""
        return [*self.payloads(), *self.verification_material(), self.sha256sums]


def _require(path: Path, what: str) -> Path:
    if not path.exists():
        raise ManifestError(f"mandatory {what} missing: {path}")
    return path


def build_asset_manifest(
    dist_dir: Path,
    notes: Path,
    provenance_dir: Path | None,
    version: str,
) -> AssetManifest:
    """Construct and validate the typed mandatory asset manifest.

    Wheel and tarball names must match the package name + release version
    exactly; SBOM payloads are enumerated by their canonical names (their
    detached signatures/bundles are NOT a substitute for the payloads).
    Raises ManifestError on the first missing/misnamed item.
    """
    if not dist_dir.is_dir():
        raise ManifestError(f"dist directory {dist_dir} not found")
    if not notes.exists():
        raise ManifestError(f"release notes {notes} not found")
    if notes.with_suffix(notes.suffix + ".unsigned-preview").exists():
        raise ManifestError(
            f"release notes {notes} are an UNSIGNED PREVIEW and are "
            "ineligible for upload (sign in publication mode instead)"
        )

    wheels = sorted(dist_dir.glob("*.whl"))
    expected_wheel = f"textforensics-{version}-py3-none-any.whl"
    if expected_wheel not in [w.name for w in wheels]:
        raise ManifestError(
            f"mandatory wheel {expected_wheel} missing in {dist_dir} "
            f"(found: {[w.name for w in wheels]})"
        )
    wheel = dist_dir / expected_wheel

    expected_sdist = f"textforensics-{version}.tar.gz"
    expected_source = f"textforensics-{version}-source.tar.gz"
    sdist = _require(dist_dir / expected_sdist, f"sdist {expected_sdist}")
    source = _require(dist_dir / expected_source, f"source tarball {expected_source}")

    manifest = AssetManifest(
        wheel=wheel,
        wheel_sig=_require(dist_dir / f"{expected_wheel}.sig", "wheel signature"),
        wheel_bundle=_require(dist_dir / f"{expected_wheel}.bundle", "wheel signature bundle"),
        sdist=sdist,
        sdist_sig=_require(dist_dir / f"{expected_sdist}.sig", "sdist signature"),
        sdist_bundle=_require(dist_dir / f"{expected_sdist}.bundle", "sdist signature bundle"),
        source_tarball=source,
        source_sig=_require(dist_dir / f"{expected_source}.sig", "source tarball signature"),
        source_bundle=_require(
            dist_dir / f"{expected_source}.bundle", "source tarball signature bundle"
        ),
        notes=notes,
        notes_checksum=_require(
            notes.with_suffix(notes.suffix + ".sha256"), "release-notes checksum"
        ),
        notes_sig=_require(notes.with_suffix(notes.suffix + ".sig"), "notes signature"),
        notes_bundle=_require(
            notes.with_suffix(notes.suffix + ".bundle"), "notes signature bundle"
        ),
        sha256sums=_require(dist_dir / "SHA256SUMS", "SHA256SUMS manifest"),
        sbom_cdx=_require(dist_dir / SBOM_CDX_NAME, "CycloneDX SBOM payload"),
        sbom_cdx_sig=_require(dist_dir / f"{SBOM_CDX_NAME}.sig", "CycloneDX SBOM signature"),
        sbom_cdx_bundle=_require(
            dist_dir / f"{SBOM_CDX_NAME}.bundle", "CycloneDX SBOM signature bundle"
        ),
        sbom_spdx=_require(dist_dir / SBOM_SPDX_NAME, "SPDX SBOM payload"),
        sbom_spdx_sig=_require(dist_dir / f"{SBOM_SPDX_NAME}.sig", "SPDX SBOM signature"),
        sbom_spdx_bundle=_require(
            dist_dir / f"{SBOM_SPDX_NAME}.bundle", "SPDX SBOM signature bundle"
        ),
    )

    if provenance_dir is None or not provenance_dir.is_dir():
        raise ManifestError(f"provenance directory {provenance_dir} not found")
    manifest.provenance_bundles = sorted(provenance_dir.glob("*.intoto.jsonl"))
    if not manifest.provenance_bundles:
        raise ManifestError(f"no provenance bundles (*.intoto.jsonl) in {provenance_dir}")

    for asset in manifest.all_assets():
        if not asset.exists():
            raise ManifestError(f"expected artifact {asset} missing")
    return manifest


def parse_sha256sums(path: Path) -> dict[str, str]:
    """Parse a SHA256SUMS file into {basename: hex digest}.

    Entries are keyed by basename because the manifest spans directories
    (``dist/``, the notes next to the checkout root, ``provenance/``) while
    SHA256SUMS is generated as one file in ``dist/``. Basenames across the
    attached asset set are unique; :func:`verify_checksums` refuses to
    verify an ambiguous set.
    """
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition(" ")
        name = Path(name.strip().lstrip("*")).name
        if len(digest) != 64:
            raise ManifestError(f"malformed SHA256SUMS entry: {line!r}")
        entries[name] = digest
    return entries


def verify_checksums(manifest: AssetManifest) -> bool:
    """Recompute digests for every attached asset and compare against
    SHA256SUMS (by basename). A missing entry or a digest mismatch
    (tampered payload) returns False.

    The notes checksum file itself is a checksum artifact, not a payload:
    it is not required to appear in SHA256SUMS; instead the notes digest
    is verified against it directly.
    """
    try:
        entries = parse_sha256sums(manifest.sha256sums)
    except (OSError, ManifestError) as exc:
        print(f"ERROR: cannot read SHA256SUMS: {exc}", file=sys.stderr)
        return False
    covered = [*manifest.payloads(), *manifest.verification_material()]
    basenames = [a.name for a in covered if a != manifest.notes_checksum]
    if len(set(basenames)) != len(basenames):
        print("ERROR: ambiguous duplicate basenames in asset set", file=sys.stderr)
        return False
    ok = True
    for asset in covered:
        if asset == manifest.notes_checksum:
            continue
        expected = entries.get(asset.name)
        if expected is None:
            print(f"ERROR: SHA256SUMS has no entry for {asset.name}", file=sys.stderr)
            ok = False
            continue
        if compute_sha256(asset) != expected:
            print(f"ERROR: checksum mismatch for {asset.name}", file=sys.stderr)
            ok = False
    try:
        recorded = manifest.notes_checksum.read_text(encoding="utf-8").split()[0]
    except (OSError, IndexError) as exc:
        print(f"ERROR: cannot read notes checksum: {exc}", file=sys.stderr)
        return False
    if recorded != compute_sha256(manifest.notes):
        print("ERROR: checksum mismatch for release notes", file=sys.stderr)
        ok = False
    return ok


def verify_tag_binding(tag: str, source_sha: str) -> bool:
    """Bind tag -> commit -> artifact source SHA. Existence of the tag is
    NOT enough: it must resolve to exactly the artifact's source commit."""
    resolved = tag_commit(tag)
    if resolved is None:
        print(f"ERROR: tag {tag} does not resolve to a commit", file=sys.stderr)
        return False
    if resolved != source_sha:
        print(
            f"ERROR: tag {tag} resolves to {resolved}, not the artifact source commit {source_sha}",
            file=sys.stderr,
        )
        return False
    return True


def validate_sbom_payloads(manifest: AssetManifest) -> list[str]:
    """Structural validation of the SBOM payloads (ENG-06).

    Checksums prove integrity, not that a payload is an SBOM: a payload
    must parse as JSON and carry its format marker (CycloneDX
    ``bomFormat`` / SPDX ``spdxVersion``). A payload that fails this
    check is refused even when its SHA256SUMS entry matches.
    """
    errors: list[str] = []
    for path, fmt, key, want in (
        (manifest.sbom_cdx, "CycloneDX", "bomFormat", "CycloneDX"),
        (manifest.sbom_spdx, "SPDX", "spdxVersion", "SPDX-"),
    ):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"SBOM payload {path.name} is not valid JSON: {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"SBOM payload {path.name} is not a JSON object")
            continue
        value = data.get(key)
        if fmt == "CycloneDX":
            if value != want:
                errors.append(f"SBOM payload {path.name} has bomFormat {value!r}, not {want!r}")
        elif not isinstance(value, str) or not value.startswith(want):
            errors.append(
                f"SBOM payload {path.name} has spdxVersion {value!r}, not an {want!r} version"
            )
    return errors


def verify_signatures(
    manifest: AssetManifest,
    identity: str | None,
    issuer: str | None,
) -> tuple[bool, list[str]]:
    """Verify every detached signature in the manifest (ENG-06).

    Both the expected signer identity and the OIDC issuer are required:
    keyless cosign verification without them is refused by cosign since
    2.0, and verifying against "any signer" would accept a signature
    from a compromised pipeline. A missing identity/issuer, a missing
    cosign binary, a malformed bundle, or any rejected signature fails
    the whole verification. Returns (ok, errors).
    """
    if not identity or not issuer:
        return False, [
            "signer identity is not configured: --expected-identity and "
            "--expected-issuer are both required to verify signatures "
            "(the signing identity is a human decision; see "
            "docs/verification/promotion-boundary.md). Refusing to "
            "verify against any signer."
        ]
    errors: list[str] = []
    for payload, sig, bundle in manifest.signed_pairs():
        structural = validate_bundle_structure(bundle)
        if structural is not None:
            errors.append(structural)
            continue
        ok, detail = verify_cosign_blob(payload, sig, bundle, identity, issuer)
        if not ok:
            errors.append(detail)
    return (not errors), errors


def verify_uploaded_assets(
    tag: str,
    manifest: AssetManifest,
) -> tuple[bool, list[str]]:
    """Read-back verification of a published release (ENG-05).

    Lists the published release's assets with ``gh release view`` and
    downloads every attached asset with ``gh release download``, then
    compares each downloaded file's SHA-256 (and the API-reported size)
    against the local file. A ``gh release create`` exit code of 0 is
    NOT proof the artifacts arrived intact: a missing asset, a size
    mismatch, or a digest mismatch fails the upload. Read-only: no
    remote writes are performed here. Returns (ok, errors).
    """
    errors: list[str] = []
    view = subprocess.run(
        ["gh", "release", "view", tag, "--json", "assets"],
        capture_output=True,
        text=True,
    )
    if view.returncode != 0:
        return False, [
            f"could not list published release {tag}: "
            f"{(view.stderr or '').strip() or 'gh release view failed'}"
        ]
    try:
        published = {asset["name"]: asset for asset in json.loads(view.stdout).get("assets", [])}
    except (json.JSONDecodeError, AttributeError, TypeError) as exc:
        return False, [f"could not parse `gh release view` output for {tag}: {exc}"]
    local_by_name = {asset.name: asset for asset in manifest.all_assets()}
    for name in sorted(local_by_name):
        if name not in published:
            errors.append(f"published release {tag} is missing attached asset {name}")
            continue
        size = published[name].get("size")
        if size is not None and size != local_by_name[name].stat().st_size:
            errors.append(
                f"published asset {name} has size {size}, "
                f"local file has size {local_by_name[name].stat().st_size}"
            )
    if errors:
        return False, errors
    with tempfile.TemporaryDirectory(prefix="release-readback-") as tmp:
        tmpdir = Path(tmp)
        for name in sorted(local_by_name):
            local = local_by_name[name]
            download = subprocess.run(
                [
                    "gh",
                    "release",
                    "download",
                    tag,
                    "--dir",
                    str(tmpdir),
                    "--pattern",
                    name,
                ],
                capture_output=True,
                text=True,
            )
            if download.returncode != 0:
                errors.append(
                    f"could not download published asset {name} for read-back: "
                    f"{(download.stderr or '').strip() or 'gh release download failed'}"
                )
                continue
            downloaded = tmpdir / name
            if not downloaded.exists():
                errors.append(f"read-back download of {name} produced no file")
                continue
            if compute_sha256(downloaded) != compute_sha256(local):
                errors.append(
                    f"read-back digest mismatch for {name}: the published "
                    "bytes differ from the local file"
                )
    return (not errors), errors


def _prepare_verified_manifest(
    dist_dir: Path,
    notes: Path,
    provenance_dir: Path | None,
    version: str,
    identity: str | None,
    issuer: str | None,
) -> tuple[AssetManifest | None, list[str]]:
    """Shared pre-publication verification (upload + verify-upload):
    typed manifest, checksums, SBOM structure, signatures. Returns
    (manifest, errors); manifest is None when any check fails. Prints
    nothing: callers report the errors."""
    try:
        manifest = build_asset_manifest(dist_dir, notes, provenance_dir, version)
    except ManifestError as exc:
        return None, [str(exc)]
    errors: list[str] = []
    if not verify_checksums(manifest):
        errors.append("checksum verification failed")
    errors.extend(validate_sbom_payloads(manifest))
    ok, sig_errors = verify_signatures(manifest, identity, issuer)
    errors.extend(sig_errors)
    if errors:
        return None, errors
    return manifest, []


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_version(_args: argparse.Namespace) -> int:
    print(read_version())
    return 0


def cmd_changelog(args: argparse.Namespace) -> int:
    version = read_version()
    tag = args.since_tag if args.since_tag is not None else latest_tag()
    if tag and not tag_exists(tag):
        print(f"WARNING: tag '{tag}' not found; using full history", file=sys.stderr)
        tag = None
    commits = commit_range(tag)

    sha = run_git("rev-parse", "HEAD")
    short_sha = sha[:12]
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        f"# textforensics v{version}",
        "",
        f"- **Release commit:** `{short_sha}`",
        f"- **Generated:** {now}",
        f"- **Commit range:** {tag or '(no previous tag)'}..HEAD ({len(commits)} commits)",
        "",
        "## Verification",
        "",
        "This release is published with:",
        "",
        "- a cosign-signed changelog (keyless Sigstore signatures in CI),",
        "- CycloneDX and SPDX JSON SBOMs,",
        "- SLSA-style build provenance attestations (actions/attest-build-provenance@v1),",
        "- SHA-256 checksums for every attached artifact.",
        "",
        "Text-only detection cannot prove authorship; see the project README "
        "for scope and limitations of this tool.",
        "",
    ]

    if not commits:
        lines += ["_No commits found since the previous tag._", ""]
    else:
        buckets: dict[str, list[str]] = {}
        for entry in commits:
            buckets.setdefault(classify(entry), []).append(entry)
        for section in (
            "Features",
            "Fixes",
            "Performance",
            "Refactoring",
            "Documentation",
            "Other Changes",
        ):
            entries = buckets.get(section)
            if not entries:
                continue
            lines += [f"## {section}", ""]
            lines += [f"- {entry}" for entry in entries]
            lines += [""]

    output = Path(args.output)
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote changelog for v{version} to {output} ({len(commits)} commits)")
    return 0


def cmd_sign_notes(args: argparse.Namespace) -> int:
    notes = Path(args.notes)
    if not notes.exists():
        print(f"ERROR: {notes} not found", file=sys.stderr)
        return 1

    digest = hashlib.sha256(notes.read_bytes()).hexdigest()
    checksum_path = notes.with_suffix(notes.suffix + ".sha256")
    checksum_path.write_text(f"{digest}  {notes.name}\n", encoding="utf-8")
    print(f"SHA-256 checksum of release notes: {digest}")

    mode = getattr(args, "mode", "publication")
    if mode == "unsigned-preview":
        marker = notes.with_suffix(notes.suffix + ".unsigned-preview")
        marker.write_text(
            "UNSIGNED PREVIEW — NOT ELIGIBLE FOR UPLOAD. "
            "These notes carry a SHA-256 checksum only, not a cryptographic "
            "signature. Re-sign in publication mode (cosign required) "
            "before any release upload.\n",
            encoding="utf-8",
        )
        print(
            "UNSIGNED PREVIEW: release notes carry a SHA-256 checksum only. "
            "This output is NOT ELIGIBLE FOR UPLOAD.",
            file=sys.stderr,
        )
        return 0

    # Publication mode: cryptographic signing is mandatory. A checksum is
    # not an authenticity signature, and must never be called one.
    try:
        signed = run_cosign(
            "sign-blob",
            "--yes",
            str(notes),
            "--bundle",
            str(notes) + ".bundle",
            "--output-signature",
            str(notes) + ".sig",
        )
    except subprocess.CalledProcessError as exc:
        print(
            f"ERROR: cosign sign-blob failed (exit {exc.returncode}); "
            "release notes are not signed.",
            file=sys.stderr,
        )
        return 1
    if not signed:
        print(
            "ERROR: cosign is not available; cannot sign release notes in "
            "publication mode. A SHA-256 checksum is not an authenticity "
            "signature. Install cosign or use --mode unsigned-preview for a "
            "local preview that is ineligible for upload.",
            file=sys.stderr,
        )
        return 1
    print(f"Cosign (keyless) signature written to {notes}.sig")
    return 0


def cmd_upload(args: argparse.Namespace) -> int:
    # Fail-safe confirmation mirror of the workflow input check. The value
    # must be exactly RELEASE: unset, empty, and wrong values ALL fail.
    confirmation = os.environ.get(CONFIRMATION_ENV)
    if confirmation != CONFIRMATION_VALUE:
        print(
            f"ERROR: {CONFIRMATION_ENV} must be exactly '{CONFIRMATION_VALUE}' "
            "(unset, empty, and wrong values are all rejected)",
            file=sys.stderr,
        )
        return 1

    version = args.version or read_version()
    tag = args.tag or f"v{version}"
    dist_dir = Path(args.dist_dir)
    notes = Path(args.notes)
    prov_dir = Path(args.provenance_dir) if args.provenance_dir else None

    # (1-4) Typed mandatory asset manifest, checksums, SBOM structure,
    # signatures (cosign verify-blob against the expected signer
    # identity/issuer). All before any remote-writing command.
    manifest, errors = _prepare_verified_manifest(
        dist_dir,
        notes,
        prov_dir,
        version,
        args.expected_identity,
        args.expected_issuer,
    )
    if manifest is None:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    # (5) Tag must resolve to the artifact's source commit.
    source_sha = args.source_sha or run_git("rev-parse", "HEAD")
    if not verify_tag_binding(tag, source_sha):
        return 1

    # (5b) W10 no-publication mode: every check above has now run on the
    # exact code path a real upload takes. Stop here: print the plan and
    # exit 0 without launching `gh release create` or any other remote
    # write. A dry run that reaches this point has proven the candidate
    # would be publishable; a candidate that fails any check above has
    # already exited 1, exactly as a real upload would.
    if getattr(args, "dry_run", False):
        assets = manifest.all_assets()
        print(f"DRY-RUN: release {tag} (textforensics v{version}) from {source_sha}")
        print(f"DRY-RUN: confirmation {CONFIRMATION_ENV} verified; {len(assets)} asset(s) checked:")
        for asset in assets:
            print(f"DRY-RUN:   - {asset}")
        print("DRY-RUN: no release was created, no tag was pushed, no remote write was made.")
        return 0

    # Only now, with every check passed, launch the remote-writing command.
    assets = manifest.all_assets()
    title = f"textforensics v{version}"
    cmd = [
        "gh",
        "release",
        "create",
        tag,
        *[str(a) for a in assets],
        "--title",
        title,
        "--notes-file",
        str(notes),
        "--verify-tag",
    ]

    print(f"Creating release {tag} ({title}) with {len(assets)} asset(s):")
    for asset in assets:
        print(f"  - {asset}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(
            f"ERROR: `gh release create` failed (exit {exc.returncode}); "
            "the release was NOT published.",
            file=sys.stderr,
        )
        return 1

    # (6) A zero exit code is not proof the artifacts arrived intact:
    # read the published release back and compare digests. A read-back
    # failure is a failed upload, never a success.
    ok, readback_errors = verify_uploaded_assets(tag, manifest)
    if not ok:
        for error in readback_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"ERROR: read-back verification of published release {tag} "
            "failed; the release is NOT verified as published. Inspect "
            f"the release {tag} before retrying or deleting it.",
            file=sys.stderr,
        )
        return 1

    print(
        f"Release {tag} published and read-back verified "
        f"({len(assets)} assets, digests match). Provenance attestations "
        "are also available in the repository attestation store "
        "(`gh attestation verify`)."
    )
    return 0


def cmd_verify_upload(args: argparse.Namespace) -> int:
    """Read-only re-verification of an already-published release.

    Rebuilds the manifest and re-verifies checksums, SBOM structure,
    signatures and tag binding, then reads the published assets back
    and compares digests. Performs no remote writes (only `gh release
    view` / `gh release download` reads). Exit 0: the published
    release matches the local asset set; exit 1: any mismatch.
    """
    version = args.version or read_version()
    tag = args.tag or f"v{version}"
    dist_dir = Path(args.dist_dir)
    notes = Path(args.notes)
    prov_dir = Path(args.provenance_dir) if args.provenance_dir else None

    manifest, errors = _prepare_verified_manifest(
        dist_dir,
        notes,
        prov_dir,
        version,
        args.expected_identity,
        args.expected_issuer,
    )
    if manifest is None:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    source_sha = args.source_sha or run_git("rev-parse", "HEAD")
    if not verify_tag_binding(tag, source_sha):
        return 1

    ok, readback_errors = verify_uploaded_assets(tag, manifest)
    if not ok:
        for error in readback_errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"ERROR: read-back verification of published release {tag} failed.",
            file=sys.stderr,
        )
        return 1
    print(
        f"Published release {tag} verified: {len(manifest.all_assets())} "
        "assets present with matching digests and verified signatures."
    )
    return 0


def cmd_create_tag(args: argparse.Namespace) -> int:
    """Create the release tag at exactly the candidate source SHA and
    push it, then verify it on the remote.

    This is the ONLY place a release tag is created: `upload` requires
    the tag to already resolve to the source SHA, so without this step
    a new version could never publish — and a tag must never be created
    by an undocumented manual step outside the boundary. A tag that
    already resolves to a different commit is never moved. `--dry-run`
    validates the preconditions and prints the plan without any remote
    write (W10 rehearsal).
    """
    tag = args.tag
    source_sha = args.source_sha or run_git("rev-parse", "HEAD")
    remote = args.remote
    resolved = tag_commit(tag)
    if resolved is not None and resolved != source_sha:
        print(
            f"ERROR: tag {tag} already resolves to {resolved}, not the "
            f"artifact source commit {source_sha}; refusing to move a tag.",
            file=sys.stderr,
        )
        return 1
    if args.dry_run:
        if resolved == source_sha:
            print(
                f"DRY-RUN: tag {tag} already resolves to {source_sha}; would push it to {remote}."
            )
        else:
            print(f"DRY-RUN: would create tag {tag} at {source_sha} and push it to {remote}.")
        return 0
    if resolved is None:
        try:
            subprocess.run(
                ["git", "tag", tag, source_sha],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            print(
                f"ERROR: could not create tag {tag} at {source_sha}: "
                f"{(exc.stderr or '').strip() or exc}",
                file=sys.stderr,
            )
            return 1
    try:
        subprocess.run(
            ["git", "push", remote, tag],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        print(
            f"ERROR: could not push tag {tag} to {remote}: {(exc.stderr or '').strip() or exc}",
            file=sys.stderr,
        )
        return 1
    result = subprocess.run(
        ["git", "ls-remote", remote, tag],
        capture_output=True,
        text=True,
    )
    remote_sha = result.stdout.split()[0] if result.stdout.split() else None
    if result.returncode != 0 or remote_sha != source_sha:
        print(
            f"ERROR: remote {remote} tag {tag} resolves to {remote_sha}, "
            f"not {source_sha}; the pushed tag is NOT verified.",
            file=sys.stderr,
        )
        return 1
    print(f"Tag {tag} created at {source_sha} and pushed to {remote} (verified).")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_version = sub.add_parser("version", help="Print the version from pyproject.toml")
    p_version.set_defaults(func=cmd_version)

    p_changelog = sub.add_parser("changelog", help="Generate release notes from commit history")
    p_changelog.add_argument("--output", default="release-notes.md")
    p_changelog.add_argument(
        "--since-tag",
        default=None,
        help="Tag to start the changelog from (default: latest tag)",
    )
    p_changelog.set_defaults(func=cmd_changelog)

    p_sign = sub.add_parser("sign-notes", help="Create signed release notes")
    p_sign.add_argument("--notes", default="release-notes.md")
    p_sign.add_argument(
        "--mode",
        choices=["publication", "unsigned-preview"],
        default="publication",
        help="publication (default): cosign signing is mandatory; "
        "unsigned-preview: checksum only, ineligible for upload",
    )
    p_sign.set_defaults(func=cmd_sign_notes)

    p_upload = sub.add_parser("upload", help="Create GitHub release and upload artifacts")
    p_upload.add_argument("--notes", default="release-notes.md")
    p_upload.add_argument("--dist-dir", default="dist")
    p_upload.add_argument("--provenance-dir", default=None)
    p_upload.add_argument("--tag", default=None)
    p_upload.add_argument("--version", default=None)
    p_upload.add_argument(
        "--source-sha",
        default=None,
        help="Source commit the tag must resolve to (default: git HEAD).",
    )
    p_upload.add_argument(
        "--expected-identity",
        default=None,
        help="Expected keyless signer identity for cosign verify-blob "
        "(required; e.g. the release workflow identity).",
    )
    p_upload.add_argument(
        "--expected-issuer",
        default=None,
        help="Expected OIDC issuer for cosign verify-blob (required; "
        "https://token.actions.githubusercontent.com in CI).",
    )
    p_upload.add_argument(
        "--dry-run",
        action="store_true",
        help="No-publication rehearsal mode (W10): run the exact "
        "pre-publication checks (confirmation, manifest, checksums, "
        "SBOM structure, signatures, tag binding) and print the release "
        "plan without launching `gh release create` or any remote write.",
    )
    p_upload.set_defaults(func=cmd_upload)

    p_verify = sub.add_parser(
        "verify-upload",
        help="Read-only re-verification of an already-published release",
    )
    p_verify.add_argument("--notes", default="release-notes.md")
    p_verify.add_argument("--dist-dir", default="dist")
    p_verify.add_argument("--provenance-dir", default=None)
    p_verify.add_argument("--tag", default=None)
    p_verify.add_argument("--version", default=None)
    p_verify.add_argument(
        "--source-sha",
        default=None,
        help="Source commit the tag must resolve to (default: git HEAD).",
    )
    p_verify.add_argument(
        "--expected-identity",
        default=None,
        help="Expected keyless signer identity for cosign verify-blob (required).",
    )
    p_verify.add_argument(
        "--expected-issuer",
        default=None,
        help="Expected OIDC issuer for cosign verify-blob (required).",
    )
    p_verify.set_defaults(func=cmd_verify_upload)

    p_tag = sub.add_parser(
        "create-tag",
        help="Create the release tag at the candidate SHA and push it",
    )
    p_tag.add_argument("--tag", required=True, help="Tag to create (e.g. v1.2.3).")
    p_tag.add_argument(
        "--source-sha",
        default=None,
        help="Source commit the tag must resolve to (default: git HEAD).",
    )
    p_tag.add_argument("--remote", default="origin", help="Git remote (default: origin).")
    p_tag.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the preconditions and print the plan without any remote write.",
    )
    p_tag.set_defaults(func=cmd_create_tag)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
