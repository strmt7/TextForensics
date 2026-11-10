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
              present and valid (names, versions, digests); the tag resolves
              to the artifact's source commit; and the notes were signed in
              publication mode. No remote-writing command is launched until
              every check passes.

The script only shells out to git / cosign / gh; it performs no direct
network access of its own. Raw release content never leaves the machine
except through the explicitly invoked gh CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
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


def run_cosign(*args: str) -> bool:
    """Run cosign if it is installed. Returns True on success."""
    if shutil.which("cosign") is None:
        return False
    subprocess.run(["cosign", *args], check=True)
    return True


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
    upload before any remote-writing command is launched."""

    wheel: Path
    sdist: Path
    source_tarball: Path
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
            self.sbom_cdx_sig,
            self.sbom_cdx_bundle,
            self.sbom_spdx_sig,
            self.sbom_spdx_bundle,
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
        sdist=sdist,
        source_tarball=source,
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
    signed = run_cosign(
        "sign-blob",
        "--yes",
        str(notes),
        "--bundle",
        str(notes) + ".bundle",
        "--output-signature",
        str(notes) + ".sig",
    )
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

    # (1) Typed mandatory asset manifest: presence + names + versions.
    try:
        manifest = build_asset_manifest(dist_dir, notes, prov_dir, version)
    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    # (2) Checksums must cover every attached asset and match content.
    if not verify_checksums(manifest):
        print("ERROR: checksum verification failed", file=sys.stderr)
        return 1

    # (3) Tag must resolve to the artifact's source commit.
    source_sha = args.source_sha or run_git("rev-parse", "HEAD")
    if not verify_tag_binding(tag, source_sha):
        return 1

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
    subprocess.run(cmd, check=True)

    print(
        "Release published. Provenance attestations are also available in the "
        "repository attestation store (`gh attestation verify`)."
    )
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
    p_upload.set_defaults(func=cmd_upload)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
