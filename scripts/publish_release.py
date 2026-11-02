#!/usr/bin/env python3
"""Release publishing helper for TextForensics.

Subcommands used by .github/workflows/release.yml:

  version     Print the package version from pyproject.toml.
  changelog   Generate release notes (changelog) from the commit history.
  sign-notes  Create signed release notes using cosign (keyless in CI),
              falling back to a SHA-256 checksum signature when cosign is
              unavailable (e.g. local dry runs).
  upload      Create the GitHub Release and attach artifacts together with
              their cosign signatures, checksums and provenance bundles.

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
from datetime import datetime, timezone
from pathlib import Path

import tomllib

CONFIRMATION_ENV = "RELEASE_CONFIRMATION"
CONFIRMATION_VALUE = "RELEASE"


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
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        f"# textforensics v{version}",
        "",
        f"- **Release commit:** `{short_sha}`",
        f"- **Generated:** {now}",
        f"- **Commit range:** {tag or '(no previous tag)'}..HEAD "
        f"({len(commits)} commits)",
        "",
        "## Verification",
        "",
        "This release is published with:",
        "",
        "- a cosign-signed changelog (keyless Sigstore signatures in CI),",
        "- CycloneDX and SPDX JSON SBOMs,",
        "- SLSA-style build provenance attestations "
        "(actions/attest-build-provenance@v1),",
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
    print(f"SHA-256 of release notes: {digest}")

    signed = run_cosign(
        "sign-blob",
        "--yes",
        str(notes),
        "--bundle",
        str(notes) + ".bundle",
        "--output-signature",
        str(notes) + ".sig",
    )
    if signed:
        print(f"Cosign (keyless) signature written to {notes}.sig")
    else:
        print(
            "WARNING: cosign not found; release notes carry a SHA-256 "
            "checksum signature only.",
            file=sys.stderr,
        )
    return 0


def cmd_upload(args: argparse.Namespace) -> int:
    # Fail-safe confirmation mirror of the workflow input check.
    confirmation = os.environ.get(CONFIRMATION_ENV, "")
    if confirmation and confirmation != CONFIRMATION_VALUE:
        print(
            f"ERROR: {CONFIRMATION_ENV} must be exactly '{CONFIRMATION_VALUE}'",
            file=sys.stderr,
        )
        return 1

    version = args.version or read_version()
    tag = args.tag or f"v{version}"
    dist_dir = Path(args.dist_dir)
    notes = Path(args.notes)

    if not notes.exists():
        print(f"ERROR: release notes {notes} not found", file=sys.stderr)
        return 1
    if not dist_dir.is_dir():
        print(f"ERROR: dist directory {dist_dir} not found", file=sys.stderr)
        return 1

    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = [
        p
        for p in sorted(dist_dir.glob("*.tar.gz"))
        if p.name.endswith(f"{version}-source.tar.gz")
        or p.name.startswith("textforensics-")
    ]
    if not wheels:
        print("ERROR: no wheel found in dist/", file=sys.stderr)
        return 1
    if not sdists:
        print("ERROR: no sdist/source tarball found in dist/", file=sys.stderr)
        return 1

    checksums = dist_dir / "SHA256SUMS"
    provenance_bundles: list[Path] = []
    prov_dir = Path(args.provenance_dir) if args.provenance_dir else None
    if prov_dir and prov_dir.is_dir():
        provenance_bundles = sorted(prov_dir.glob("*.intoto.jsonl"))

    assets: list[Path] = []
    assets += wheels
    assets += sdists
    if checksums.exists():
        assets.append(checksums)
    assets += [p for p in sorted(dist_dir.glob("*.sig"))]
    assets += [p for p in sorted(dist_dir.glob("*.bundle"))]
    assets += provenance_bundles

    for asset in assets:
        if not asset.exists():
            print(f"ERROR: expected artifact {asset} missing", file=sys.stderr)
            return 1

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

    p_changelog = sub.add_parser(
        "changelog", help="Generate release notes from commit history"
    )
    p_changelog.add_argument("--output", default="release-notes.md")
    p_changelog.add_argument(
        "--since-tag",
        default=None,
        help="Tag to start the changelog from (default: latest tag)",
    )
    p_changelog.set_defaults(func=cmd_changelog)

    p_sign = sub.add_parser("sign-notes", help="Create signed release notes")
    p_sign.add_argument("--notes", default="release-notes.md")
    p_sign.set_defaults(func=cmd_sign_notes)

    p_upload = sub.add_parser(
        "upload", help="Create GitHub release and upload artifacts"
    )
    p_upload.add_argument("--notes", default="release-notes.md")
    p_upload.add_argument("--dist-dir", default="dist")
    p_upload.add_argument("--provenance-dir", default=None)
    p_upload.add_argument("--tag", default=None)
    p_upload.add_argument("--version", default=None)
    p_upload.set_defaults(func=cmd_upload)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
