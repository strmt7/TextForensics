#!/usr/bin/env python3
"""Verify a SIGNED GitHub Release exists for a candidate SHA (ENG-14).

Container promotion (and, by the same boundary, any publication) must
not happen for a candidate that was never published as a signed
release. The exact-SHA acceptance gate (scripts/promotion_gate.py)
proves the checks passed; this script proves the release exists and
is signed. Both must pass before mutable tags are pushed.

Checks, in order (all read-only ``gh api`` GETs; this script never
creates releases, tags, or registry writes):

1. Tag binding: the tag ``v<version>`` (default: the version in
   pyproject.toml) must resolve to exactly the candidate SHA. An
   annotated tag is dereferenced to its commit first; tag existence
   alone is not enough.
2. Release record: a release must exist for that tag and must not be
   a draft. A draft is not a published release.
3. Signature assets: the release must carry at least one
   signature/attestation asset (a file ending ``.sig`` or ``.bundle``).
   The release workflow signs the SBOM payloads and the release notes
   (scripts/publish_release.py), so a release with no signature asset
   did not go through the signed publication path and is unsigned.

Exit codes mirror the promotion gate: 0 promotion allowed, 1 refused,
2 the gate itself could not be evaluated (``gh`` unavailable, an
unexpected API failure, or a malformed response).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


class GateError(Exception):
    """The gate itself could not be evaluated (exit 2)."""


class Refusal(Exception):
    """Promotion is refused for a stated reason (exit 1)."""


def _version_from_pyproject() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def _gh_api(endpoint: str, runner=None) -> dict | list:
    """One read-only `gh api` GET. A 404 raises Refusal (the object
    does not exist); any other failure raises GateError."""
    run = runner or subprocess.run
    try:
        result = run(
            ["gh", "api", endpoint],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        # Any failure to invoke gh means the gate cannot be evaluated
        # (exit 2): it must never become a silent allow.
        raise GateError(f"`gh api {endpoint}` could not run: {exc}") from exc
    if result.returncode != 0:
        combined = (result.stdout + result.stderr).lower()
        if "404" in combined or "not found" in combined:
            raise Refusal(f"`gh api {endpoint}`: not found")
        raise GateError(
            f"`gh api {endpoint}` failed (exit {result.returncode}): "
            f"{(result.stdout + result.stderr).strip()[:500]}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(f"`gh api {endpoint}` returned unparseable JSON: {exc}") from exc


def _resolve_tag_to_commit(*, owner: str, repo: str, tag: str, runner=None) -> str:
    """Resolve a tag to its commit SHA, dereferencing annotated tags."""
    ref = _gh_api(f"repos/{owner}/{repo}/git/ref/tags/{tag}", runner=runner)
    if not isinstance(ref, dict):
        raise GateError(f"unexpected tag-ref response for {tag}: {ref!r}")
    obj = ref.get("object") or {}
    sha = obj.get("sha")
    if not sha:
        raise GateError(f"tag {tag} has no object SHA in its ref: {ref!r}")
    if obj.get("type") == "tag":
        tag_obj = _gh_api(f"repos/{owner}/{repo}/git/tags/{sha}", runner=runner)
        if not isinstance(tag_obj, dict):
            raise GateError(f"unexpected tag-object response for {tag}: {tag_obj!r}")
        commit_sha = (tag_obj.get("object") or {}).get("sha")
        if not commit_sha:
            raise GateError(f"annotated tag {tag} has no commit SHA: {tag_obj!r}")
        return str(commit_sha)
    return str(sha)


def verify_signed_release(*, sha: str, owner: str, repo: str, version: str, runner=None) -> dict:
    """Refuse (Refusal) or allow (return evidence dict) promotion."""
    tag = f"v{version}"
    try:
        commit_sha = _resolve_tag_to_commit(owner=owner, repo=repo, tag=tag, runner=runner)
    except Refusal as exc:
        raise Refusal(f"no tag {tag} resolves to a commit for candidate {sha}: {exc}") from exc
    if commit_sha != sha:
        raise Refusal(
            f"tag {tag} points at {commit_sha}, not candidate {sha}; "
            "the signed release (if any) is for a different commit"
        )
    try:
        release = _gh_api(f"repos/{owner}/{repo}/releases/tags/{tag}", runner=runner)
    except Refusal as exc:
        raise Refusal(
            f"no GitHub Release exists for tag {tag} (candidate {sha}): {exc}; "
            "promote only after the signed release is published"
        ) from exc
    if not isinstance(release, dict):
        raise GateError(f"unexpected release response for {tag}: {release!r}")
    if release.get("draft"):
        raise Refusal(f"release {tag} is a draft, not a published signed release")
    release_id = release.get("id")
    if release_id is None:
        raise GateError(f"release {tag} has no id: {release!r}")
    assets = _gh_api(
        f"repos/{owner}/{repo}/releases/{release_id}/assets?per_page=100", runner=runner
    )
    if not isinstance(assets, list):
        raise GateError(f"unexpected release-assets response for {tag}: {assets!r}")
    names = [str(a.get("name", "")) for a in assets if isinstance(a, dict)]
    signed = [n for n in names if n.endswith(".sig") or n.endswith(".bundle")]
    if not signed:
        raise Refusal(
            f"release {tag} (candidate {sha}) carries no signature asset "
            "(.sig / .bundle); the release is unsigned — it did not go "
            "through the signed publication path"
        )
    return {
        "tag": tag,
        "candidate_sha": sha,
        "release_id": release_id,
        "assets": names,
        "signature_assets": signed,
    }


def main(argv: list[str] | None = None, runner=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a signed GitHub Release exists for a candidate SHA.",
    )
    parser.add_argument("--sha", required=True, help="Candidate source SHA")
    parser.add_argument("--repo", required=True, help="Repository as owner/name")
    parser.add_argument(
        "--version",
        default=None,
        help="Package version (default: read from pyproject.toml)",
    )
    args = parser.parse_args(argv)
    if "/" not in args.repo:
        print("error: --repo must be owner/name", file=sys.stderr)
        return 2
    owner, repo = args.repo.split("/", 1)
    version = args.version or _version_from_pyproject()
    try:
        evidence = verify_signed_release(
            sha=args.sha, owner=owner, repo=repo, version=version, runner=runner
        )
    except Refusal as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    except GateError as exc:
        print(f"error: signed-release gate could not be evaluated: {exc}", file=sys.stderr)
        return 2
    print(
        f"signed release verified: tag {evidence['tag']} (release "
        f"{evidence['release_id']}) points at candidate {args.sha} and "
        f"carries signature assets: {', '.join(evidence['signature_assets'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
