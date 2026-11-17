"""W10 Worker A — release-candidate manifest schema and manifest tests.

The candidate-manifest schema is the 14th packaged schema. These tests
cover the schema contract (load, version, dispatch, rejection of bad
payloads) and — once ``docs/release/candidate-manifest.json`` exists —
the committed candidate manifest itself: it must validate, its
in-repo asset digests must match the files on disk, and its
reproducibility record must be internally consistent with the asset
digests it lists.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "docs" / "release" / "candidate-manifest.json"

EXPECTED_KINDS = {
    "license",
    "license-notice",
    "sbom",
    "sdist",
    "source-archive",
    "wheel",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*args, timeout=30):
    """Run git in the repo root; return the CompletedProcess."""
    import subprocess

    return subprocess.run(
        ["git", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _is_shallow_checkout():
    result = _git("rev-parse", "--is-shallow-repository")
    return result.returncode == 0 and result.stdout.strip() == "true"


def _ensure_source_sha_available(source_sha):
    """Make ``source_sha`` resolvable in this checkout, or skip.

    A depth-1 checkout (the CI default) does not contain the
    candidate source commit even though it is a real commit on main,
    so ``git cat-file -e <sha>^{commit}`` fails there. In that case
    fetch just that commit from the remote (GitHub serves
    arbitrary-SHA fetches) and re-check, so the manifest is still
    verified against its real source commit in CI. Skip only when
    the checkout is shallow AND the fetch fails (no remote /
    offline): the check is then unverifiable here, not failed. In a
    full checkout a missing object is a real failure and raises.
    """
    import unittest

    if _git("cat-file", "-e", f"{source_sha}^{{commit}}").returncode == 0:
        return
    if not _is_shallow_checkout():
        raise AssertionError(f"source_sha {source_sha} is not a commit")
    try:
        fetched = _git("fetch", "--no-tags", "--depth=1", "origin", source_sha, timeout=120)
    except Exception:
        fetched = None
    if (
        fetched is not None
        and fetched.returncode == 0
        and _git("cat-file", "-e", f"{source_sha}^{{commit}}").returncode == 0
    ):
        return
    raise unittest.SkipTest(
        f"shallow checkout: source_sha {source_sha} is not present "
        "locally and could not be fetched from origin, so the "
        "manifest cannot be verified against its source commit here"
    )


class CandidateManifestSchemaTests(unittest.TestCase):
    """The 14th packaged schema: load, version, dispatch, rejection."""

    def test_schema_loads_with_expected_identity(self):
        from textforensics.schema import load_schema

        schema = load_schema("candidate-manifest")
        self.assertEqual(schema["$id"], "textforensics.candidate-manifest/v1")
        self.assertEqual(schema["title"], "TextForensics Release Candidate Manifest")
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "textforensics.candidate-manifest/v1",
        )

    def test_supported_versions_is_exactly_v1(self):
        from textforensics.schema import supported_versions

        self.assertEqual(
            supported_versions("candidate-manifest"),
            {"textforensics.candidate-manifest/v1"},
        )

    def test_registry_counts_fourteen_schemas(self):
        from textforensics.schema import list_schemas

        self.assertEqual(len(list_schemas()), 14)
        self.assertIn("candidate-manifest", list_schemas())

    def test_validate_accepts_minimal_synthetic_payload(self):
        from test_schema import _valid_payloads

        from textforensics.schema import validate, validate_candidate_manifest

        payload = _valid_payloads()["candidate-manifest"]
        self.assertEqual(validate_candidate_manifest(payload), [])
        self.assertEqual(validate(payload, "candidate-manifest"), [])

    def test_validate_rejects_wrong_version(self):
        from test_schema import _valid_payloads

        from textforensics.schema import validate_candidate_manifest

        payload = json.loads(json.dumps(_valid_payloads()["candidate-manifest"]))
        payload["schema"] = "textforensics.candidate-manifest/v999"
        errors = validate_candidate_manifest(payload)
        self.assertTrue(any("unsupported schema version" in e for e in errors), errors)

    def test_validate_rejects_bad_digest_and_missing_asset(self):
        from test_schema import _valid_payloads

        from textforensics.schema import validate_candidate_manifest

        payload = json.loads(json.dumps(_valid_payloads()["candidate-manifest"]))
        payload["assets"][0]["sha256"] = "not-a-digest"
        errors = validate_candidate_manifest(payload)
        self.assertTrue(errors, "bad sha256 must be rejected")

        payload = json.loads(json.dumps(_valid_payloads()["candidate-manifest"]))
        del payload["assets"][0]
        errors = validate_candidate_manifest(payload)
        self.assertTrue(errors, "fewer than six assets must be rejected")

    def test_validate_rejects_non_identical_reproducibility(self):
        from test_schema import _valid_payloads

        from textforensics.schema import validate_candidate_manifest

        payload = json.loads(json.dumps(_valid_payloads()["candidate-manifest"]))
        payload["reproducibility"]["identical"] = False
        errors = validate_candidate_manifest(payload)
        self.assertTrue(errors, "identical=false must be rejected")


@unittest.skipUnless(MANIFEST_PATH.exists(), "candidate manifest not committed yet")
class CommittedCandidateManifestTests(unittest.TestCase):
    """The committed docs/release/candidate-manifest.json itself.

    These tests only run once the manifest exists (H2 commit). They
    check the real manifest: schema validity, one asset per required
    kind, internal consistency between the reproducibility record and
    the asset digests, and digest agreement for every in-repo asset.
    """

    def setUp(self):
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_manifest_validates_against_its_schema(self):
        from textforensics.schema import validate_candidate_manifest

        self.assertEqual(validate_candidate_manifest(self.manifest), [])

    def test_manifest_covers_all_six_asset_kinds_exactly_once(self):
        kinds = [asset["kind"] for asset in self.manifest["assets"]]
        self.assertEqual(sorted(kinds), sorted(EXPECTED_KINDS))
        self.assertEqual(len(kinds), len(set(kinds)))

    def test_reproducibility_record_matches_asset_digests(self):
        repro = self.manifest["reproducibility"]
        by_kind = {a["kind"]: a for a in self.manifest["assets"]}
        self.assertTrue(repro["identical"])
        self.assertEqual(repro["builds"], 2)
        self.assertEqual(repro["wheel"]["build_a_sha256"], by_kind["wheel"]["sha256"])
        self.assertEqual(repro["wheel"]["build_b_sha256"], by_kind["wheel"]["sha256"])
        self.assertEqual(repro["sdist"]["build_a_sha256"], by_kind["sdist"]["sha256"])
        self.assertEqual(repro["sdist"]["build_b_sha256"], by_kind["sdist"]["sha256"])
        self.assertEqual(
            repro["source_archive"]["build_a_sha256"],
            by_kind["source-archive"]["sha256"],
        )
        self.assertEqual(
            repro["source_archive"]["build_b_sha256"],
            by_kind["source-archive"]["sha256"],
        )
        self.assertTrue(repro["source_archive"]["identical"])

    def test_source_sha_is_a_real_commit(self):
        source_sha = self.manifest["candidate"]["source_sha"]
        # Shallow-checkout tolerant: fetches the commit from the
        # remote when needed (see _ensure_source_sha_available).
        _ensure_source_sha_available(source_sha)

    def test_in_repo_asset_digests_and_sizes_match_disk(self):
        for asset in self.manifest["assets"]:
            if asset["kind"] not in ("license", "license-notice", "sbom"):
                continue
            path = REPO_ROOT / asset["path"]
            self.assertTrue(path.is_file(), f"missing in-repo asset {path}")
            self.assertEqual(_sha256_file(path), asset["sha256"], f"digest mismatch: {path}")
            self.assertEqual(path.stat().st_size, asset["size_bytes"], f"size mismatch: {path}")

    def test_sbom_asset_matches_committed_sbom_metadata(self):
        sbom_path = REPO_ROOT / "sbom" / "textforensics.cdx.json"
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        asset = next(a for a in self.manifest["assets"] if a["kind"] == "sbom")
        self.assertEqual(asset["sbom_serial_number"], sbom["serialNumber"])
        self.assertEqual(asset["sbom_components"], len(sbom["components"]))
        self.assertEqual(asset["path"], "sbom/textforensics.cdx.json")

    def test_build_profile_matches_tools_lockfile_at_source_sha(self):
        import hashlib
        import subprocess

        profile = self.manifest["candidate"]["build_profile"]
        source_sha = self.manifest["candidate"]["source_sha"]
        # Shallow-checkout tolerant: fetches the commit from the
        # remote when needed, so `git show <sha>:...` below can run.
        _ensure_source_sha_available(source_sha)
        result = subprocess.run(
            ["git", "show", f"{source_sha}:requirements-tools-hashed.txt"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, "lockfile missing at source_sha")
        digest = hashlib.sha256(result.stdout).hexdigest()
        self.assertEqual(digest, profile["tools_lockfile_sha256"])
        text = result.stdout.decode("utf-8")
        for name in ("build", "setuptools", "wheel"):
            self.assertIn(f"{name}=={profile[name]}", text)


if __name__ == "__main__":
    unittest.main()
