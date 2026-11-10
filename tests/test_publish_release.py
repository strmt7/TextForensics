"""Tests for scripts/publish_release.py (ENG-05 / ENG-06 publication boundary).

Publication must fail closed: exact confirmation, a typed mandatory asset
manifest (wheel, sdist, source tarball, notes + verification material, both
SBOM payloads + their signatures/bundles, SHA256SUMS, provenance), per-asset
content validation, tag -> commit -> artifact-SHA binding, and cryptographic
signing in publication mode.

Every negative test asserts the failure happens BEFORE any remote-writing
command is invoked: the mocked subprocess receives zero remote-writing calls.
No test contacts GitHub, a registry, or any publishing endpoint.

NO-PUBLICATION TEST (W0 acceptance): see
``test_no_publication_mode_invokes_zero_remote_writes`` at the end.
"""

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"

REMOTE_WRITE_PREFIXES = (
    ("gh", "release", "create"),
    ("gh", "release", "upload"),
    ("twine", "upload"),
    ("docker", "push"),
    ("git", "tag"),
    ("git", "push"),
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "publish_release", SCRIPTS_DIR / "publish_release.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["publish_release"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def pub():
    return _load_module()


VERSION = "9.9.9"
TAG = "v9.9.9"
SOURCE_SHA = "c" * 40


class RemoteCallRecorder:
    """Records every subprocess.run call; reports remote-writing ones."""

    def __init__(self):
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    def remote_writes(self):
        return [
            c
            for c in self.calls
            if tuple(c[:3]) in REMOTE_WRITE_PREFIXES
            or tuple(c[:2]) in {("docker", "push"), ("twine", "upload")}
        ]

    def assert_no_remote_writes(self):
        assert self.remote_writes() == [], f"remote writes invoked: {self.remote_writes()}"


@pytest.fixture
def recorder(pub, monkeypatch):
    rec = RemoteCallRecorder()
    monkeypatch.setattr(pub.subprocess, "run", rec)
    return rec


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, data: bytes = b"payload") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _write_checksums(dist: Path, assets: list[Path]) -> Path:
    sums = dist / "SHA256SUMS"
    lines = "".join(f"{_sha256(a)}  {a.name}\n" for a in assets)
    sums.write_text(lines, encoding="utf-8")
    return sums


@pytest.fixture
def valid_dist(tmp_path, monkeypatch):
    """A complete, correctly-named, correctly-checksummed release fixture."""
    dist = tmp_path / "dist"
    prov = tmp_path / "provenance"
    notes = tmp_path / "release-notes.md"
    _write(notes, b"# textforensics v9.9.9\n")
    wheel = _write(dist / f"textforensics-{VERSION}-py3-none-any.whl", b"wheel-bytes")
    sdist = _write(dist / f"textforensics-{VERSION}.tar.gz", b"sdist-bytes")
    source = _write(dist / f"textforensics-{VERSION}-source.tar.gz", b"source-bytes")
    cdx = _write(dist / "textforensics-sbom.cdx.json", b'{"bomFormat":"CycloneDX"}')
    spdx = _write(dist / "textforensics-sbom.spdx.json", b'{"spdxVersion":"SPDX-2.3"}')
    cdx_sig = _write(dist / "textforensics-sbom.cdx.json.sig", b"sig")
    cdx_bundle = _write(dist / "textforensics-sbom.cdx.json.bundle", b"bundle")
    spdx_sig = _write(dist / "textforensics-sbom.spdx.json.sig", b"sig")
    spdx_bundle = _write(dist / "textforensics-sbom.spdx.json.bundle", b"bundle")
    notes_sig = _write(tmp_path / "release-notes.md.sig", b"sig")
    notes_bundle = _write(tmp_path / "release-notes.md.bundle", b"bundle")
    notes_sum = tmp_path / "release-notes.md.sha256"
    notes_sum.write_text(f"{_sha256(notes)}  release-notes.md\n", encoding="utf-8")
    bundle0 = _write(prov / "provenance-bundle-0.intoto.jsonl", b"provenance")
    payload_assets = [
        wheel,
        sdist,
        source,
        cdx,
        spdx,
        cdx_sig,
        cdx_bundle,
        spdx_sig,
        spdx_bundle,
        notes,
        notes_sig,
        notes_bundle,
        bundle0,
    ]
    _write_checksums(dist, payload_assets)
    # Tag v9.9.9 resolves to the artifact source commit.
    monkeypatch.setattr(
        sys.modules["publish_release"],
        "run_git",
        lambda *args: SOURCE_SHA if TAG in args[0] else SOURCE_SHA,
    )
    return {
        "dist": dist,
        "prov": prov,
        "notes": notes,
        "wheel": wheel,
        "sdist": sdist,
        "source": source,
        "cdx": cdx,
        "spdx": spdx,
        "assets": payload_assets,
    }


def _upload_args(fx, extra=None):
    args = [
        "upload",
        "--notes",
        str(fx["notes"]),
        "--dist-dir",
        str(fx["dist"]),
        "--provenance-dir",
        str(fx["prov"]),
        "--tag",
        TAG,
        "--version",
        VERSION,
        "--source-sha",
        SOURCE_SHA,
    ]
    return args + (extra or [])


def _run_upload(pub, fx, monkeypatch, confirmation="RELEASE"):
    if confirmation is None:
        monkeypatch.delenv("RELEASE_CONFIRMATION", raising=False)
    else:
        monkeypatch.setenv("RELEASE_CONFIRMATION", confirmation)
    args = pub.build_parser().parse_args(_upload_args(fx))
    return pub.cmd_upload(args)


# --- ENG-05: confirmation ---------------------------------------------------


def test_upload_fails_with_confirmation_unset(pub, valid_dist, recorder, monkeypatch):
    rc = _run_upload(pub, valid_dist, monkeypatch, confirmation=None)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_with_confirmation_empty(pub, valid_dist, recorder, monkeypatch):
    rc = _run_upload(pub, valid_dist, monkeypatch, confirmation="")
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_with_wrong_confirmation(pub, valid_dist, recorder, monkeypatch):
    rc = _run_upload(pub, valid_dist, monkeypatch, confirmation="YES")
    assert rc != 0
    recorder.assert_no_remote_writes()


# --- ENG-05: audit probe regression (fake wheel, no confirmation) -----------


def test_audit_probe_wrong_name_wheel_no_confirmation_fails(pub, tmp_path, recorder, monkeypatch):
    """ENG-05 reproduction: no confirmation + wrong-name wheel used to exit 0
    with a captured would-be `gh release create`. It must now fail first."""
    dist = tmp_path / "dist"
    _write(dist / "wrong-name-9.9.9-py3-none-any.whl", b"fake wheel")
    _write(dist / "textforensics-9.9.9-source.tar.gz", b"fake sdist")
    notes = _write(tmp_path / "release-notes.md", b"# notes\n")
    monkeypatch.delenv("RELEASE_CONFIRMATION", raising=False)
    args = pub.build_parser().parse_args(
        [
            "upload",
            "--notes",
            str(notes),
            "--dist-dir",
            str(dist),
            "--version",
            "9.9.9",
        ]
    )
    assert pub.cmd_upload(args) != 0
    recorder.assert_no_remote_writes()


# --- ENG-05: typed manifest, per-asset validation ---------------------------


def test_upload_succeeds_with_complete_valid_manifest(pub, valid_dist, recorder, monkeypatch):
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc == 0
    assert len(recorder.remote_writes()) == 1
    cmd = recorder.remote_writes()[0]
    assert cmd[:3] == ["gh", "release", "create"]
    assert cmd[3] == TAG
    # ENG-06: both SBOM payloads must actually be attached.
    assert str(valid_dist["cdx"]) in cmd
    assert str(valid_dist["spdx"]) in cmd
    assert str(valid_dist["wheel"]) in cmd
    assert str(valid_dist["source"]) in cmd


def test_upload_fails_with_wrong_name_wheel(pub, valid_dist, recorder, monkeypatch):
    valid_dist["wheel"].unlink()
    _write(valid_dist["dist"] / f"wrong-name-{VERSION}-py3-none-any.whl", b"wheel-bytes")
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_with_wheel_version_mismatch(pub, valid_dist, recorder, monkeypatch):
    valid_dist["wheel"].unlink()
    _write(valid_dist["dist"] / "textforensics-9.9.8-py3-none-any.whl", b"wheel-bytes")
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


@pytest.mark.parametrize("missing", ["wheel", "sdist", "source", "cdx", "spdx"])
def test_upload_fails_when_mandatory_payload_missing(
    pub, valid_dist, recorder, monkeypatch, missing
):
    valid_dist[missing].unlink()
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_sbom_signature_missing(pub, valid_dist, recorder, monkeypatch):
    (valid_dist["dist"] / "textforensics-sbom.cdx.json.sig").unlink()
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_sbom_bundle_missing(pub, valid_dist, recorder, monkeypatch):
    (valid_dist["dist"] / "textforensics-sbom.spdx.json.bundle").unlink()
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_notes_signature_missing(pub, valid_dist, recorder, monkeypatch):
    (valid_dist["notes"].parent / "release-notes.md.sig").unlink()
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_notes_bundle_missing(pub, valid_dist, recorder, monkeypatch):
    (valid_dist["notes"].parent / "release-notes.md.bundle").unlink()
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_sha256sums_missing(pub, valid_dist, recorder, monkeypatch):
    (valid_dist["dist"] / "SHA256SUMS").unlink()
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_provenance_missing(pub, valid_dist, recorder, monkeypatch):
    for p in valid_dist["prov"].glob("*.intoto.jsonl"):
        p.unlink()
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_checksum_mismatches_tampered_payload(
    pub, valid_dist, recorder, monkeypatch
):
    valid_dist["wheel"].write_bytes(b"tampered-wheel-bytes")
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_checksum_entry_missing_for_asset(pub, valid_dist, recorder, monkeypatch):
    sums = valid_dist["dist"] / "SHA256SUMS"
    kept = [
        ln
        for ln in sums.read_text().splitlines()
        if Path(ln.split()[-1]).name != "textforensics-sbom.spdx.json"
    ]
    sums.write_text("\n".join(kept) + "\n", encoding="utf-8")
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_upload_fails_when_tag_resolves_to_other_commit(pub, valid_dist, recorder, monkeypatch):
    monkeypatch.setattr(
        sys.modules["publish_release"],
        "run_git",
        lambda *args: "d" * 40,  # tag exists but points elsewhere
    )
    rc = _run_upload(pub, valid_dist, monkeypatch)
    assert rc != 0
    recorder.assert_no_remote_writes()


def test_manifest_asset_list_includes_sbom_payloads(pub, valid_dist):
    manifest = pub.build_asset_manifest(
        dist_dir=valid_dist["dist"],
        notes=valid_dist["notes"],
        provenance_dir=valid_dist["prov"],
        version=VERSION,
    )
    names = [p.name for p in manifest.all_assets()]
    assert "textforensics-sbom.cdx.json" in names
    assert "textforensics-sbom.spdx.json" in names
    assert f"textforensics-{VERSION}-py3-none-any.whl" in names


def test_verify_checksums_rejects_tampered_payload(pub, valid_dist):
    manifest = pub.build_asset_manifest(
        dist_dir=valid_dist["dist"],
        notes=valid_dist["notes"],
        provenance_dir=valid_dist["prov"],
        version=VERSION,
    )
    assert pub.verify_checksums(manifest) is True
    valid_dist["cdx"].write_bytes(b"tampered sbom")
    assert pub.verify_checksums(manifest) is False


# --- ENG-06: sign-notes -----------------------------------------------------


def test_sign_notes_fails_when_cosign_absent_in_publication_mode(
    pub, tmp_path, recorder, monkeypatch, capsys
):
    """ENG-06 reproduction: sign-notes used to return 0 with cosign absent."""
    notes = _write(tmp_path / "release-notes.md", b"# notes\n")
    monkeypatch.setattr(pub, "run_cosign", lambda *a: False)
    args = pub.build_parser().parse_args(["sign-notes", "--notes", str(notes)])
    assert pub.cmd_sign_notes(args) != 0
    captured = capsys.readouterr()
    assert "checksum signature" not in captured.out.lower()
    assert "checksum signature" not in captured.err.lower()
    recorder.assert_no_remote_writes()


def test_sign_notes_succeeds_when_cosign_signs(pub, tmp_path, recorder, monkeypatch):
    notes = _write(tmp_path / "release-notes.md", b"# notes\n")
    monkeypatch.setattr(pub, "run_cosign", lambda *a: True)
    args = pub.build_parser().parse_args(["sign-notes", "--notes", str(notes)])
    assert pub.cmd_sign_notes(args) == 0
    recorder.assert_no_remote_writes()


def test_unsigned_preview_mode_is_ineligible_for_upload(
    pub, tmp_path, valid_dist, recorder, monkeypatch
):
    notes = _write(tmp_path / "preview-notes.md", b"# notes\n")
    args = pub.build_parser().parse_args(
        ["sign-notes", "--notes", str(notes), "--mode", "unsigned-preview"]
    )
    assert pub.cmd_sign_notes(args) == 0
    assert not (tmp_path / "preview-notes.md.sig").exists()
    assert (tmp_path / "preview-notes.md.unsigned-preview").exists()
    # Preview-signed notes must not reach the upload path.
    monkeypatch.setattr(pub, "run_cosign", lambda *a: True)
    upload_args = pub.build_parser().parse_args(
        [
            "upload",
            "--notes",
            str(notes),
            "--dist-dir",
            str(valid_dist["dist"]),
            "--provenance-dir",
            str(valid_dist["prov"]),
            "--tag",
            TAG,
            "--version",
            VERSION,
            "--source-sha",
            SOURCE_SHA,
        ]
    )
    monkeypatch.setenv("RELEASE_CONFIRMATION", "RELEASE")
    assert pub.cmd_upload(upload_args) != 0
    recorder.assert_no_remote_writes()


# --- NO-PUBLICATION TEST (W0 acceptance) ------------------------------------


def test_no_publication_mode_invokes_zero_remote_writes(
    pub, tmp_path, valid_dist, recorder, monkeypatch
):
    """Every publishing entry point, invoked in no-publication mode with
    mocked subprocess/network, must perform ZERO remote-writing invocations
    and return the documented refusal / not-applicable result."""
    monkeypatch.delenv("RELEASE_CONFIRMATION", raising=False)
    monkeypatch.setattr(pub, "run_cosign", lambda *a: False)

    # 1. Release upload path without confirmation: refusal, no remote writes.
    args = pub.build_parser().parse_args(_upload_args(valid_dist))
    assert pub.cmd_upload(args) != 0

    # 2. sign-notes in publication mode without cosign: refusal.
    notes = _write(tmp_path / "notes2.md", b"# notes\n")
    args = pub.build_parser().parse_args(["sign-notes", "--notes", str(notes)])
    assert pub.cmd_sign_notes(args) != 0

    # 3. sign-notes in unsigned-preview mode: not applicable to publication.
    args = pub.build_parser().parse_args(
        ["sign-notes", "--notes", str(notes), "--mode", "unsigned-preview"]
    )
    assert pub.cmd_sign_notes(args) == 0
    assert (tmp_path / "notes2.md.unsigned-preview").exists()

    # 4. Non-publishing entry points: no remote writes either.
    monkeypatch.setattr(pub, "read_version", lambda *a, **k: VERSION)
    monkeypatch.setattr(pub, "run_git", lambda *a: "")
    assert pub.main(["version"]) == 0
    args = pub.build_parser().parse_args(["changelog", "--output", str(tmp_path / "cl.md")])
    assert pub.cmd_changelog(args) == 0

    # 5. Promotion gate fetch path (read-only gh api) performs no writes.
    spec = importlib.util.spec_from_file_location(
        "promotion_gate", SCRIPTS_DIR / "promotion_gate.py"
    )
    gate = importlib.util.module_from_spec(spec)
    sys.modules["promotion_gate"] = gate
    spec.loader.exec_module(gate)
    seen = []
    gate.fetch_check_runs(
        "strmt7",
        "TextForensics",
        "a" * 40,
        runner=lambda cmd, **k: (
            seen.append(cmd) or type("R", (), {"stdout": '{"check_runs": []}'})()
        ),
    )
    assert seen == [
        [
            "gh",
            "api",
            "repos/strmt7/TextForensics/commits/" + "a" * 40 + "/check-runs?per_page=100",
        ]
    ]

    recorder.assert_no_remote_writes()
