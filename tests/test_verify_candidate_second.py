"""Tests for scripts/verify_candidate_second.py (W10 second verifier).

The verifier reproduces the complete unpublished asset set from scratch
(fresh checkout, fresh venv, rebuild) and verifies it against a candidate
manifest with the REAL cosign verify-blob path. These tests cover the
pure verification logic; the end-to-end rebuild is exercised by
``verify ... self-test`` (see the W10-C report) and by the verifier's own
control case, not by this suite (a full rebuild takes minutes).

Cosign tests use the real cosign binary when it is on PATH and skip
otherwise: a missing cosign binary must never be reported as a pass.
"""

import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_candidate_second", SCRIPTS_DIR / "verify_candidate_second.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_candidate_second"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verifier():
    return _load_module()


SHA = "a" * 40
OTHER_SHA = "b" * 40


def _good_manifest():
    return {
        "format": "textforensics-candidate-manifest/1",
        "version": "0.2.0",
        "source_sha": SHA,
        "tag": "v0.2.0",
        "build": {},
        "assets": [
            {"name": "textforensics-0.2.0-py3-none-any.whl",
             "sha256": "0" * 64, "size": 10},
            {"name": "SHA256SUMS", "sha256": "1" * 64, "size": 20},
        ],
        "checksums_file": "SHA256SUMS",
        "signer": {"mode": "local-key", "public_key_sha256": "2" * 64},
        "provenance": {"bundles": []},
    }


# --- manifest schema --------------------------------------------------------


def test_valid_manifest_schema_passes(verifier):
    assert verifier.validate_manifest_schema(_good_manifest()) == []


def test_manifest_wrong_format_fails(verifier):
    manifest = _good_manifest()
    manifest["format"] = "something-else/9"
    errors = verifier.validate_manifest_schema(manifest)
    assert any("format" in e for e in errors)


def test_manifest_missing_field_fails(verifier):
    manifest = _good_manifest()
    del manifest["tag"]
    errors = verifier.validate_manifest_schema(manifest)
    assert any("tag" in e for e in errors)


def test_manifest_malformed_sha_fails(verifier):
    manifest = _good_manifest()
    manifest["assets"][0]["sha256"] = "not-a-sha"
    errors = verifier.validate_manifest_schema(manifest)
    assert any("malformed sha256" in e for e in errors)


def test_manifest_duplicate_asset_fails(verifier):
    manifest = _good_manifest()
    manifest["assets"].append(dict(manifest["assets"][0]))
    errors = verifier.validate_manifest_schema(manifest)
    assert any("twice" in e for e in errors)


def test_manifest_missing_checksums_file_fails(verifier):
    manifest = _good_manifest()
    manifest["assets"] = [manifest["assets"][0]]
    errors = verifier.validate_manifest_schema(manifest)
    assert any("checksums file" in e for e in errors)


def test_load_manifest_unreadable_raises_unevaluated(verifier, tmp_path):
    missing = tmp_path / "nope.json"
    with pytest.raises(verifier.Unevaluated):
        verifier.load_manifest(missing)


def test_load_manifest_malformed_json_raises_unevaluated(verifier, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(verifier.Unevaluated):
        verifier.load_manifest(bad)


# --- tarball comparison -----------------------------------------------------


def _make_tarball(path: Path, members: dict[str, bytes], mtime: int) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, data in sorted(members.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(data))


def test_compare_tarballs_identical_bytes(verifier, tmp_path):
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    _make_tarball(a, {"x.txt": b"hello"}, 1704067200)
    shutil.copyfile(a, b)
    assert verifier.compare_tarballs(a, b, "test") == []


def test_compare_tarballs_metadata_only_difference(verifier, tmp_path):
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    _make_tarball(a, {"x.txt": b"hello"}, 1704067200)
    _make_tarball(b, {"x.txt": b"hello"}, 1704067201)
    errors = verifier.compare_tarballs(a, b, "test")
    assert len(errors) == 1
    assert "member contents are identical" in errors[0]


def test_compare_tarballs_content_difference(verifier, tmp_path):
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    _make_tarball(a, {"x.txt": b"hello"}, 1704067200)
    _make_tarball(b, {"x.txt": b"HELLO"}, 1704067200)
    errors = verifier.compare_tarballs(a, b, "test")
    assert len(errors) == 1
    assert "member contents differ" in errors[0]


def test_compare_tarballs_missing_member(verifier, tmp_path):
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    _make_tarball(a, {"x.txt": b"hello", "y.txt": b"world"}, 1704067200)
    _make_tarball(b, {"x.txt": b"hello"}, 1704067200)
    errors = verifier.compare_tarballs(a, b, "test")
    assert errors and "member contents differ" in errors[0]


# --- notes ------------------------------------------------------------------


def test_strip_generated_line(verifier):
    text = "# textforensics v0.2.0\n- **Generated:** 2026-11-17 00:00:00 UTC\n- **Release commit:** `abc123`\n"
    stripped = verifier.strip_generated_line(text)
    assert "Generated:" not in stripped
    assert "Release commit:" in stripped


# --- bundle structure -------------------------------------------------------


def test_bundle_structure_keyless_ok(verifier, tmp_path):
    bundle = tmp_path / "x.bundle"
    bundle.write_text(
        json.dumps({"verificationMaterial": {}, "dsseEnvelope": {}}),
        encoding="utf-8")
    assert verifier.validate_bundle_structure(bundle) is None


def test_bundle_structure_local_key_ok(verifier, tmp_path):
    bundle = tmp_path / "x.bundle"
    bundle.write_text(
        json.dumps({"verificationMaterial": {}, "messageSignature": {}}),
        encoding="utf-8")
    assert verifier.validate_bundle_structure(bundle) is None


def test_bundle_structure_garbage_fails(verifier, tmp_path):
    bundle = tmp_path / "x.bundle"
    bundle.write_text("not json", encoding="utf-8")
    assert verifier.validate_bundle_structure(bundle) is not None


def test_bundle_structure_no_verification_material_fails(verifier, tmp_path):
    bundle = tmp_path / "x.bundle"
    bundle.write_text(json.dumps({"dsseEnvelope": {}}), encoding="utf-8")
    assert verifier.validate_bundle_structure(bundle) is not None


# --- check-run evaluation ---------------------------------------------------


def _all_pass_runs(verifier):
    return [{"name": prefix, "status": "completed", "conclusion": "success",
             "head_sha": SHA} for prefix in verifier.REQUIRED_CHECKS]


def test_check_runs_all_pass(verifier):
    assert verifier.evaluate_check_runs(_all_pass_runs(verifier), SHA) == []


def test_check_runs_failed_blocks(verifier):
    runs = _all_pass_runs(verifier)
    runs[0] = {**runs[0], "conclusion": "failure"}
    blockers = verifier.evaluate_check_runs(runs, SHA)
    assert len(blockers) == 1
    assert "did not pass" in blockers[0]


def test_check_runs_skipped_blocks(verifier):
    runs = _all_pass_runs(verifier)
    runs[1] = {**runs[1], "conclusion": "skipped"}
    blockers = verifier.evaluate_check_runs(runs, SHA)
    assert len(blockers) == 1
    assert "was skipped" in blockers[0]


def test_check_runs_stale_blocks(verifier):
    runs = _all_pass_runs(verifier)
    runs[2] = {**runs[2], "head_sha": OTHER_SHA}
    blockers = verifier.evaluate_check_runs(runs, SHA)
    assert len(blockers) == 1
    assert "is stale" in blockers[0]


def test_check_runs_missing_blocks(verifier):
    runs = _all_pass_runs(verifier)[:-1]
    blockers = verifier.evaluate_check_runs(runs, SHA)
    assert len(blockers) == 1
    assert "no check-run" in blockers[0]


def test_check_runs_matrix_legs_all_must_pass(verifier):
    runs = _all_pass_runs(verifier)
    runs.append({**runs[1], "name": runs[1]["name"] + " 3.11",
                 "conclusion": "failure"})
    blockers = verifier.evaluate_check_runs(runs, SHA)
    assert len(blockers) == 1
    assert "did not pass" in blockers[0]


# --- real cosign verify-blob ------------------------------------------------


@pytest.fixture()
def cosign_keypair(tmp_path):
    """A real local Ed25519 key pair (openssl) for cosign --key checks.

    Signatures are made with openssl, not ``cosign sign-blob``: on this
    VM cosign v3.1.4 sign-blob mandates --bundle, and bundle creation
    POSTs to Rekor and the Sigstore TSA, which the egress proxy blocks
    (see scripts/verify_candidate_second.py). Verification itself is
    the real cosign path (``verify-blob --key``)."""
    cosign = shutil.which("cosign")
    if cosign is None:
        pytest.skip("cosign binary not on PATH")
    if shutil.which("openssl") is None:
        pytest.skip("openssl binary not on PATH")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519",
         "-out", str(tmp_path / "cosign.key")],
        capture_output=True, check=True, stdin=subprocess.DEVNULL, timeout=120)
    subprocess.run(
        ["openssl", "pkey", "-in", str(tmp_path / "cosign.key"),
         "-pubout", "-out", str(tmp_path / "cosign.pub")],
        capture_output=True, check=True, stdin=subprocess.DEVNULL, timeout=120)
    return cosign, tmp_path / "cosign.key", tmp_path / "cosign.pub"


def _sign(key, payload: Path) -> Path:
    """Sign with openssl (Ed25519, raw) and write a base64 .sig."""
    import base64

    raw = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", str(key),
         "-rawin", "-in", str(payload)],
        capture_output=True, check=True, stdin=subprocess.DEVNULL, timeout=120)
    sig = payload.with_suffix(payload.suffix + ".sig")
    sig.write_bytes(base64.b64encode(raw.stdout) + b"\n")
    return sig


def test_cosign_verify_blob_real_path_accepts(verifier, tmp_path, cosign_keypair):
    cosign, key, pub = cosign_keypair
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"candidate bytes")
    sig = _sign(key, payload)
    # Local-key verification uses the public key + --insecure-ignore-tlog
    # (rehearsal signatures are never Rekor-logged; see module docstring).
    ok, detail = verifier.verify_cosign_blob(
        cosign, payload=payload, sig=sig, bundle=None,
        key=pub, identity=None, issuer=None, insecure_ignore_tlog=True)
    assert ok, detail
    assert detail == "Verified OK"


def test_cosign_verify_blob_rejects_tampered_payload(
        verifier, tmp_path, cosign_keypair):
    cosign, key, pub = cosign_keypair
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"candidate bytes")
    sig = _sign(key, payload)
    payload.write_bytes(b"candidate BYTEs")
    ok, detail = verifier.verify_cosign_blob(
        cosign, payload=payload, sig=sig, bundle=None,
        key=pub, identity=None, issuer=None, insecure_ignore_tlog=True)
    assert not ok
    assert "rejected" in detail


def test_cosign_verify_blob_rejects_wrong_key(
        verifier, tmp_path, cosign_keypair):
    cosign, key, pub = cosign_keypair
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"candidate bytes")
    sig = _sign(key, payload)
    # A second, unrelated key pair.
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519",
         "-out", str(other / "cosign.key")],
        capture_output=True, check=True, stdin=subprocess.DEVNULL, timeout=120)
    subprocess.run(
        ["openssl", "pkey", "-in", str(other / "cosign.key"),
         "-pubout", "-out", str(other / "cosign.pub")],
        capture_output=True, check=True, stdin=subprocess.DEVNULL, timeout=120)
    ok, detail = verifier.verify_cosign_blob(
        cosign, payload=payload, sig=sig, bundle=None,
        key=other / "cosign.pub", identity=None, issuer=None,
        insecure_ignore_tlog=True)
    assert not ok
    assert "rejected" in detail
