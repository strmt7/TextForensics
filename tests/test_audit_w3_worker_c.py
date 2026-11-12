"""W3 Worker C — shared installed / packed / standalone acceptance corpus.

C04 is the hub: the same mutated cases must be rejected identically
through the installed combined verifier, the real packer, and the
truly standalone (no-install, stdlib-only) verifier.  Clean T1/T2
controls must keep producing the documented 0/1/2 states.

Also holds the C05 duplicate-member corpus, the C06 seal-record
spy tests, and the C10 v3-map corpus entries (the installed-side
v3 tests live in test_verify_consolidation.py).
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import math
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from textforensics.casefile import seal_case_file
from textforensics.report import build_forensic_bundle
from textforensics.sealed_bundle import (
    SealedBundleError,
    canonical_json_bytes,
    pack_sealed_bundle,
    verify_sealed_bundle,
)
from textforensics.sealing import public_key_from_seed
from textforensics.verify import verify_case_file_combined

sys.path.insert(0, str(Path(__file__).parent))
from test_standalone_verify import build_bundle as sa_build_bundle  # noqa: E402
from test_standalone_verify import load_standalone  # noqa: E402

TEXT = (
    "The committee met on Tuesday to review the quarterly figures and "
    "discuss the outlook for the coming year. The chair opened the meeting "
    "with a summary of the previous session, and the members agreed to "
    "focus on three items: revenue, staffing, and the maintenance budget. "
    "Revenue grew modestly in the first quarter, driven by new contracts "
    "in the northern region. Staffing remains tight, and the hiring plan "
    "was approved with minor changes. The maintenance budget was reduced "
    "after a review of the supplier quotes. The meeting ended with a plan "
    "to reconvene in four weeks to review progress on each item."
)
SEED = bytes(range(32))
SIGNER = {"identity": "strmt7", "role": "sealer"}
PUBLIC_KEY = public_key_from_seed(SEED)

STANDALONE = load_standalone()


def sealed_case():
    return seal_case_file(build_forensic_bundle(TEXT).to_dict())


def reseal(case, *, allow_nan=False):
    out = copy.deepcopy(case)
    stripped = copy.deepcopy(out)
    stripped.pop("case_sha256", None)
    stripped.pop("created_at_utc", None)
    canonical = json.dumps(
        stripped,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=allow_nan,
    )
    out["case_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return out


def _other_overall(current):
    for state in ("strong", "mixed", "insufficient"):
        if state != current:
            return state
    raise AssertionError("unreachable")


def _dim(name, state="supported"):
    return {"dimension": name, "state": state, "reason": "synthetic"}


def _coverage(dimensions, *, stale_key=False):
    counts = {"supported": 0, "partial": 0, "unknown": 0, "out_of_scope": 0}
    if stale_key:
        counts["stale"] = 0
    for item in dimensions:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Corpus mutations (each takes a sealed case, returns a resealed case)
# ---------------------------------------------------------------------------


def _mut_raw_text(case):
    case["process"]["reviewer"] = {
        "identity": "x",
        "role": "y",
        "reasoning": "z",
        "agreed_with_tool": True,
        "raw_text": "CANARY raw source text",
    }
    return case


def _mut_empty_checklist(case):
    case["process"]["items"] = {}
    return case


def _mut_template_notice(case):
    case["process"]["template_notice"] = "altered notice"
    return case


def _mut_d1_removed(case):
    del case["process"]["items"]["D1"]
    return case


def _mut_d1_bad_status(case):
    case["process"]["items"]["D1"]["status"] = "banana"
    return case


def _mut_wrong_overall(case):
    tm = case["forensic_bundle"]["trust_map"]
    tm["overall"] = _other_overall(tm["overall"])
    return case


def _mut_one_dim_map(case):
    tm = case["forensic_bundle"]["trust_map"]
    tm["dimensions"] = [_dim("not-a-declared-dimension")]
    tm["overall"] = "strong"
    tm["coverage"] = _coverage(tm["dimensions"])
    return case


def _mut_one_dim_map_v3(case):
    tm = case["forensic_bundle"]["trust_map"]
    tm["schema"] = "textforensics.trust-map/v3"
    tm["dimensions"] = [_dim("not-a-declared-dimension")]
    tm["overall"] = "strong"
    tm["coverage"] = _coverage(tm["dimensions"], stale_key=True)
    case["manifest"]["schema_versions"]["trust_map"] = "textforensics.trust-map/v3"
    return case


def _mut_tool_name(case):
    case["tool"]["name"] = "EvilTool"
    return case


def _mut_manifest_calibration_ids(case):
    case["manifest"]["calibration_ids"] = ["tampered"]
    return case


def _mut_manifest_schema_versions(case):
    case["manifest"]["schema_versions"]["trust_map"] = "textforensics.trust-map/v9"
    return case


def _mut_bad_verdict(case):
    case["forensic_bundle"]["detector_results"][0]["verdict"] = "definitely_ai"
    return case


def _mut_nan_score(case):
    case["forensic_bundle"]["detector_results"][0]["score"] = math.nan
    return case


MUTANTS = [
    ("raw_text_in_reviewer", _mut_raw_text, False),
    ("empty_checklist", _mut_empty_checklist, False),
    ("altered_template_notice", _mut_template_notice, False),
    ("d1_removed", _mut_d1_removed, False),
    ("d1_bad_status", _mut_d1_bad_status, False),
    ("wrong_trust_map_overall", _mut_wrong_overall, False),
    ("one_dim_undeclared_map", _mut_one_dim_map, False),
    ("one_dim_undeclared_map_v3", _mut_one_dim_map_v3, False),
    ("tool_name_tampered", _mut_tool_name, False),
    ("manifest_calibration_ids_tampered", _mut_manifest_calibration_ids, False),
    ("manifest_schema_versions_tampered", _mut_manifest_schema_versions, False),
    ("bad_detector_verdict", _mut_bad_verdict, False),
    ("nan_detector_score", _mut_nan_score, False),
]


def _mutated(name):
    for label, fn, _ in MUTANTS:
        if label == name:
            return reseal(
                fn(copy.deepcopy(sealed_case())), allow_nan=(name == "nan_detector_score")
            )
    raise KeyError(name)


# ---------------------------------------------------------------------------
# Cross-product: installed / packed / standalone
# ---------------------------------------------------------------------------


class TestSharedAcceptanceCorpus:
    """Every corpus case: same verdict in all three entry points."""

    def test_clean_unsigned_control(self):
        case = sealed_case()
        assert verify_case_file_combined(case)["valid"] is True
        archive, record = pack_sealed_bundle(case)
        packed = verify_sealed_bundle(archive)
        assert packed["exit_code"] == 0, json.dumps(packed, indent=2)
        sa_archive, _, _ = sa_build_bundle(case_bytes=canonical_json_bytes(case), case=case)
        assert STANDALONE.verify_bundle_bytes(sa_archive)["exit_code"] == 0

    def test_clean_signed_control(self):
        case = sealed_case()
        assert verify_case_file_combined(case)["valid"] is True
        archive, record = pack_sealed_bundle(case, signing_seed=SEED, signer=SIGNER)
        packed = verify_sealed_bundle(archive, public_key=PUBLIC_KEY)
        assert packed["exit_code"] == 0, json.dumps(packed, indent=2)
        assert packed["standalone"]["signature"] == "verified"
        # Without the key the same bundle is incomplete (exit 2), not valid.
        assert verify_sealed_bundle(archive)["exit_code"] == 2
        sa_archive, _, _ = sa_build_bundle(case_bytes=canonical_json_bytes(case), case=case)
        assert STANDALONE.verify_bundle_bytes(sa_archive, public_key=PUBLIC_KEY)["exit_code"] == 0
        # The signed packed archive without a key is incomplete (exit 2).
        assert STANDALONE.verify_bundle_bytes(archive)["exit_code"] == 2

    @pytest.mark.parametrize("name,fn,_", MUTANTS, ids=[m[0] for m in MUTANTS])
    def test_mutant_rejected_installed(self, name, fn, _):
        case = _mutated(name)
        result = verify_case_file_combined(case)
        assert result["valid"] is False, (name, result["errors"])

    @pytest.mark.parametrize("name,fn,_", MUTANTS, ids=[m[0] for m in MUTANTS])
    def test_mutant_refused_by_packer(self, name, fn, _):
        case = _mutated(name)
        with pytest.raises((SealedBundleError, ValueError)):
            pack_sealed_bundle(case, signing_seed=SEED, signer=SIGNER)

    @pytest.mark.parametrize("name,fn,_", MUTANTS, ids=[m[0] for m in MUTANTS])
    def test_mutant_rejected_standalone(self, name, fn, _):
        case = _mutated(name)
        case_bytes = (
            _nan_case_bytes(case) if name == "nan_detector_score" else canonical_json_bytes(case)
        )
        sa_archive, _, _ = sa_build_bundle(case_bytes=case_bytes, case=case)
        report = STANDALONE.verify_bundle_bytes(sa_archive, public_key=PUBLIC_KEY)
        assert report["exit_code"] == 1, (name, json.dumps(report, indent=2))

    def test_mutant_rejected_standalone_no_install_subprocess(self, tmp_path):
        """The no-install path: the bundled verify.py run with no
        TextForensics on sys.path must exit 1 on a mutant bundle."""
        case = _mutated("wrong_trust_map_overall")
        sa_archive, _, _ = sa_build_bundle(case_bytes=canonical_json_bytes(case), case=case)
        bundle_path = tmp_path / "mutant.zip"
        bundle_path.write_bytes(sa_archive)
        verify_src = (
            Path(__file__).parent.parent / "src" / "textforensics" / "_standalone_verify.py"
        )
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": "", "SYSTEMROOT": "/nonexistent"}
        proc = subprocess.run(
            [sys.executable, str(verify_src), str(bundle_path)],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        assert proc.returncode == 1, proc.stdout + proc.stderr

    def test_clean_control_no_install_subprocess(self, tmp_path):
        case = sealed_case()
        sa_archive, _, _ = sa_build_bundle(case_bytes=canonical_json_bytes(case), case=case)
        bundle_path = tmp_path / "clean.zip"
        bundle_path.write_bytes(sa_archive)
        verify_src = (
            Path(__file__).parent.parent / "src" / "textforensics" / "_standalone_verify.py"
        )
        env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": "", "SYSTEMROOT": "/nonexistent"}
        proc = subprocess.run(
            [sys.executable, str(verify_src), str(bundle_path)],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


def _nan_case_bytes(case):
    """Canonical case bytes for a NaN-score case (allow_nan=True: the
    reseal hash was computed over the same spelling)."""
    return json.dumps(
        case, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=True
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# C05 — duplicate ZIP member names
# ---------------------------------------------------------------------------


def _dup_archive(*, wrong_name, first=True):
    """A real signed production bundle with a prepended/appended second
    copy of *wrong_name* carrying wrong content; the original manifest
    and signature are untouched."""
    case = sealed_case()
    archive, record = pack_sealed_bundle(case, signing_seed=SEED, signer=SIGNER)
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        entries = [(info.filename, zf.read(info.filename)) for info in zf.infolist()]
        comment = zf.comment
    wrong = b"wrong content that must never verify"
    if wrong_name == "case.json":
        wrong_case = copy.deepcopy(case)
        wrong_case["limitations"]["plain_language"]["human_fpr"] = "forged"
        wrong = canonical_json_bytes(wrong_case)
    elif wrong_name == "manifest.json":
        manifest = json.loads(dict(entries)["manifest.json"].decode("utf-8"))
        manifest["context"]["case_id"] = "0" * 64
        wrong = json.dumps(
            manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    buf = io.BytesIO()
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # deliberate duplicates
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:

            def _w(name, data):
                info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 0
                info.external_attr = 0o644 << 16
                zf.writestr(info, data)

            if first:
                _w(wrong_name, wrong)
            for name, data in sorted(entries):
                _w(name, data)
            if not first:
                _w(wrong_name, wrong)
            zf.comment = comment
    return buf.getvalue(), archive


class TestDuplicateMembers:
    @pytest.mark.parametrize("wrong_name", ["case.json", "manifest.json", "verify.py"])
    @pytest.mark.parametrize("first", [True, False])
    def test_duplicate_member_rejected_standalone(self, wrong_name, first):
        dup, original = _dup_archive(wrong_name=wrong_name, first=first)
        assert dup != original
        report = STANDALONE.verify_bundle_bytes(dup, public_key=PUBLIC_KEY)
        assert report["exit_code"] == 1, json.dumps(report, indent=2)
        assert report["signature"] != "verified" or any(
            c["id"] == "container_duplicate_entries" for c in report["checks"]
        )
        assert any(c["id"] == "container_duplicate_entries" for c in report["checks"]), json.dumps(
            report["checks"], indent=2
        )

    def test_duplicate_member_rejected_by_wrapper(self):
        dup, _ = _dup_archive(wrong_name="case.json", first=True)
        result = verify_sealed_bundle(dup, public_key=PUBLIC_KEY)
        assert result["exit_code"] == 1

    def test_case_insensitive_collision_rejected(self):
        """case.json + Case.json in one bundle: on a case-insensitive
        filesystem an extractor would collide them, so the bundle is
        rejected before any content is read."""
        case = sealed_case()
        archive, _ = pack_sealed_bundle(case)
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            entries = [(info.filename, zf.read(info.filename)) for info in zf.infolist()]
            comment = zf.comment
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:

            def _w(name, data):
                info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 0
                info.external_attr = 0o644 << 16
                zf.writestr(info, data)

            for name, data in sorted(entries):
                _w(name, data)
            _w("Case.json", b"collision")
            zf.comment = comment
        report = STANDALONE.verify_bundle_bytes(buf.getvalue())
        assert report["exit_code"] == 1
        assert any(c["id"] == "container_duplicate_entries" for c in report["checks"])

    def test_expected_archive_digest_catches_modification(self):
        """External digest pinning (the pre-existing mitigation) still
        catches a modified archive even if duplicate rejection did not
        exist: the pinned digest of the original does not match."""
        dup, original = _dup_archive(wrong_name="case.json", first=True)
        original_digest = hashlib.sha256(original).hexdigest()
        report = STANDALONE.verify_bundle_bytes(
            dup, expected_digest=original_digest, public_key=PUBLIC_KEY
        )
        assert report["exit_code"] == 1
        assert any(
            c["id"] == "seal_expected_digest" and c["status"] == "fail" for c in report["checks"]
        )
        # And the unmodified archive matches its own pinned digest.
        clean = STANDALONE.verify_bundle_bytes(
            original, expected_digest=original_digest, public_key=PUBLIC_KEY
        )
        assert clean["exit_code"] == 0


# ---------------------------------------------------------------------------
# C06 — seal-record cross-check must not read after rejection
# ---------------------------------------------------------------------------


class TestPreviousSignaturesMirror:
    """C02 contract §2.1 (Worker B): the standalone accepts a
    well-formed superseded-signature history, warns, and never treats
    a superseded signature as the current seal."""

    def _entry(self, **overrides):
        entry = {
            "algorithm": "ed25519",
            "key_fingerprint": "ab" * 32,
            "signer": {"identity": "strmt7", "role": "sealer"},
            "dsse": {
                "payloadType": "textforensics.case-signing/v2",
                "payload": "eA",
                "signatures": [],
            },
            "superseded_reason": "re-signed-after-custody-append",
            "superseded_at_utc": "2026-11-12T00:00:00Z",
        }
        entry.update(overrides)
        return entry

    def _report(self, previous):
        case = sealed_case()
        if previous is not None:
            case["seal"]["previous_signatures"] = previous
        case = reseal(case)
        archive, _, _ = sa_build_bundle(case=case, case_bytes=json.dumps(case).encode("utf-8"))
        return STANDALONE.verify_bundle_bytes(archive)

    def _check(self, report, check_id):
        return next(c for c in report["checks"] if c["id"] == check_id)

    def test_well_formed_history_warns_and_passes(self):
        report = self._report([self._entry()])
        assert report["exit_code"] == 0
        assert self._check(report, "seal_case_previous_signatures")["status"] == "pass"
        assert "prior_signature_superseded" in report["warnings"]

    def test_absent_field_is_silent(self):
        report = self._report(None)
        assert report["exit_code"] == 0
        assert not any(c["id"] == "seal_case_previous_signatures" for c in report["checks"])
        assert "prior_signature_superseded" not in report["warnings"]

    @pytest.mark.parametrize(
        "previous",
        [
            "not-a-list",
            [{"algorithm": "ed25519"}],  # missing five fields
            [{}],
            [
                {
                    "algorithm": "rsa",
                    "key_fingerprint": "ab" * 32,
                    "signer": {"identity": "x", "role": "y"},
                    "dsse": {},
                    "superseded_reason": "re-signed-after-custody-append",
                    "superseded_at_utc": "2026-11-12T00:00:00Z",
                }
            ],
            [
                {
                    "algorithm": "ed25519",
                    "key_fingerprint": "zz" * 32,
                    "signer": {"identity": "x", "role": "y"},
                    "dsse": {},
                    "superseded_reason": "re-signed-after-custody-append",
                    "superseded_at_utc": "2026-11-12T00:00:00Z",
                }
            ],
            [
                {
                    "algorithm": "ed25519",
                    "key_fingerprint": "ab" * 32,
                    "signer": {"identity": "", "role": "y"},
                    "dsse": {},
                    "superseded_reason": "re-signed-after-custody-append",
                    "superseded_at_utc": "2026-11-12T00:00:00Z",
                }
            ],
            [
                {
                    "algorithm": "ed25519",
                    "key_fingerprint": "ab" * 32,
                    "signer": {"identity": "x", "role": "y"},
                    "dsse": {},
                    "superseded_reason": "made-up-reason",
                    "superseded_at_utc": "2026-11-12T00:00:00Z",
                }
            ],
        ],
    )
    def test_malformed_history_fails(self, previous):
        report = self._report(previous)
        assert report["exit_code"] == 1
        assert self._check(report, "seal_case_previous_signatures")["status"] == "fail"


class TestSealRecordAfterRejection:
    def _bomb(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("case.json", b"A" * 1_048_576)
        return buf.getvalue()

    def test_zero_untrusted_reads_after_rejection(self, monkeypatch):
        """Spy: after the standalone verifier rejects the container,
        the wrapper must perform ZERO member reads (ZipFile.read/open
        or the capped reread helper)."""
        bomb = self._bomb()
        assert STANDALONE.verify_bundle_bytes(bomb)["exit_code"] == 1
        reads = []
        orig_open = zipfile.ZipFile.open
        orig_read = zipfile.ZipFile.read

        def spy_open(self, name, mode="r", pwd=None, **kw):
            reads.append(("open", str(name)))
            return orig_open(self, name, mode=mode, pwd=pwd, **kw)

        def spy_read(self, name, pwd=None):
            reads.append(("read", str(name)))
            return orig_read(self, name, pwd)

        monkeypatch.setattr(zipfile.ZipFile, "open", spy_open)
        monkeypatch.setattr(zipfile.ZipFile, "read", spy_read)
        import textforensics.sealed_bundle as sb

        capped_calls = []
        orig_capped = sb._read_capped

        def spy_capped(zf, name):
            capped_calls.append(name)
            return orig_capped(zf, name)

        monkeypatch.setattr(sb, "_read_capped", spy_capped)
        result = verify_sealed_bundle(bomb, seal_record={"schema": "x", "manifest": {}})
        assert result["exit_code"] == 1
        assert result["seal_record"]["status"] == "unavailable"
        assert result["seal_record"]["reason"] == "seal_failed"
        assert reads == [], reads
        assert capped_calls == [], capped_calls

    def test_seal_record_guards_use_tiny_limits(self, monkeypatch):
        """The wrapper's reread guards fire with tiny limits instead of
        hundreds of MiB: a valid bundle whose members exceed a patched
        10-byte per-entry cap must fail the cross-check, not read on."""
        import textforensics.sealed_bundle as sb

        case = sealed_case()
        archive, record = pack_sealed_bundle(case)
        monkeypatch.setattr(sb, "MAX_ENTRY_BYTES", 10)
        result = verify_sealed_bundle(archive, seal_record=record)
        assert result["exit_code"] == 1
        assert result["seal_record"]["errors"], result["seal_record"]
        monkeypatch.setattr(sb, "MAX_ENTRY_BYTES", 64 * 1024 * 1024)
        monkeypatch.setattr(sb, "MAX_ENTRIES", 1)
        result = verify_sealed_bundle(archive, seal_record=record)
        assert result["exit_code"] == 1
        assert result["seal_record"]["errors"]
