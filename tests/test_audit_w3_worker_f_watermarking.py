"""W3 Worker F (recovery) kill tests for watermarking (audit-w3-f).

Each test kills one or more proof survivors from the W3 re-proof
(hidden_files/audit-w3-f2-survivors-watermarking.json): the test
asserts the original behaviour on a distinguishing input, so the
mutant fails it. Distinguishing inputs are boundary values (signing
exactly at a validity bound, skew exactly at the tolerance, reserved
names at the range edges), reversed-order values for the ``!=`` ->
``<`` / ``>`` mutants, runtime-built distinct-but-equal strings for
the ``is`` / ``is not`` mutants, mocked ``os.name`` + syscall spies
for the platform branches, and exact file bytes for the serialiser
mutants. See hidden_files/audit-w3-worker-f.md §5 for the per-mutant
kill evidence (mutate_code re-proof) and §6 for the
proven-equivalent survivors (disjoint-set ``|`` -> ``^``, redundant
filename guards, subsumed length check, dead ``verified`` initial
value, and the unobservable ``missing_ok`` / ``maxsplit`` /
default-``365`` replacements).
"""

import base64
import hashlib
import json
import os
import stat
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pytest
from test_watermarking import (  # noqa: E402
    _handcraft_signature,
    _make_manager_and_signature,
    _public_key_with_bounds,
)

from textforensics.watermarking import (
    WatermarkError,
    WatermarkKeyPair,
    WatermarkManager,
    WatermarkSignature,
    _canonical_payload_hash,
    _is_valid_key_id,
)

WIDE_CREATED = "2020-01-01T00:00:00+00:00"
WIDE_EXPIRES = "2030-01-01T00:00:00+00:00"
SIGNING_TIME = "2026-01-01T00:00:00+00:00"


def _manager_with_key(tmp):
    """A manager with one key, its keypair and a wide-bounds public key."""
    manager = WatermarkManager(Path(tmp))
    manager.generate_key(key_id="test-key")
    keypair = manager.get_keypair("test-key")
    pk = _public_key_with_bounds(
        manager.get_public_key("test-key"),
        created_at=WIDE_CREATED,
        expires_at=WIDE_EXPIRES,
    )
    return manager, keypair, pk


def _both(manager, signature, pk, **expected):
    """Run both public verifiers; return (primary, manager) results."""
    from textforensics.watermarking import verify_watermark

    primary = verify_watermark(
        detector_id=expected.get("detector_id", "test/detector"),
        detector_version=expected.get("detector_version", "1.0"),
        text_sha256=expected.get("text_sha256", "a" * 64),
        score=expected.get("score", 0.2),
        verdict=expected.get("verdict", "human_like"),
        signature=signature,
        public_key=pk,
    )
    return primary, manager.verify_signature(signature, pk)


class TestWorkerFWatermarkingExpiryArithmetic:
    """Kill the WatermarkKeyPair.generate / generate_key arithmetic."""

    def test_generate_expires_at_exact_year(self):
        """Add / FloorDiv / NumberReplacer at [333,39/54/57/61/63]:
        the expiry year is exactly ``now.year + expires_days // 365
        + 1``. Every replacement changes the year for at least one
        of 365 / 728 / 730 (730 separates ``x << 1`` from ``x + 1``;
        728 separates ``// 364`` from ``// 365``)."""
        now = datetime.now(UTC)
        for expires_days in (365, 728, 730):
            keypair = WatermarkKeyPair.generate(expires_days=expires_days)
            parsed = datetime.fromisoformat(keypair.expires_at)
            assert parsed.year == now.year + expires_days // 365 + 1
            assert (parsed.month, parsed.day) == (now.month, now.day)

    def test_generate_default_expiry_year(self):
        """NumberReplacer [326,69] occ for ``365`` -> ``364`` (the
        default): 364 // 365 == 0, so the mutant expires a year
        early. (``365`` -> ``366`` is equivalent: 366 // 365 == 1.)"""
        now = datetime.now(UTC)
        keypair = WatermarkKeyPair.generate()
        assert datetime.fromisoformat(keypair.expires_at).year == now.year + 2

    def test_generate_key_default_expiry_year(self, tmp_path):
        """NumberReplacer [597,74] occ for ``365`` -> ``364`` (the
        generate_key default): same arithmetic through the manager."""
        now = datetime.now(UTC)
        manager = WatermarkManager(tmp_path)
        keypair = manager.generate_key()
        assert datetime.fromisoformat(keypair.expires_at).year == now.year + 2

    def test_generate_key_id_length(self):
        """NumberReplacer [338,46] ``hex[:12]`` -> ``[:13]`` /
        ``[:11]``: the generated ID is exactly ``wmk-`` + 12 hex
        chars (16 chars)."""
        keypair = WatermarkKeyPair.generate()
        assert len(keypair.key_id) == 16
        assert keypair.key_id.startswith("wmk-")
        assert all(c in "0123456789abcdef" for c in keypair.key_id[4:])


class TestWorkerFWatermarkingKeyIdBoundaries:
    """Kill the reserved-name range and split mutants."""

    def test_reserved_names_range_edges(self):
        """NumberReplacer [132,32/35] and [133,32/35] (``range(1,
        10)``): COM1/COM9/LPT1/LPT9 are reserved, COM0/COM10/
        LPT0/LPT10 are not. Each replacement moves one edge."""
        assert _is_valid_key_id("COM1") is False
        assert _is_valid_key_id("COM9") is False
        assert _is_valid_key_id("COM0") is True
        assert _is_valid_key_id("COM10") is True
        assert _is_valid_key_id("LPT1") is False
        assert _is_valid_key_id("LPT9") is False
        assert _is_valid_key_id("LPT0") is True
        assert _is_valid_key_id("LPT10") is True

    def test_split_maxsplit_zero(self):
        """NumberReplacer [197,29] occ for ``1`` -> ``0``:
        ``split(".", 0)`` never splits, so the whole dotted ID is
        checked against the reserved set and ``COM1.x`` passes. The
        original splits on the first dot and rejects it."""
        assert _is_valid_key_id("COM1.x") is False

    def test_split_index_one(self):
        """NumberReplacer [197,32] ``[0]`` -> ``[1]`` / ``[-1]``:
        the check must look at the segment BEFORE the first dot.
        ``x.COM1`` is valid; the mutants read the reserved second
        segment instead."""
        assert _is_valid_key_id("x.COM1") is True

    def test_is_valid_key_id_non_string(self):
        """ReplaceOrWithAnd [191,35]: a non-string ID must be
        rejected by the type guard. The mutant requires BOTH
        disjuncts, so it falls through to the regex and raises
        TypeError instead of returning False."""
        assert _is_valid_key_id(123) is False


class TestWorkerFWatermarkingValidityBoundaries:
    """Kill the C20 boundary comparisons and the envelope tolerance."""

    def test_signing_exactly_at_created_at(self, tmp_path):
        """ReplaceComparisonOperator_Lt_LtE [236,47]: signing
        exactly at created_at is inside the window. The mutant
        (``<=``) rejects it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        pk = _public_key_with_bounds(pk, created_at=SIGNING_TIME, expires_at=WIDE_EXPIRES)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        primary, mgr = _both(manager, sig, pk)
        assert primary is True
        assert mgr is True

    def test_signing_exactly_at_expires_at(self, tmp_path):
        """ReplaceComparisonOperator_Gt_GtE [238,47]: signing
        exactly at expires_at is inside the window. The mutant
        (``>=``) rejects it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        pk = _public_key_with_bounds(pk, created_at=WIDE_CREATED, expires_at=SIGNING_TIME)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        primary, mgr = _both(manager, sig, pk)
        assert primary is True
        assert mgr is True

    def test_envelope_skew_exactly_tolerance(self, tmp_path):
        """NumberReplacer [117,50] ``minutes=5`` -> ``4`` and
        ReplaceComparisonOperator_Gt_GtE [247,16]: a signed_at skew
        of exactly 300 s is within tolerance. The ``4``-minute
        mutant (240 s) and the ``>=`` mutant both reject it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, signed_at="2026-01-01T00:05:00+00:00"
        )
        primary, mgr = _both(manager, sig, pk)
        assert primary is True
        assert mgr is True

    def test_envelope_skew_beyond_tolerance(self, tmp_path):
        """NumberReplacer [117,50] ``minutes=5`` -> ``6``: a
        signed_at skew of 330 s exceeds the 5-minute tolerance.
        The ``6``-minute mutant (360 s) accepts it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, signed_at="2026-01-01T00:05:30+00:00"
        )
        primary, mgr = _both(manager, sig, pk)
        assert primary is False
        assert mgr is False

    def test_envelope_expires_earlier_than_trusted(self, tmp_path):
        """ReplaceComparisonOperator_Eq_LtE [251,55]: an envelope
        expires_at EARLIER than the trusted key's expires_at must
        fail (only equality agrees). The mutant (``<=``) accepts
        it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, expires_at="2027-01-01T00:00:00+00:00"
        )
        primary, mgr = _both(manager, sig, pk)
        assert primary is False
        assert mgr is False


class TestWorkerFWatermarkingValidateBranches:
    """Kill the _validate_watermark_signature failure branches."""

    def test_non_signature_object_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [266,15]: a non-WatermarkSignature
        must fail. The mutant returns True."""
        manager, _keypair, pk = _manager_with_key(tmp_path)
        assert manager.verify_signature("not-a-signature", pk) is False

    def test_non_public_key_object_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [268,15]: a non-WatermarkPublicKey
        must fail. The mutant returns True."""
        manager, signature, _pk = _make_manager_and_signature(tmp_path)
        assert manager.verify_signature(signature, "not-a-key") is False

    def test_unhashable_payload_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [277,15]: a payload whose canonical
        hash is None (``_canonical_payload_hash`` returns None for
        the unhashable set member) must fail. The mutant returns
        True at the ``recomputed is None`` guard and then crashes
        in ``hmac.compare_digest(None, ...)``. (The neighbouring
        [274,15] guard is covered by
        test_non_dict_payload_rejected, not by this test.)"""
        manager, signature, pk = _make_manager_and_signature(tmp_path)
        bad = replace(signature, payload={"x": {1, 2}})
        assert manager.verify_signature(bad, pk) is False

    def test_non_dict_payload_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [274,15]: a non-dict payload must
        fail closed. The payload is a genuine list with a valid
        Ed25519 signature over its canonical hash, so every check
        after the type guard passes — only the guard distinguishes
        the two. The mutant returns True at the guard and then
        crashes on ``payload.get("timestamp")`` downstream (the
        guard is load-bearing for the dict access in
        ``_check_key_validity_at_signing_time``), so the mutant
        raises instead of returning False. Only
        ``manager.verify_signature`` is used here:
        ``verify_watermark`` touches ``payload.get`` before the
        guard and raises on a non-dict payload even unmutated."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        payload = [1, 2]
        canonical = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
        payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        signature_bytes = keypair.sign(payload_hash.encode("utf-8"))
        sig = WatermarkSignature(
            key_id=keypair.key_id,
            signature=base64.b64encode(signature_bytes).decode("ascii"),
            signed_at=SIGNING_TIME,
            expires_at=WIDE_EXPIRES,
            payload_hash=payload_hash,
            payload=payload,
            algorithm="ed25519",
        )
        assert manager.verify_signature(sig, pk) is False

    def test_non_string_payload_hash_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [277,15]: a non-string payload_hash
        must fail. The mutant returns True."""
        manager, signature, pk = _make_manager_and_signature(tmp_path)
        bad = replace(signature, payload_hash=123)
        assert manager.verify_signature(bad, pk) is False

    def test_malformed_payload_hash_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [279,15]: a payload_hash that is not
        64 hex chars must fail. The mutant returns True."""
        manager, signature, pk = _make_manager_and_signature(tmp_path)
        bad = replace(signature, payload_hash="xyz")
        assert manager.verify_signature(bad, pk) is False

    def test_algorithm_distinct_object(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_IsNot [269,27]: the
        algorithm must be compared by VALUE. A runtime-built
        ``"ed25519"`` (a distinct object from the module constant)
        is equal, so the original proceeds and verifies; the mutant
        (``is not``) rejects it. The value is built with
        ``"".join`` — adjacent-literal ``+`` is constant-folded by
        CPython to the interned literal, which is the SAME object
        as the module constant (``"ed25519"`` is identifier-like)
        and would not distinguish the mutant."""
        from textforensics.watermarking import WATERMARK_ALGORITHM

        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        algorithm = "".join(["ed255", "19"])
        assert algorithm is not WATERMARK_ALGORITHM
        sig = replace(sig, algorithm=algorithm)
        primary, mgr = _both(manager, sig, pk)
        assert primary is True
        assert mgr is True

    def test_key_id_greater_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Lt [271,24]: a key_id
        GREATER than the trusted one must fail. The mutant (``<``)
        only fails on lesser IDs, so it proceeds and verifies."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        sig = replace(sig, key_id="zzz")
        primary, mgr = _both(manager, sig, pk)
        assert primary is False
        assert mgr is False

    def test_key_id_lesser_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Gt [271,24]: a key_id
        LESS than the trusted one must fail. The mutant (``>``)
        only fails on greater IDs, so it proceeds and verifies."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        sig = replace(sig, key_id="aaa")
        primary, mgr = _both(manager, sig, pk)
        assert primary is False
        assert mgr is False

    def test_key_id_distinct_object(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_IsNot [271,24]: the key
        ID must be compared by VALUE. A runtime-built ``"test-key"``
        is equal, so the original proceeds and verifies; the mutant
        (``is not``) rejects it. The value is built with
        ``"".join`` — the ``+`` form is constant-folded, and the
        two ``"test-key"`` literals in this module are deduplicated
        by the compiler to the SAME object, which would not
        distinguish the mutant."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        key_id = "".join(["test", "-key"])
        assert key_id is not pk.key_id
        sig = replace(sig, key_id=key_id)
        primary, mgr = _both(manager, sig, pk)
        assert primary is True
        assert mgr is True

    def test_whitespace_signature_encoding_rejected(self, tmp_path):
        """ReplaceTrueWithFalse [285,73]: base64 with ``validate``
        must reject embedded whitespace. The mutant
        (``validate=False``) decodes it and verifies."""
        manager, signature, pk = _make_manager_and_signature(tmp_path)
        raw = signature.signature
        bad = replace(signature, signature=raw[:10] + "\n" + raw[10:])
        assert manager.verify_signature(bad, pk) is False

    def test_whitespace_public_key_rejected(self, tmp_path):
        """ReplaceTrueWithFalse [399,59]: a public key whose base64
        carries whitespace must fail closed. The mutant
        (``validate=False``) decodes it and verifies."""
        _manager, keypair, pk = _manager_with_key(tmp_path)
        sig_bytes = keypair.sign(b"data")
        raw = pk.public_key
        bad_pk = replace(pk, public_key=raw[:10] + "\n" + raw[10:])
        assert bad_pk.verify(b"data", sig_bytes) is False

    def test_unknown_key_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [743,23]: a signature whose key is
        unknown to the manager must fail. The mutant returns True."""
        manager, keypair, _pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME, key_id="no-such-key")
        assert manager.verify_signature(sig) is False

    def test_explicit_public_key_accepted(self, tmp_path):
        """Regression test (kills no mutant on its own): a supplied
        public key must be used, not rejected. The [742,15] guard
        mutants live in the ``public_key is None`` lookup branch,
        which this test never enters — they are killed by
        test_manager_lookup_public_key_accepted."""
        manager, signature, pk = _make_manager_and_signature(tmp_path)
        assert manager.verify_signature(signature, pk) is True

    def test_manager_lookup_public_key_accepted(self, tmp_path):
        """ReplaceUnaryOperator_Delete_Not [742,15] and AddNot
        [742,15] (``if not pk``): with no public key supplied the
        manager must look the key up and verify. Both mutants turn
        the guard around (``if pk:``), so a found key returns False.
        (``AddNot`` inserts ``not`` before the first operand only,
        but here the condition is a single ``not pk``, so both
        mutants are ``if pk:``.) The signature is made by
        ``sign_detector_output`` (now), so it is inside the stored
        key's validity bounds — a handcrafted 2026-01-01 signature
        predates the key created now and fails even unmutated."""
        manager, signature, _pk = _make_manager_and_signature(tmp_path)
        assert manager.verify_signature(signature, None) is True


class TestWorkerFWatermarkingCanonicalHash:
    """Kill the canonical-payload-hash mutants."""

    def test_non_ascii_payload_hashes(self, tmp_path):
        """ReplaceFalseWithTrue [162,76]: the canonical hash must
        use ``ensure_ascii=False`` like the signer. A non-ASCII
        payload verifies under the original; the mutant
        (``ensure_ascii=True``) recomputes a different digest and
        rejects it."""
        manager, signature, pk = _make_manager_and_signature(tmp_path, metadata={"note": "héllo"})
        assert manager.verify_signature(signature, pk) is True

    def test_unhashable_payload_returns_none(self):
        """ExceptionReplacer [163,12] (``TypeError``): an
        unhashable payload must return None, not raise. The mutant
        replaces the caught type, so the TypeError propagates."""
        assert _canonical_payload_hash({"x": {1, 2}}) is None

    def test_circular_payload_returns_none(self):
        """ExceptionReplacer [163,23] (``ValueError``): a circular
        payload must return None, not raise. The mutant replaces
        the caught type, so the ValueError propagates."""
        payload: dict = {}
        payload["self"] = payload
        assert _canonical_payload_hash(payload) is None


class TestWorkerFWatermarkingSaveKey:
    """Kill the _save_key platform / serialiser / handler mutants."""

    def test_nt_branch_runs_chmod(self, tmp_path, monkeypatch):
        """AddNot [583,15] and Eq_NotEq / Eq_Lt / Eq_Gt [583,23]:
        with ``os.name == "nt"`` the NT branch must chmod the
        destination. The mutants skip the branch, so no chmod
        happens. (Mocking ``os.name`` to ``"nt"`` makes
        ``pathlib.Path`` construct ``WindowsPath``, so the manager
        is created first and the module's ``Path`` is pinned to
        ``PosixPath`` inside the mocked block.)"""
        from pathlib import PosixPath

        calls = []
        real_chmod = os.chmod
        manager = WatermarkManager(tmp_path)
        monkeypatch.setattr(os, "chmod", lambda p, m: calls.append((str(p), m)) or real_chmod(p, m))
        with (
            mock.patch.object(os, "name", "nt"),
            mock.patch("textforensics.watermarking.Path", PosixPath),
        ):
            keypair = manager.generate_key(key_id="nt-key")
        assert (str(tmp_path / "nt-key.key.json"), 0o600) in calls
        assert keypair.key_id == "nt-key"

    def test_nt_branch_lte_mock(self, tmp_path, monkeypatch):
        """Eq_LtE [583,23]: ``os.name`` below ``"nt"`` must not take
        the NT branch. The mutant (``<=``) takes it and chmods."""
        calls = []
        monkeypatch.setattr(os, "name", "n")
        monkeypatch.setattr(os, "chmod", lambda p, m: calls.append((str(p), m)))
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="lt-key")
        assert calls == []

    def test_nt_branch_gte_mock(self, tmp_path, monkeypatch):
        """Eq_GtE [583,23]: ``os.name`` above ``"nt"`` must not take
        the NT branch. The mutant (``>=``) takes it and chmods."""
        calls = []
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(os, "chmod", lambda p, m: calls.append((str(p), m)))
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="gt-key")
        assert calls == []

    def test_posix_branch_runs_fsync(self, tmp_path, monkeypatch):
        """AddNot [586,15] and Eq_NotEq / Eq_Lt / Eq_Gt [586,23]:
        with ``os.name == "posix"`` the POSIX branch must fsync
        the key directory (the temp-file fsync happens regardless,
        so the directory fd is identified via the os.open spy).
        The mutants skip the branch, so the directory is never
        fsynced."""
        opened = {}
        fsynced = []
        real_open = os.open
        real_fsync = os.fsync
        monkeypatch.setattr(os, "name", "posix")
        monkeypatch.setattr(
            os,
            "open",
            lambda p, *a, **k: opened.setdefault(str(p), real_open(p, *a, **k)),
        )
        monkeypatch.setattr(os, "fsync", lambda fd: fsynced.append(fd) or real_fsync(fd))
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="posix-key")
        dir_fd = opened.get(str(tmp_path))
        assert dir_fd is not None
        assert dir_fd in fsynced

    def test_posix_branch_gte_mock(self, tmp_path, monkeypatch):
        """Eq_GtE [586,23]: ``os.name`` above ``"posix"`` must not
        take the POSIX branch. The mutant (``>=``) takes it and
        fsyncs the directory."""
        opened = {}
        fsynced = []
        real_open = os.open
        real_fsync = os.fsync
        monkeypatch.setattr(os, "name", "posix2")
        monkeypatch.setattr(
            os,
            "open",
            lambda p, *a, **k: opened.setdefault(str(p), real_open(p, *a, **k)),
        )
        monkeypatch.setattr(os, "fsync", lambda fd: fsynced.append(fd) or real_fsync(fd))
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="gte-key")
        assert str(tmp_path) not in opened

    def test_posix_branch_lte_mock(self, tmp_path, monkeypatch):
        """Eq_LtE [586,23]: ``os.name`` below ``"posix"`` must not
        take the POSIX branch. The mutant (``<=``) takes it and
        fsyncs the directory."""
        opened = {}
        fsynced = []
        real_open = os.open
        real_fsync = os.fsync
        monkeypatch.setattr(os, "name", "pos")
        monkeypatch.setattr(
            os,
            "open",
            lambda p, *a, **k: opened.setdefault(str(p), real_open(p, *a, **k)),
        )
        monkeypatch.setattr(os, "fsync", lambda fd: fsynced.append(fd) or real_fsync(fd))
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="lte-key")
        assert str(tmp_path) not in opened

    def test_fchmod_is_called(self, tmp_path, monkeypatch):
        """AddNot [569,19] (``hasattr(os, "fchmod")``): the temp
        file must be chmodded before publishing. The mutant skips
        the call."""
        calls = []
        real_fchmod = os.fchmod
        monkeypatch.setattr(os, "fchmod", lambda fd, m: calls.append((fd, m)) or real_fchmod(fd, m))
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="fchmod-key")
        assert len(calls) == 1
        assert calls[0][1] == 0o600

    def test_saved_file_indent_two(self, tmp_path):
        """NumberReplacer [562,55] ``indent=2`` -> ``3`` / ``1``:
        the published key file is exactly the indent-2 dump plus a
        trailing newline."""
        manager = WatermarkManager(tmp_path)
        keypair = manager.generate_key(key_id="indent-key")
        content = (tmp_path / "indent-key.key.json").read_text(encoding="utf-8")
        expected = json.dumps(keypair.to_dict(), indent=2, ensure_ascii=False) + "\n"
        assert content == expected

    def test_saved_file_keeps_non_ascii(self, tmp_path):
        """ReplaceFalseWithTrue [562,71]: the published key file
        must keep non-ASCII metadata raw (``ensure_ascii=False``).
        The mutant escapes it."""
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="unicode-key")
        keypair = replace(keypair, metadata={"note": "héllo"})
        manager._save_key(keypair)
        content = (tmp_path / "unicode-key.key.json").read_text(encoding="utf-8")
        assert "héllo" in content
        assert "\\u00e9" not in content

    def test_nt_chmod_mode_0600(self, tmp_path, monkeypatch):
        """NumberReplacer [585,42] ``0o600`` -> ``0o601`` /
        ``0o599``: under the NT branch the destination must end up
        mode 0600 exactly. (See test_nt_branch_runs_chmod for why
        the manager is created before mocking ``os.name``.)"""
        from pathlib import PosixPath

        manager = WatermarkManager(tmp_path)
        with (
            mock.patch.object(os, "name", "nt"),
            mock.patch("textforensics.watermarking.Path", PosixPath),
        ):
            manager.generate_key(key_id="mode-key")
        mode = stat.S_IMODE((tmp_path / "mode-key.key.json").stat().st_mode)
        assert mode == 0o600

    def test_link_failure_is_watermark_error(self, tmp_path, monkeypatch):
        """ExceptionReplacer [581,19] (``FileExistsError``): a
        link-time collision must surface as WatermarkError, not
        leak FileExistsError. The mutant replaces the caught type,
        so the FileExistsError propagates."""
        monkeypatch.setattr(os, "link", lambda *a, **k: (_ for _ in ()).throw(FileExistsError("x")))
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="link-key")
        with pytest.raises(Exception) as excinfo:
            manager._save_key(keypair)
        assert type(excinfo.value).__name__ == "WatermarkError"

    def test_key_file_path_rejects_escape_greater(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Lt [542,28] and
        NotEq_Is [542,28] and NotEq_Lt [542,54] and NotEq_Is
        [542,54]: a key file that is a symlink escaping the store
        must be rejected. The planted link points at
        ``/zzz/zzz.key.json`` — parent ``/zzz`` is GREATER than the
        store and the name ``"zzz.key.json"`` is GREATER than
        ``"test-key.key.json"`` — so both ``<`` mutants (which only
        reject lesser parents/names) and both ``is`` mutants (the
        resolved parent/name are distinct objects from the base /
        expected name) fail to raise. The targets do not exist, so
        no write ever escapes the store: the mutants proceed to
        ``os.link`` and raise ``FileNotFoundError`` instead of
        ``WatermarkError``."""
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="test-key")
        (tmp_path / "test-key.key.json").symlink_to("/zzz/zzz.key.json")
        with pytest.raises(WatermarkError):
            manager._save_key(keypair)

    def test_key_file_path_rejects_escape_lesser(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Gt [542,28] and
        NotEq_Gt [542,54]: a key file that is a symlink escaping
        the store must be rejected. The planted link points at
        ``/aaa/aaa.key.json`` — parent ``/aaa`` is LESS than the
        store and the name ``"aaa.key.json"`` is LESS than
        ``"test-key.key.json"`` — so both ``>`` mutants (which only
        reject greater parents/names) fail to raise."""
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="test-key")
        (tmp_path / "test-key.key.json").symlink_to("/aaa/aaa.key.json")
        with pytest.raises(WatermarkError):
            manager._save_key(keypair)

    def test_key_file_path_rejects_escape_same_name(self, tmp_path):
        """ReplaceOrWithAnd [542,36]: a key file that is a symlink
        escaping the store must be rejected even when the name
        matches. The planted link points at
        ``/zzz/test-key.key.json`` — the parent differs but the name
        is the expected one — so the ``and`` mutant (which only
        rejects when BOTH disjuncts hold) fails to raise. This test
        also kills NotEq_Lt / NotEq_Is [542,28] (parent greater /
        distinct)."""
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="test-key")
        (tmp_path / "test-key.key.json").symlink_to("/zzz/test-key.key.json")
        with pytest.raises(WatermarkError):
            manager._save_key(keypair)

    def test_key_file_path_rejects_escape_lesser_same_name(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Gt [542,28]: a key file
        that is a symlink escaping the store must be rejected. The
        planted link points at ``/aaa/test-key.key.json`` — the
        parent is LESS than the store and the name MATCHES, so the
        ``>`` mutant (which only rejects greater parents) fails to
        raise AND the name disjunct cannot save it (it is False).
        (The ``/zzz`` test cannot kill this mutant: the parent is
        greater there, so the mutant raises via the parent disjunct
        exactly like the original — the two disjuncts are joined by
        ``or``, so a mutant on one is observable only when the other
        is False.)"""
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="test-key")
        (tmp_path / "test-key.key.json").symlink_to("/aaa/test-key.key.json")
        with pytest.raises(WatermarkError):
            manager._save_key(keypair)

    def test_key_file_path_rejects_escape_same_dir_greater_name(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Lt [542,54] and NotEq_Is
        [542,54]: a key file that is a symlink to a DIFFERENT name
        in the SAME directory must be rejected. The planted link
        points at the relative ``"zzz.key.json"`` — the parent IS
        the store and the name ``"zzz.key.json"`` is GREATER than
        ``"test-key.key.json"`` — so the ``<`` mutant (which only
        rejects lesser names) and the ``is`` mutant (distinct
        objects) fail to raise, and the parent disjunct cannot save
        them (it is False)."""
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="test-key")
        (tmp_path / "test-key.key.json").symlink_to("zzz.key.json")
        with pytest.raises(WatermarkError):
            manager._save_key(keypair)

    def test_key_file_path_rejects_escape_same_dir_lesser_name(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Gt [542,54]: a key file
        that is a symlink to a DIFFERENT name in the SAME directory
        must be rejected. The planted link points at the relative
        ``"aaa.key.json"`` — the parent IS the store and the name
        ``"aaa.key.json"`` is LESS than ``"test-key.key.json"`` —
        so the ``>`` mutant (which only rejects greater names)
        fails to raise, and the parent disjunct cannot save it."""
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="test-key")
        (tmp_path / "test-key.key.json").symlink_to("aaa.key.json")
        with pytest.raises(WatermarkError):
            manager._save_key(keypair)

    def test_fchmod_failure_closes_fd(self, tmp_path, monkeypatch):
        """ExceptionReplacer [571,19] (``BaseException``): if
        fchmod raises, the temp fd must be closed before the error
        propagates. The mutant replaces the caught type, so the fd
        leaks."""
        seen = []

        def _raising_fchmod(fd, mode):
            seen.append(fd)
            raise OSError("fchmod boom")

        monkeypatch.setattr(os, "fchmod", _raising_fchmod)
        manager = WatermarkManager(tmp_path)
        keypair = WatermarkKeyPair.generate(key_id="fd-key")
        with pytest.raises(OSError, match="fchmod boom"):
            manager._save_key(keypair)
        assert len(seen) == 1
        # The fd is closed: closing it again must fail.
        with pytest.raises(OSError):
            os.close(seen[0])


class TestWorkerFWatermarkingManager:
    """Kill the generate_key / revoke / _load_keys mutants."""

    def test_generate_key_without_key_dir(self):
        """ReplaceComparisonOperator_IsNot_Is [607,24] and AddNot
        [607,11]: without a key directory, generate_key must still
        return a keypair (in-memory only). The mutants take the
        ``_key_file_path`` branch and raise WatermarkError."""
        manager = WatermarkManager(None)
        keypair = manager.generate_key(key_id="mem-key")
        assert keypair.key_id == "mem-key"
        assert manager.get_keypair("mem-key") is keypair

    def test_load_keys_without_key_dir(self):
        """ReplaceOrWithAnd [509,28]: a manager without a key
        directory loads nothing. The mutant (``and``) evaluates
        ``None.exists()`` and raises AttributeError."""
        manager = WatermarkManager(None)
        assert manager._keys == {}

    def test_revoke_removes_file(self, tmp_path):
        """AddNot [643,19]: revoking a key must unlink its file.
        The mutant skips the unlink, so the file survives and a
        fresh manager reloads the key."""
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="revoke-key")
        assert manager.revoke_key("revoke-key") is True
        assert not (tmp_path / "revoke-key.key.json").exists()
        assert WatermarkManager(tmp_path).get_keypair("revoke-key") is None

    def test_revoke_removes_broken_symlink(self, tmp_path):
        """AddNot [643,19]: revoking a key whose file is a BROKEN
        symlink must still unlink it. ``AddNot`` inserts ``not``
        before the first operand only, so the mutant is ``if not
        key_file.is_symlink() or key_file.exists():`` — for a
        regular file that is still True (the unlink happens), but
        for a broken symlink (``is_symlink`` True, ``exists``
        False) it is False and the link survives. The plain
        revoke test cannot distinguish the mutant; only the broken
        symlink can."""
        manager = WatermarkManager(tmp_path)
        manager.generate_key(key_id="revoke-key")
        key_file = tmp_path / "revoke-key.key.json"
        key_file.unlink()
        key_file.symlink_to(tmp_path / "no-such-target.key.json")
        assert key_file.is_symlink() and not key_file.exists()
        assert manager.revoke_key("revoke-key") is True
        assert not key_file.is_symlink()
        assert not os.path.lexists(key_file)

    def _load_with_bad_first(self, tmp_path, bad_name, bad_content, monkeypatch):
        """Build a store with a good key, then load it with a bad
        file ordered FIRST via a patched glob: the bad file must be
        skipped and the good key loaded."""
        mgr0 = WatermarkManager(tmp_path)
        mgr0.generate_key(key_id="good-key")
        good = tmp_path / "good-key.key.json"
        bad = tmp_path / bad_name
        if isinstance(bad_content, str) and bad_content == "SYMLINK":
            bad.symlink_to(good)
        else:
            bad.write_text(bad_content, encoding="utf-8")
        real_glob = Path.glob
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [bad, good])
        mgr = WatermarkManager(tmp_path)
        assert mgr.get_keypair("good-key") is not None
        monkeypatch.setattr(Path, "glob", real_glob)

    def test_load_keys_skips_symlink(self, tmp_path, monkeypatch):
        """ReplaceContinueWithBreak [516,16]: a symlinked key file
        must be skipped, not end the load. The mutant breaks, so
        the good key is never loaded."""
        self._load_with_bad_first(tmp_path, "aaa.key.json", "SYMLINK", monkeypatch)

    def test_load_keys_skips_directory(self, tmp_path):
        """ReplaceOrWithAnd [515,37]: a directory named
        ``*.key.json`` must be skipped, not end the load. The
        mutant (``or`` -> ``and``) only skips a file that is BOTH a
        symlink AND not a file; a plain directory passes the guard
        and ``read_text`` raises ``IsADirectoryError``, which the
        load handler does not catch, so manager construction
        crashes. (A symlink-to-file does NOT distinguish the
        mutant: the filename-mismatch check skips it either way.)"""
        mgr0 = WatermarkManager(tmp_path)
        mgr0.generate_key(key_id="good-key")
        (tmp_path / "zzz.key.json").mkdir()
        mgr = WatermarkManager(tmp_path)
        assert mgr.get_keypair("good-key") is not None

    def test_load_keys_skips_corrupt_json(self, tmp_path, monkeypatch):
        """ReplaceContinueWithBreak [522,16]: a corrupt key file
        must be skipped, not end the load."""
        self._load_with_bad_first(tmp_path, "aaa.key.json", "{invalid json", monkeypatch)

    def test_load_keys_skips_invalid_key_id(self, tmp_path, monkeypatch):
        """ReplaceContinueWithBreak [524,16]: a file whose embedded
        ID is not allowlisted must be skipped, not end the load."""
        mgr0 = WatermarkManager(tmp_path)
        keypair = mgr0.generate_key(key_id="good-key")
        good = tmp_path / "good-key.key.json"
        bad = tmp_path / "aaa.key.json"
        data = keypair.to_dict()
        data["key_id"] = "COM1"
        bad.write_text(json.dumps(data), encoding="utf-8")
        real_glob = Path.glob
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [bad, good])
        mgr = WatermarkManager(tmp_path)
        assert mgr.get_keypair("good-key") is not None
        monkeypatch.setattr(Path, "glob", real_glob)

    def test_load_keys_skips_filename_mismatch(self, tmp_path, monkeypatch):
        """ReplaceContinueWithBreak [526,16] and
        ReplaceComparisonOperator_NotEq_Lt / NotEq_Is [525,44]: a
        file whose embedded ID does not match its filename must be
        skipped, not end the load — and the mismatched ID must NOT
        be loaded. The ``<`` mutant only skips when the expected
        name is lesser (``"other-key.key.json"`` is GREATER than
        ``"aaa.key.json"``, so it loads ``"other-key"``); the ``is``
        mutant never skips (the f-string and the filename are
        distinct objects). The ``>`` mutant is killed by
        test_load_keys_skips_filename_mismatch_lesser."""
        mgr0 = WatermarkManager(tmp_path)
        keypair = mgr0.generate_key(key_id="good-key")
        good = tmp_path / "good-key.key.json"
        bad = tmp_path / "aaa.key.json"
        data = keypair.to_dict()
        data["key_id"] = "other-key"
        bad.write_text(json.dumps(data), encoding="utf-8")
        real_glob = Path.glob
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [bad, good])
        mgr = WatermarkManager(tmp_path)
        assert mgr.get_keypair("good-key") is not None
        assert mgr.get_keypair("other-key") is None
        monkeypatch.setattr(Path, "glob", real_glob)

    def test_load_keys_skips_filename_mismatch_lesser(self, tmp_path, monkeypatch):
        """ReplaceComparisonOperator_NotEq_Gt [525,44]: a file whose
        embedded ID is lexicographically LESS than its filename
        must still be skipped. The ``>`` mutant only skips when the
        expected name is greater (``"aaa.key.json"`` is LESS than
        ``"zzz.key.json"``, so it loads ``"aaa"``)."""
        mgr0 = WatermarkManager(tmp_path)
        keypair = mgr0.generate_key(key_id="good-key")
        good = tmp_path / "good-key.key.json"
        bad = tmp_path / "zzz.key.json"
        data = keypair.to_dict()
        data["key_id"] = "aaa"
        bad.write_text(json.dumps(data), encoding="utf-8")
        real_glob = Path.glob
        monkeypatch.setattr(Path, "glob", lambda self, pattern: [bad, good])
        mgr = WatermarkManager(tmp_path)
        assert mgr.get_keypair("good-key") is not None
        assert mgr.get_keypair("aaa") is None
        monkeypatch.setattr(Path, "glob", real_glob)


class TestWorkerFWatermarkingVerifyFields:
    """Kill the verify_watermark expected-field mutants."""

    def test_detector_id_greater_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Lt [795,34]: a payload
        detector_id GREATER than expected must fail. The mutant
        (``<``) only fails on lesser IDs, so it proceeds and
        verifies. (The ``>`` mutant at the same position is killed
        by test_detector_id_lesser_mismatch.)"""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair,
            timestamp=SIGNING_TIME,
            payload_overrides={"detector_id": "zzz"},
        )
        primary, mgr = _both(manager, sig, pk)
        assert primary is False
        assert mgr is True  # manager.verify_signature does not bind expected fields

    def test_detector_id_lesser_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Gt [795,34]: a payload
        detector_id LESS than expected must fail. The mutant
        (``>``) only fails on greater IDs, so it proceeds and
        verifies."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair,
            timestamp=SIGNING_TIME,
            payload_overrides={"detector_id": "aaa"},
        )
        primary, mgr = _both(manager, sig, pk)
        assert primary is False
        assert mgr is True  # manager.verify_signature does not bind expected fields

    def test_detector_id_distinct_object(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_IsNot [795,34]: the
        detector_id must be compared by VALUE. A runtime-built
        equal ID verifies; the mutant (``is not``) rejects it. The
        value is built with ``"".join`` — the ``+`` form is
        constant-folded to the same object as the expected literal
        in this module and would not distinguish the mutant."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair,
            timestamp=SIGNING_TIME,
            payload_overrides={"detector_id": "".join(["test", "/detector"])},
        )
        primary, mgr = _both(manager, sig, pk)
        assert primary is True
        assert mgr is True

    def test_detector_version_greater_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Lt [797,39]: a payload
        version GREATER than expected must fail. The mutant (``<``)
        only fails on lesser versions, so it proceeds and verifies."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, payload_overrides={"detector_version": "9.9"}
        )
        primary, _mgr = _both(manager, sig, pk)
        assert primary is False

    def test_detector_version_lesser_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Gt [797,39]: a payload
        version LESS than expected must fail. The mutant (``>``)
        only fails on greater versions, so it proceeds and verifies."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, payload_overrides={"detector_version": "0.1"}
        )
        primary, _mgr = _both(manager, sig, pk)
        assert primary is False

    def test_detector_version_distinct_object(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_IsNot [797,39]: the
        version must be compared by VALUE. A runtime-built equal
        version verifies; the mutant (``is not``) rejects it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair,
            timestamp=SIGNING_TIME,
            payload_overrides={"detector_version": "1" + ".0"},
        )
        primary, _mgr = _both(manager, sig, pk)
        assert primary is True

    def test_text_sha256_greater_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Lt [799,34]: a payload
        hash GREATER than expected must fail. The mutant (``<``)
        only fails on lesser hashes, so it proceeds and verifies."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, payload_overrides={"text_sha256": "f" * 64}
        )
        primary, _mgr = _both(manager, sig, pk)
        assert primary is False

    def test_score_lesser_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_Gt [801,28]: a payload
        score LESS than expected must fail. The mutant (``>``) only
        fails on greater scores, so it proceeds and verifies."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, payload_overrides={"score": 0.1}
        )
        primary, _mgr = _both(manager, sig, pk, score=0.2)
        assert primary is False

    def test_score_distinct_object(self, tmp_path):
        """ReplaceComparisonOperator_NotEq_IsNot [801,28]: the score
        must be compared by VALUE. A runtime-built equal float
        verifies; the mutant (``is not``) rejects it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        primary, _mgr = _both(manager, sig, pk, score=0.1 + 0.1)
        assert primary is True

    def test_verdict_greater_mismatch(self, tmp_path):
        """ReplaceComparisonOperator_Eq_GtE [803,34]: a payload
        verdict GREATER than expected must fail. The mutant
        (``>=``) accepts it."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair, timestamp=SIGNING_TIME, payload_overrides={"verdict": "zebra"}
        )
        primary, _mgr = _both(manager, sig, pk)
        assert primary is False

    def test_verdict_distinct_object(self, tmp_path):
        """ReplaceComparisonOperator_Eq_Is [803,34]: the verdict
        must be compared by VALUE. A runtime-built equal verdict
        verifies; the mutant (``is``) rejects it. The value is
        built with ``"".join`` — the ``+`` form is constant-folded
        to the interned literal, which is the SAME object as the
        expected literal (``"human_like"`` is identifier-like) and
        would not distinguish the mutant."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(
            keypair,
            timestamp=SIGNING_TIME,
            payload_overrides={"verdict": "".join(["human", "_like"])},
        )
        primary, _mgr = _both(manager, sig, pk)
        assert primary is True

    def test_wrong_score_rejected(self, tmp_path):
        """ReplaceFalseWithTrue [798,15]: a mismatched expected
        score must fail. The mutant returns True."""
        manager, keypair, pk = _manager_with_key(tmp_path)
        sig = _handcraft_signature(keypair, timestamp=SIGNING_TIME)
        primary, _mgr = _both(manager, sig, pk, score=0.9)
        assert primary is False
