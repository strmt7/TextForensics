"""Tests for the wave-1 dataset loaders (transport, specs, cache).

No network is used here: every HTTP call is mocked. Live downloads are
covered by the smoke tests in the measurement script, which are skipped
without network/cache.
"""

import datetime
import http.client
import http.server
import io
import ipaddress
import json
import os
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from textforensics.datasets import (
    DETECTRL_X_BYTES,
    DETECTRL_X_FILE,
    DETECTRL_X_SHA256,
    DETECTRL_X_URL,
    LABEL_HUMAN,
    LABEL_MACHINE,
    DatasetFetchError,
    DatasetLicenceError,
    DatasetsServerClient,
    DownloadError,
    NormalizedRow,
    _map_detectrl,
    _map_m4,
    _map_m4gt_bench,
    _NoDowngradeRedirectHandler,
    _SplitTimeoutHTTPHandler,
    _SplitTimeoutHTTPSHandler,
    cache_path,
    default_cache_dir,
    detectrl_x_raw_path,
    download_detectrl_x,
    download_large_file,
    fetch_sample,
    fetch_strided_sample,
    get_spec,
    iter_detectrl_x_rows,
    manifest_path,
    map_row,
    read_sample_cache,
    require_licence,
    sample_detectrl_x_rows,
    sample_offsets,
    verify_detectrl_x_file,
    write_sample_cache,
)


def _fake_response(payload: dict) -> mock.MagicMock:
    body = io.BytesIO(json.dumps(payload).encode("utf-8"))
    response = mock.MagicMock()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    response.read.return_value = body.read()
    return response


def _row(text: str, label: int | None, dataset: str = "mage") -> NormalizedRow:
    return NormalizedRow(
        text=text,
        label=label,
        dataset=dataset,
        config="default",
        split="train",
        source_id="r0",
        regime="raw",
        meta={},
    )


class SpecTests(unittest.TestCase):
    def test_known_keys(self) -> None:
        for key in (
            "raid",
            "mage",
            "beemo",
            "mixset",
            "opai_bench",
            "ghostwriter",
            "detectrl_x",
            "detectrl",
            "m4",
            "m4gt_bench",
        ):
            self.assertEqual(get_spec(key).key, key)

    def test_unknown_key_raises(self) -> None:
        with self.assertRaises(KeyError):
            get_spec("no_such_dataset")

    def test_label_convention_constants(self) -> None:
        self.assertEqual(LABEL_MACHINE, 1)
        self.assertEqual(LABEL_HUMAN, 0)

    def test_beemo_licence_verified(self) -> None:
        spec = get_spec("beemo")
        self.assertEqual(spec.licence_status, "verified")
        self.assertIn("CC-BY-NC-4.0", spec.licence or "")
        require_licence(spec)  # must not raise

    def test_verified_licences(self) -> None:
        # Resolved 2026-11-06 from live sources (see
        # hidden_files/phase3-datasets-licences.md).
        self.assertEqual(get_spec("raid").licence, "MIT")
        self.assertIn("Apache-2.0", get_spec("mage").licence or "")
        self.assertIn("CC BY 4.0", get_spec("mage").licence or "")
        self.assertEqual(get_spec("opai_bench").licence, "Apache-2.0")
        for key in ("raid", "mage", "opai_bench"):
            require_licence(get_spec(key))  # must not raise

    def test_ghostwriter_per_domain_licences(self) -> None:
        # Verified 2026-11-07 from the live HF card (lines 340-468);
        # there is no `license:` tag in the HF API record, so the card
        # text is the only licence source. Two domains are NC and the
        # blog corpus is non-commercial-research-only.
        spec = get_spec("ghostwriter")
        self.assertEqual(spec.licence_status, "verified")
        require_licence(spec)  # must not raise
        licences = spec.domain_licences
        assert licences is not None
        self.assertEqual(len(licences), 8)
        self.assertEqual(licences["cnn_news"], "Apache-2.0")
        self.assertEqual(licences["euro_court_cases"], "CC-BY-NC-SA 4.0")
        self.assertEqual(licences["student_essays"], "CC-BY-NC-SA 4.0")
        self.assertIn("non-commercial research", licences["blog_authorship_corpus"])
        self.assertEqual(licences["gutenberg"], "CC0")
        for domain in licences:
            self.assertIn(domain, spec.licence or "")
        self.assertIn("non-commercial research evaluation", spec.licence_note)
        self.assertIn("no redistribution", spec.licence_note)

    def test_detectrl_x_licence_conflict_recorded_verbatim(self) -> None:
        # Three-way conflict verified live 2026-11-07 (see the spec's
        # licence_note): GitHub README Apache-2.0 + NC restriction, HF
        # MIT, ACL 2026 paper NC restriction. All three strings are
        # recorded verbatim; the strictest reading governs.
        spec = get_spec("detectrl_x")
        self.assertEqual(spec.licence_status, "verified")
        require_licence(spec)  # must not raise
        licence = spec.licence or ""
        self.assertIn("Apache License 2.0", licence)
        self.assertIn("MIT", licence)
        self.assertIn("noncommercial academic research purposes", licence)
        self.assertIn("non-commercial academic research only", licence)
        note = spec.licence_note
        self.assertIn("licensed under the Apache License 2.0", note)
        self.assertIn("strictly restricted to non-commercial academic research purposes", note)
        self.assertIn("strictly restricted to noncommercial academic research purposes", note)
        self.assertIn("No redistribution of raw text, ever", note)
        self.assertIn("local cache only, no redistribution", note)
        self.assertEqual(spec.hf_id, "WUJUNCHAO/DetectRL-X")
        self.assertEqual(spec.splits, (("binary", "train"), ("binary", "test")))

    def test_wave1_specs_have_no_domain_licences(self) -> None:
        # The optional field defaults to None so wave-1 specs are untouched.
        for key in ("raid", "mage", "beemo", "mixset", "opai_bench"):
            self.assertIsNone(get_spec(key).domain_licences)

    def test_unresolved_licences_block_fetch(self) -> None:
        # MixSet has no licence on any source checked 2026-11-06; the
        # gate stays closed until the authors clarify.
        with self.assertRaises(DatasetLicenceError):
            require_licence(get_spec("mixset"))

    def test_detectrl_licence_unresolved(self) -> None:
        # No dataset licence exists anywhere checked 2026-11-07:
        # GitHub API record "license":null for NLP2CT/DetectRL and
        # for the parent fork junchaoIU/DetectRL, no LICENSE file,
        # no README statement; the FAU reprocessed version is also
        # "license":null with no LICENSE file. The gate stays closed.
        spec = get_spec("detectrl")
        self.assertIsNone(spec.licence)
        self.assertEqual(spec.licence_status, "unresolved")
        with self.assertRaises(DatasetLicenceError):
            require_licence(spec)
        note = spec.licence_note
        self.assertIn('"license":null', note)
        self.assertIn("junchaoIU/DetectRL", note)
        self.assertIn("No LICENSE file", note)
        self.assertIn("philipp-ding", note)
        self.assertIn("licence statement from the authors", note)
        # The verified route and the paper-only count are recorded in
        # the notes, with the row counts explicitly NOT verified.
        self.assertIn("git clone https://github.com/NLP2CT/DetectRL.git", spec.notes)
        self.assertIn("235,200", spec.notes)
        self.assertIn("NOT verified", spec.notes)
        self.assertIn("98.5%", spec.notes)
        self.assertIn("benchmark construction.py", spec.notes)
        # No loader splits are mapped until a live row is inspected.
        self.assertEqual(spec.configs, ())
        self.assertEqual(spec.splits, ())

    def test_m4_licence_unresolved(self) -> None:
        # No single dataset licence exists anywhere checked
        # 2026-11-07: GitHub API record "license":null, no LICENSE
        # file, no README statement. Per-source licences in paper
        # Table 1 do not add up to a dataset licence, and two sources
        # are NC. The gate stays closed.
        spec = get_spec("m4")
        self.assertIsNone(spec.licence)
        self.assertEqual(spec.licence_status, "unresolved")
        with self.assertRaises(DatasetLicenceError):
            require_licence(spec)
        note = spec.licence_note
        self.assertIn('"license":null', note)
        self.assertIn("no LICENSE file", note)
        self.assertIn("CC BY-SA-3.0", note)
        self.assertIn("CC BY-NC-SA-4.0", note)
        self.assertIn("Two sources are NC", note)
        self.assertIn("licence statement from the authors", note)
        # The verified route and the count contradiction are recorded
        # in the notes, with no figure quoted as the size.
        self.assertIn("git clone https://github.com/mbzuai-nlp/M4.git", spec.notes)
        self.assertIn("147,895", spec.notes)
        self.assertIn("122K", spec.notes)
        self.assertIn("245K", spec.notes)
        self.assertIn("CONTRADICTION", spec.notes)
        self.assertIn("NO `*gpt4*` file exists", spec.notes)
        self.assertIn("human_text", spec.notes)
        self.assertIn("machine_text", spec.notes)
        self.assertIn("download_large_file", spec.notes)
        self.assertIn("curl", spec.notes)
        # No train/test split is defined; no loader splits are mapped
        # until a live row is inspected.
        self.assertEqual(spec.configs, ())
        self.assertEqual(spec.splits, ())

    def test_m4gt_bench_licence_unresolved(self) -> None:
        # No single dataset licence exists anywhere checked
        # 2026-11-07: GitHub API record "license":null, no LICENSE
        # file, no README statement. Per-source licences in paper
        # Table 2 do not add up to a dataset licence, and three
        # sources are NC. The gate stays closed.
        spec = get_spec("m4gt_bench")
        self.assertIsNone(spec.licence)
        self.assertEqual(spec.licence_status, "unresolved")
        with self.assertRaises(DatasetLicenceError):
            require_licence(spec)
        note = spec.licence_note
        self.assertIn('"license":null', note)
        self.assertIn("no LICENSE file", note)
        self.assertIn("CC BY-SA-3.0", note)
        self.assertIn("CC BY-NC-SA-4.0", note)
        self.assertIn("Three sources are NC", note)
        self.assertIn("licence statement from the authors", note)
        # The verified Drive route and the scope-qualified counts are
        # recorded in the notes; Drive row counts are NOT verifiable
        # without downloading.
        self.assertIn("1xC-n5hHiXmaCLmA0q3p8Cbyd7Dk0dpDE", spec.notes)
        self.assertIn("SubtaskA_multilingual.jsonl", spec.notes)
        self.assertIn("subtaskC_train_dev.jsonl", spec.notes)
        self.assertIn("138,465", spec.notes)
        self.assertIn("217,909", spec.notes)
        self.assertIn("281k", spec.notes)
        self.assertIn("NOT verifiable without downloading", spec.notes)
        self.assertIn("U4 spine", spec.notes)
        self.assertIn("per-task, never pooled", spec.notes)
        self.assertIn("download_large_file", spec.notes)
        self.assertIn("curl", spec.notes)
        # Task structure is recorded in the notes; no loader splits
        # are mapped until a live row is inspected.
        self.assertEqual(spec.configs, ())
        self.assertEqual(spec.splits, ())


class CacheDirTests(unittest.TestCase):
    def test_env_override(self) -> None:
        with mock.patch.dict(os.environ, {"TEXTFORENSICS_DATASETS_DIR": "/tmp/ds-test"}):
            self.assertEqual(default_cache_dir(), Path("/tmp/ds-test"))

    def test_default_is_outside_repo(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TEXTFORENSICS_DATASETS_DIR", None)
            os.environ.pop("XDG_CACHE_HOME", None)
            path = default_cache_dir()
        self.assertIn(".cache", path.parts)
        self.assertNotIn("TextForensics-rewrite", path.parts)

    def test_cache_paths(self) -> None:
        root = Path("/tmp/ds-cache")
        self.assertEqual(
            cache_path("mage", "default", "train", cache_dir=root),
            root / "mage" / "default" / "train.jsonl",
        )
        self.assertEqual(
            manifest_path("mage", "default", "train", cache_dir=root),
            root / "mage" / "default" / "train.manifest.json",
        )


class ClientTests(unittest.TestCase):
    def test_rows_parses_payload(self) -> None:
        payload = {"rows": [{"row_idx": 0, "row": {"text": "a", "label": 1}}]}
        with mock.patch(
            "textforensics.datasets._guarded_urlopen", return_value=_fake_response(payload)
        ):
            client = DatasetsServerClient(retries=0)
            self.assertEqual(
                client.rows("yaful/MAGE", "default", "train"), [{"text": "a", "label": 1}]
            )

    def test_rows_length_limit(self) -> None:
        client = DatasetsServerClient(retries=0)
        with self.assertRaises(ValueError):
            client.rows("yaful/MAGE", "default", "train", length=101)

    def test_splits_and_size(self) -> None:
        splits_payload = {
            "splits": [{"dataset": "yaful/MAGE", "config": "default", "split": "train"}]
        }
        size_payload = {"size": {"dataset": {"dataset": "yaful/MAGE", "num_rows": 436606}}}
        with mock.patch(
            "textforensics.datasets._guarded_urlopen", return_value=_fake_response(splits_payload)
        ):
            self.assertEqual(
                DatasetsServerClient(retries=0).splits("yaful/MAGE"), splits_payload["splits"]
            )
        with mock.patch(
            "textforensics.datasets._guarded_urlopen", return_value=_fake_response(size_payload)
        ):
            self.assertEqual(
                DatasetsServerClient(retries=0).size("yaful/MAGE")["dataset"]["num_rows"], 436606
            )

    def test_retries_then_raises(self) -> None:
        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen", side_effect=urllib.error.URLError("down")
            ) as urlopen,
            self.assertRaises(DatasetFetchError),
        ):
            DatasetsServerClient(retries=2, timeout_s=1)._get_json("/splits", {"dataset": "x"})
        self.assertEqual(urlopen.call_count, 3)

    def test_remote_disconnect_is_retried(self) -> None:
        # RemoteDisconnected escapes urlopen raw (not wrapped in
        # URLError); a single transient proxy reset must not kill a
        # long strided fetch. Regression test for the RAID n=600 run.
        import http.client

        calls = {"n": 0}

        def _flaky(*args: object, **kwargs: object) -> mock.MagicMock:
            calls["n"] += 1
            if calls["n"] < 3:
                raise http.client.RemoteDisconnected("Remote end closed connection")
            return _fake_response({"rows": [{"row": {"a": 1}}]})

        with mock.patch("textforensics.datasets._guarded_urlopen", side_effect=_flaky):
            payload = DatasetsServerClient(retries=3, timeout_s=1)._get_json(
                "/rows", {"dataset": "x"}
            )
        self.assertEqual(payload, {"rows": [{"row": {"a": 1}}]})
        self.assertEqual(calls["n"], 3)

    def test_refuses_plain_http_base_url(self) -> None:
        # B310 fix: the client must not fetch over plain http (the
        # default is a constant https URL; no caller passes a custom
        # base_url in production). Fails at construction, no network.
        with self.assertRaises(DownloadError) as ctx:
            DatasetsServerClient("http://example.invalid")
        self.assertIn("refuses", str(ctx.exception))

    def test_refuses_file_base_url(self) -> None:
        # urllib would honour file:// — a scheme the API client must
        # never speak.
        with self.assertRaises(DownloadError):
            DatasetsServerClient("file:///tmp/datasets-server")

    def test_accepts_loopback_http_base_url(self) -> None:
        # Local fixtures (a datasets-server stub on loopback) stay usable.
        client = DatasetsServerClient("http://127.0.0.1:9")
        self.assertEqual(client.base_url, "http://127.0.0.1:9")


class DownloadTests(unittest.TestCase):
    """Resumable large-file downloader (wave-2 shared infrastructure).

    No network: urlopen is mocked. A live smoke test (small real file)
    is run by hand, not in the suite.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dest = Path(self._tmp.name) / "file.bin"
        self.sleep_patch = mock.patch("textforensics.datasets.time.sleep")
        self.sleep_patch.start()
        self.addCleanup(self.sleep_patch.stop)

    def _fake_download_response(self, data: bytes, *, status: int = 200):
        body = io.BytesIO(data)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = False
        response.status = status
        response.read.side_effect = lambda n=-1: body.read(n)
        return response

    def test_fresh_download_verifies_hash_and_renames(self) -> None:
        import hashlib

        data = b"hello world, resumable download"
        expected = hashlib.sha256(data).hexdigest()
        with mock.patch(
            "textforensics.datasets._guarded_urlopen",
            return_value=self._fake_download_response(data),
        ):
            result = download_large_file(
                "https://example.invalid/file.bin", self.dest, expected_sha256=expected
            )
        self.assertEqual(result, self.dest)
        self.assertEqual(self.dest.read_bytes(), data)
        self.assertFalse(Path(str(self.dest) + ".part").exists())

    def test_hash_mismatch_raises_and_leaves_no_valid_file(self) -> None:
        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                return_value=self._fake_download_response(b"corrupt"),
            ),
            self.assertRaises(DownloadError),
        ):
            download_large_file(
                "https://example.invalid/file.bin",
                self.dest,
                expected_sha256="0" * 64,
            )
        self.assertFalse(self.dest.exists())
        self.assertTrue(Path(str(self.dest) + ".part").exists())

    def test_resume_uses_range_and_appends(self) -> None:

        part = Path(str(self.dest) + ".part")
        part.write_bytes(b"hello ")
        seen: dict[str, str] = {}

        def _urlopen(request, **kwargs):
            seen["range"] = request.get_header("Range")
            return self._fake_download_response(b"world", status=206)

        with mock.patch("textforensics.datasets._guarded_urlopen", side_effect=_urlopen):
            download_large_file("https://example.invalid/file.bin", self.dest)
        self.assertEqual(seen["range"], "bytes=6-")
        self.assertEqual(self.dest.read_bytes(), b"hello world")

    def test_server_ignoring_range_restarts_from_zero(self) -> None:
        part = Path(str(self.dest) + ".part")
        part.write_bytes(b"stale partial")
        with mock.patch(
            "textforensics.datasets._guarded_urlopen",
            return_value=self._fake_download_response(b"full file", status=200),
        ):
            download_large_file("https://example.invalid/file.bin", self.dest)
        self.assertEqual(self.dest.read_bytes(), b"full file")

    def test_transient_disconnect_is_retried_then_resumed(self) -> None:
        import http.client

        calls = {"n": 0}

        def _flaky(request, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise http.client.RemoteDisconnected("Remote end closed connection")
            return self._fake_download_response(b"data")

        with mock.patch("textforensics.datasets._guarded_urlopen", side_effect=_flaky):
            download_large_file("https://example.invalid/file.bin", self.dest, retries=2)
        self.assertEqual(self.dest.read_bytes(), b"data")
        self.assertEqual(calls["n"], 2)

    def test_404_fails_immediately_without_retry(self) -> None:
        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=urllib.error.HTTPError(
                    "https://example.invalid/missing", 404, "Not Found", {}, None
                ),
            ) as urlopen,
            self.assertRaises(DownloadError),
        ):
            download_large_file("https://example.invalid/missing", self.dest, retries=3)
        self.assertEqual(urlopen.call_count, 1)
        self.assertFalse(self.dest.exists())

    def test_already_downloaded_file_is_not_refetched(self) -> None:
        import hashlib

        data = b"already here"
        self.dest.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        with mock.patch("textforensics.datasets._guarded_urlopen") as urlopen:
            result = download_large_file(
                "https://example.invalid/file.bin", self.dest, expected_sha256=expected
            )
        urlopen.assert_not_called()
        self.assertEqual(result, self.dest)

    def test_expected_byte_count_mismatch_raises(self) -> None:
        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                return_value=self._fake_download_response(b"short"),
            ),
            self.assertRaises(DownloadError),
        ):
            download_large_file("https://example.invalid/file.bin", self.dest, expected_bytes=100)
        self.assertFalse(self.dest.exists())

    def test_truncated_body_is_retried_not_renamed(self) -> None:
        # Server declares 100 bytes but closes after 5: the
        # Content-Length check must retry instead of renaming a short file.
        def _truncated(request: urllib.request.Request, **kwargs: object):
            response = self._fake_download_response(b"short")
            response.getheader = lambda name, default=None: (
                "100" if name == "Content-Length" else default
            )
            return response

        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen", side_effect=_truncated
            ) as urlopen,
            self.assertRaises(DownloadError),
        ):
            download_large_file(
                "https://example.invalid/file.bin",
                self.dest,
                retries=1,
                use_curl_fallback=False,
            )
        self.assertEqual(urlopen.call_count, 2)
        self.assertFalse(self.dest.exists())
        self.assertTrue(Path(str(self.dest) + ".part").exists())

    def test_guarded_urlopen_receives_stall_budget_when_budgets_equal(self) -> None:
        # Equal connect/stall budgets use the guarded plain opener with
        # the stall budget (the urlopen call it replaced).
        with mock.patch(
            "textforensics.datasets._guarded_urlopen",
            return_value=self._fake_download_response(b"data"),
        ) as urlopen:
            download_large_file("https://example.invalid/file.bin", self.dest)
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 30)

        dest2 = Path(self._tmp.name) / "file2.bin"
        with mock.patch(
            "textforensics.datasets._guarded_urlopen",
            return_value=self._fake_download_response(b"data"),
        ) as urlopen:
            download_large_file(
                "https://example.invalid/file.bin",
                dest2,
                stall_timeout_s=300,
                connect_timeout_s=300,
            )
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 300)

    def test_split_timeouts_use_custom_opener(self) -> None:
        fake_opener = mock.MagicMock()
        fake_opener.open.return_value = self._fake_download_response(b"data")
        with mock.patch("urllib.request.build_opener", return_value=fake_opener) as build_opener:
            download_large_file(
                "https://example.invalid/file.bin",
                self.dest,
                stall_timeout_s=300,
                connect_timeout_s=30,
            )
        handlers = build_opener.call_args.args
        self.assertEqual(len(handlers), 3)
        self.assertIsInstance(handlers[0], _SplitTimeoutHTTPHandler)
        self.assertIsInstance(handlers[1], _SplitTimeoutHTTPSHandler)
        self.assertIsInstance(handlers[2], _NoDowngradeRedirectHandler)
        self.assertEqual(handlers[0]._stall_timeout_s, 300)
        self.assertEqual(handlers[1]._stall_timeout_s, 300)
        self.assertEqual(fake_opener.open.call_args.kwargs["timeout"], 30)
        self.assertEqual(self.dest.read_bytes(), b"data")

    def test_backoff_jitter_within_cap_and_growing(self) -> None:
        sleeps: list[float] = []
        bounds: list[tuple[float, float]] = []

        def _uniform(lo: float, hi: float) -> float:
            bounds.append((lo, hi))
            return hi  # worst case: the cap itself

        with (
            mock.patch("textforensics.datasets.random.uniform", side_effect=_uniform),
            mock.patch("textforensics.datasets.time.sleep", side_effect=sleeps.append),
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=http.client.RemoteDisconnected("Remote end closed connection"),
            ),
            self.assertRaises(DownloadError),
        ):
            download_large_file(
                "https://example.invalid/file.bin",
                self.dest,
                retries=8,
                use_curl_fallback=False,
            )
        # 8 sleeps (attempts 0..7); the bound grows 2, 4, 8, 16, 32
        # then caps at 60.
        self.assertEqual(
            bounds,
            [(0, 2.0), (0, 4.0), (0, 8.0), (0, 16.0), (0, 32.0), (0, 60.0), (0, 60.0), (0, 60.0)],
        )
        self.assertEqual(sleeps, [2.0, 4.0, 8.0, 16.0, 32.0, 60.0, 60.0, 60.0])
        for value in sleeps:
            self.assertGreaterEqual(value, 0)
            self.assertLessEqual(value, 60.0)

    def test_curl_fallback_argv_exactness(self) -> None:
        part = Path(str(self.dest) + ".part")
        seen: dict[str, object] = {}

        def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            part.write_bytes(b"via curl")
            return subprocess.CompletedProcess(argv, 0)

        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=http.client.RemoteDisconnected("Remote end closed connection"),
            ),
            mock.patch("textforensics.datasets.shutil.which", return_value="/usr/bin/curl"),
            mock.patch("textforensics.datasets.subprocess.run", side_effect=_run),
        ):
            download_large_file("https://example.invalid/file.bin", self.dest, retries=0)
        argv = seen["argv"]
        assert isinstance(argv, list)
        self.assertEqual(argv[0], "/usr/bin/curl")
        for flag in (
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--connect-timeout",
            "30",
            "--max-time",
            "3600",
            "--speed-limit",
            "1024",
            "--speed-time",
            "120",
            "--retry",
            "3",
            "--retry-delay",
            "5",
            "--continue-at",
            "-",
        ):
            self.assertIn(flag, argv)
        self.assertNotIn("--retry-all-errors", argv)
        self.assertEqual(argv[argv.index("--proto") + 1], "=https")
        self.assertEqual(argv[argv.index("--proto-redir") + 1], "=https")
        self.assertEqual(argv[argv.index("-o") + 1], str(part))
        self.assertEqual(argv[-2], "--")
        self.assertEqual(argv[-1], "https://example.invalid/file.bin")
        kwargs = seen["kwargs"]
        assert isinstance(kwargs, dict)
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(self.dest.read_bytes(), b"via curl")

    def test_curl_exit_33_restarts_from_zero(self) -> None:
        part = Path(str(self.dest) + ".part")
        part.write_bytes(b"stale partial")
        calls: list[list[str]] = []
        part_existed_on_second_call: list[bool] = []

        def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            calls.append(list(argv))
            if len(calls) == 1:
                return subprocess.CompletedProcess(argv, 33)
            part_existed_on_second_call.append(part.exists())
            part.write_bytes(b"full file")
            return subprocess.CompletedProcess(argv, 0)

        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=http.client.RemoteDisconnected("Remote end closed connection"),
            ),
            mock.patch("textforensics.datasets.shutil.which", return_value="/usr/bin/curl"),
            mock.patch("textforensics.datasets.subprocess.run", side_effect=_run),
        ):
            download_large_file("https://example.invalid/file.bin", self.dest, retries=0)
        self.assertEqual(len(calls), 2)
        self.assertIn("--continue-at", calls[0])
        self.assertNotIn("--continue-at", calls[1])
        self.assertEqual(part_existed_on_second_call, [False])
        self.assertEqual(self.dest.read_bytes(), b"full file")

    def test_curl_absent_raises_download_error_with_urllib_context(self) -> None:
        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=http.client.RemoteDisconnected("Remote end closed connection"),
            ),
            mock.patch("textforensics.datasets.shutil.which", return_value=None),
            self.assertRaises(DownloadError) as ctx,
        ):
            download_large_file("https://example.invalid/file.bin", self.dest, retries=0)
        self.assertIn("curl", str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, http.client.RemoteDisconnected)
        self.assertFalse(self.dest.exists())

    def test_curl_failure_raises_and_leaves_part(self) -> None:
        part = Path(str(self.dest) + ".part")
        part.write_bytes(b"partial")
        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=http.client.RemoteDisconnected("Remote end closed connection"),
            ),
            mock.patch("textforensics.datasets.shutil.which", return_value="/usr/bin/curl"),
            mock.patch(
                "textforensics.datasets.subprocess.run",
                return_value=subprocess.CompletedProcess([], 22),
            ) as run,
            self.assertRaises(DownloadError) as ctx,
        ):
            download_large_file("https://example.invalid/file.bin", self.dest, retries=0)
        self.assertIn("22", str(ctx.exception))
        self.assertEqual(run.call_count, 1)
        self.assertFalse(self.dest.exists())
        self.assertTrue(part.exists())
        self.assertEqual(part.read_bytes(), b"partial")

    def test_curl_refuses_non_loopback_http(self) -> None:
        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=http.client.RemoteDisconnected("Remote end closed connection"),
            ),
            mock.patch("textforensics.datasets.shutil.which", return_value="/usr/bin/curl"),
            mock.patch("textforensics.datasets.subprocess.run") as run,
            self.assertRaises(DownloadError) as ctx,
        ):
            download_large_file("http://example.invalid/file.bin", self.dest, retries=0)
        self.assertIn("refuses", str(ctx.exception))
        run.assert_not_called()

    def test_force_curl_skips_urllib(self) -> None:
        part = Path(str(self.dest) + ".part")

        def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            part.write_bytes(b"forced curl")
            return subprocess.CompletedProcess(argv, 0)

        with (
            mock.patch("textforensics.datasets._guarded_urlopen") as urlopen,
            mock.patch("textforensics.datasets.shutil.which", return_value="/usr/bin/curl"),
            mock.patch("textforensics.datasets.subprocess.run", side_effect=_run),
        ):
            download_large_file("https://example.invalid/file.bin", self.dest, force_curl=True)
        urlopen.assert_not_called()
        self.assertEqual(self.dest.read_bytes(), b"forced curl")

    def test_limit_bytes_fetches_prefix_only(self) -> None:
        seen: dict[str, str | None] = {}

        def _urlopen(request: urllib.request.Request, **kwargs: object):
            seen["range"] = request.get_header("Range")
            return self._fake_download_response(b"0123456789" * 10)

        with mock.patch("textforensics.datasets._guarded_urlopen", side_effect=_urlopen):
            download_large_file(
                "https://example.invalid/file.bin",
                self.dest,
                limit_bytes=10,
                expected_bytes=100,  # full-file checks are skipped for a prefix
            )
        self.assertEqual(seen["range"], "bytes=0-9")
        self.assertEqual(self.dest.read_bytes(), b"0123456789")

    def test_curl_prefix_probe_argv(self) -> None:
        part = Path(str(self.dest) + ".part")
        seen: dict[str, object] = {}

        def _run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            seen["argv"] = argv
            part.write_bytes(b"0123456789")
            return subprocess.CompletedProcess(argv, 0)

        with (
            mock.patch(
                "textforensics.datasets._guarded_urlopen",
                side_effect=http.client.RemoteDisconnected("Remote end closed connection"),
            ),
            mock.patch("textforensics.datasets.shutil.which", return_value="/usr/bin/curl"),
            mock.patch("textforensics.datasets.subprocess.run", side_effect=_run),
        ):
            download_large_file(
                "https://example.invalid/file.bin", self.dest, retries=0, limit_bytes=10
            )
        argv = seen["argv"]
        assert isinstance(argv, list)
        self.assertEqual(argv[argv.index("--range") + 1], "0-9")
        self.assertEqual(argv[argv.index("--max-filesize") + 1], "10")
        self.assertNotIn("--continue-at", argv)
        self.assertEqual(self.dest.read_bytes(), b"0123456789")


class DownloadUrlValidationTests(unittest.TestCase):
    """B310 fix: download_large_file refuses non-https URLs up front.

    No network is used: the scheme check runs before any fetch, so a
    refused URL must raise without urlopen ever being called.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dest = Path(self._tmp.name) / "file.bin"

    def test_refuses_plain_http_url(self) -> None:
        with (
            mock.patch("textforensics.datasets._guarded_urlopen") as urlopen,
            self.assertRaises(DownloadError) as ctx,
        ):
            download_large_file("http://example.invalid/file.bin", self.dest, retries=0)
        self.assertIn("refuses", str(ctx.exception))
        urlopen.assert_not_called()
        self.assertFalse(self.dest.exists())

    def test_refuses_file_url(self) -> None:
        # urllib would read a local file into the download — the
        # file-exfiltration shape B310 exists to catch.
        with (
            mock.patch("textforensics.datasets._guarded_urlopen") as urlopen,
            self.assertRaises(DownloadError),
        ):
            download_large_file("file:///etc/passwd", self.dest, retries=0)
        urlopen.assert_not_called()

    def test_refuses_ftp_url(self) -> None:
        with (
            mock.patch("textforensics.datasets._guarded_urlopen") as urlopen,
            self.assertRaises(DownloadError),
        ):
            download_large_file("ftp://example.invalid/file.bin", self.dest, retries=0)
        urlopen.assert_not_called()


def _write_localhost_cert(directory: str) -> tuple[str, str]:
    """Self-signed localhost cert (test fixture, generated in-process).

    ``cryptography`` is a declared dependency; no key material is
    committed and the cert lives one day. Lets the redirect tests run
    a real TLS loopback server, so an https→http downgrade is
    exercised end to end instead of only at the handler unit level.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(directory, "localhost.crt")
    key_path = os.path.join(directory, "localhost.key")
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_path).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Loopback fixture serving payloads or absolute-URL redirects.

    Per-server routing lives on the server instance: ``payloads``
    maps a path to bytes, ``redirects`` maps a path to the absolute
    ``Location`` URL, and ``requests_seen`` records every path in
    receipt order, so a test can prove a refused redirect was never
    followed (no request to the target, no bytes written).
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        path = urllib.parse.urlparse(self.path).path
        self.server.requests_seen.append(path)
        target = self.server.redirects.get(path)
        if target is not None:
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        payload = self.server.payloads.get(path)
        if payload is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _start_redirect_server(
    *, tls: tuple[str, str] | None
) -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    server.daemon_threads = True
    server.payloads = {}
    server.redirects = {}
    server.requests_seen = []
    if tls is not None:
        cert_path, key_path = tls
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class RedirectGuardTests(unittest.TestCase):
    """No-downgrade redirect guard (urllib redirect residual).

    No egress: one plain and two TLS loopback servers serve a small
    payload behind redirects. The client trusts the self-signed test
    cert only because the class temporarily installs
    ``ssl._create_unverified_context`` as the default HTTPS context —
    loopback-only test scaffolding, restored in tearDownClass, never
    production behaviour.
    """

    PAYLOAD = b"redirect-guard payload"

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cert = _write_localhost_cert(cls._tmp.name)
        cls._plain, cls._plain_thread = _start_redirect_server(tls=None)
        cls._tls_a, cls._tls_a_thread = _start_redirect_server(tls=cert)
        cls._tls_b, cls._tls_b_thread = _start_redirect_server(tls=cert)
        cls._orig_default_context = ssl._create_default_https_context
        ssl._create_default_https_context = ssl._create_unverified_context

    @classmethod
    def tearDownClass(cls) -> None:
        ssl._create_default_https_context = cls._orig_default_context
        for server, thread in (
            (cls._plain, cls._plain_thread),
            (cls._tls_a, cls._tls_a_thread),
            (cls._tls_b, cls._tls_b_thread),
        ):
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
        cls._tmp.cleanup()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dest = Path(self._tmp.name) / "file.bin"
        for server in (self._plain, self._tls_a, self._tls_b):
            server.payloads.clear()
            server.redirects.clear()
            server.requests_seen.clear()
        self.plain_url = f"http://127.0.0.1:{self._plain.server_address[1]}"
        self.tls_a_url = f"https://127.0.0.1:{self._tls_a.server_address[1]}"
        self.tls_b_url = f"https://127.0.0.1:{self._tls_b.server_address[1]}"
        self._plain.payloads["/payload"] = self.PAYLOAD
        self._tls_b.payloads["/payload"] = self.PAYLOAD

    def test_https_to_http_redirect_is_refused(self) -> None:
        self._tls_a.redirects["/start"] = f"{self.plain_url}/payload"
        with self.assertRaises(DownloadError) as ctx:
            download_large_file(
                f"{self.tls_a_url}/start", self.dest, retries=0, use_curl_fallback=False
            )
        self.assertIn("refuses", str(ctx.exception))
        self.assertFalse(self.dest.exists())
        self.assertFalse(Path(str(self.dest) + ".part").exists())
        # No HTTP request was ever made to the downgrade target.
        self.assertEqual(self._plain.requests_seen, [])
        self.assertEqual(self._tls_a.requests_seen, ["/start"])

    def test_https_to_https_redirect_succeeds(self) -> None:
        self._tls_a.redirects["/start"] = f"{self.tls_b_url}/payload"
        result = download_large_file(f"{self.tls_a_url}/start", self.dest)
        self.assertEqual(result, self.dest)
        self.assertEqual(self.dest.read_bytes(), self.PAYLOAD)
        self.assertEqual(self._tls_a.requests_seen, ["/start"])
        self.assertEqual(self._tls_b.requests_seen, ["/payload"])

    def test_http_loopback_to_http_loopback_redirect_succeeds(self) -> None:
        self._plain.redirects["/start"] = f"{self.plain_url}/payload"
        result = download_large_file(f"{self.plain_url}/start", self.dest)
        self.assertEqual(result, self.dest)
        self.assertEqual(self.dest.read_bytes(), self.PAYLOAD)
        self.assertEqual(self._plain.requests_seen, ["/start", "/payload"])

    def test_http_loopback_to_non_loopback_http_redirect_is_refused(self) -> None:
        self._plain.redirects["/start"] = "http://example.invalid/payload"
        with self.assertRaises(DownloadError) as ctx:
            download_large_file(
                f"{self.plain_url}/start", self.dest, retries=0, use_curl_fallback=False
            )
        self.assertIn("refuses", str(ctx.exception))
        self.assertFalse(self.dest.exists())
        self.assertFalse(Path(str(self.dest) + ".part").exists())
        # The origin saw exactly the one initial request: the redirect
        # was never followed (no DNS, no request to example.invalid).
        self.assertEqual(self._plain.requests_seen, ["/start"])

    def test_downgrade_refused_on_split_timeout_path(self) -> None:
        # Same downgrade, but through _split_timeout_opener (unequal
        # connect/stall budgets) instead of the plain path.
        self._tls_a.redirects["/start"] = f"{self.plain_url}/payload"
        with self.assertRaises(DownloadError) as ctx:
            download_large_file(
                f"{self.tls_a_url}/start",
                self.dest,
                stall_timeout_s=5,
                connect_timeout_s=30,
                retries=0,
                use_curl_fallback=False,
            )
        self.assertIn("refuses", str(ctx.exception))
        self.assertEqual(self._plain.requests_seen, [])

    def test_redirect_handler_refuses_downgrade(self) -> None:
        handler = _NoDowngradeRedirectHandler()
        request = urllib.request.Request("https://example.invalid/start")
        with self.assertRaises(DownloadError) as ctx:
            handler.redirect_request(
                request, None, 302, "Found", {}, "http://example.invalid/payload"
            )
        self.assertIn("refuses", str(ctx.exception))

    def test_redirect_handler_refuses_downgrade_to_loopback(self) -> None:
        # The case that caught the first implementation: a downgrade
        # is refused even when the http target is loopback (the
        # target alone would pass the scheme policy).
        handler = _NoDowngradeRedirectHandler()
        request = urllib.request.Request("https://example.invalid/start")
        with self.assertRaises(DownloadError) as ctx:
            handler.redirect_request(request, None, 302, "Found", {}, "http://127.0.0.1:9/payload")
        self.assertIn("refuses", str(ctx.exception))

    def test_redirect_handler_refuses_non_http_scheme(self) -> None:
        handler = _NoDowngradeRedirectHandler()
        request = urllib.request.Request("https://example.invalid/start")
        with self.assertRaises(DownloadError):
            handler.redirect_request(request, None, 302, "Found", {}, "file:///etc/passwd")

    def test_redirect_handler_allows_same_scheme(self) -> None:
        handler = _NoDowngradeRedirectHandler()
        https_request = urllib.request.Request("https://example.invalid/start")
        new = handler.redirect_request(
            https_request, None, 302, "Found", {}, "https://example.invalid/other"
        )
        assert new is not None
        self.assertEqual(new.full_url, "https://example.invalid/other")
        http_request = urllib.request.Request("http://127.0.0.1:9/start")
        new = handler.redirect_request(
            http_request, None, 302, "Found", {}, "http://127.0.0.1:9/other"
        )
        assert new is not None
        self.assertEqual(new.full_url, "http://127.0.0.1:9/other")

    def test_client_get_json_follows_loopback_redirect(self) -> None:
        self._plain.payloads["/splits-real"] = json.dumps({"splits": []}).encode("utf-8")
        self._plain.redirects["/splits"] = f"{self.plain_url}/splits-real"
        client = DatasetsServerClient(self.plain_url, retries=0)
        self.assertEqual(client.splits("x"), [])
        self.assertEqual(self._plain.requests_seen, ["/splits", "/splits-real"])

    def test_client_get_json_refuses_redirect_off_loopback(self) -> None:
        self._plain.redirects["/splits"] = "http://example.invalid/splits"
        client = DatasetsServerClient(self.plain_url, retries=0)
        with self.assertRaises(DownloadError) as ctx:
            client.splits("x")
        self.assertIn("refuses", str(ctx.exception))
        self.assertEqual(self._plain.requests_seen, ["/splits"])


class _StallHandler(http.server.BaseHTTPRequestHandler):
    """Range-capable fixture server with scripted faults.

    Class attributes configure the fault for the next test:
    ``delay_s`` (header delay), ``trickle_s`` (seconds between 10-byte
    body chunks), ``drop_after`` (body bytes sent before the connection
    is dropped mid-body, once). ``requests_seen`` counts GETs.
    """

    protocol_version = "HTTP/1.1"
    body = b"0123456789" * 10  # 100 bytes
    delay_s = 0.0
    trickle_s = 0.0
    drop_after: int | None = None
    requests_seen = 0
    _dropped = False

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler name
        type(self).requests_seen += 1
        time.sleep(type(self).delay_s)
        range_header = self.headers.get("Range")
        start = 0
        status = 200
        if range_header and range_header.startswith("bytes="):
            try:
                start = int(range_header[6:].split("-")[0])
            except ValueError:
                start = 0
            status = 206
        payload = type(self).body[start:]
        if type(self).drop_after is not None and not type(self)._dropped:
            type(self)._dropped = True
            self._send(status, start, payload, payload[: type(self).drop_after])
            self.close_connection = True
            return
        self._send(status, start, payload, payload)

    def _send(self, status: int, start: int, payload: bytes, chunk: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        if status == 206:
            self.send_header(
                "Content-Range",
                f"bytes {start}-{len(type(self).body) - 1}/{len(type(self).body)}",
            )
        self.end_headers()
        if type(self).trickle_s:
            for i in range(0, len(chunk), 10):
                time.sleep(type(self).trickle_s)
                self.wfile.write(chunk[i : i + 10])
                self.wfile.flush()
        else:
            self.wfile.write(chunk)
            self.wfile.flush()


class DownloadStallServerTests(unittest.TestCase):
    """Local stall-server fixtures (no egress): the failure mode is
    deterministic instead of weather-dependent.
    """

    BODY = b"0123456789" * 10  # 100 bytes

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dest = Path(self._tmp.name) / "file.bin"
        _StallHandler.delay_s = 0.0
        _StallHandler.trickle_s = 0.0
        _StallHandler.drop_after = None
        _StallHandler.requests_seen = 0
        _StallHandler._dropped = False
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _StallHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.addCleanup(self._server.shutdown)
        self.addCleanup(self._server.server_close)
        port = self._server.server_address[1]
        self.url = f"http://127.0.0.1:{port}/file.bin"

    def test_delayed_headers_trip_stall_timeout(self) -> None:
        _StallHandler.delay_s = 2.0
        with self.assertRaises(DownloadError):
            download_large_file(
                self.url,
                self.dest,
                stall_timeout_s=0.5,
                connect_timeout_s=5,
                retries=1,
                use_curl_fallback=False,
            )
        # Both attempts hit the 0.5 s stall budget, not the 5 s connect budget.
        self.assertEqual(_StallHandler.requests_seen, 2)
        self.assertFalse(self.dest.exists())

    def test_delay_within_stall_budget_succeeds(self) -> None:
        _StallHandler.delay_s = 1.0
        result = download_large_file(self.url, self.dest, stall_timeout_s=5, connect_timeout_s=5)
        self.assertEqual(result, self.dest)
        self.assertEqual(self.dest.read_bytes(), self.BODY)

    def test_trickle_body_does_not_trip_stall(self) -> None:
        _StallHandler.trickle_s = 0.2
        result = download_large_file(
            self.url, self.dest, stall_timeout_s=1, connect_timeout_s=5, chunk_size=10
        )
        self.assertEqual(result, self.dest)
        self.assertEqual(self.dest.read_bytes(), self.BODY)

    def test_mid_body_drop_resumes_with_range(self) -> None:
        _StallHandler.drop_after = 50
        result = download_large_file(
            self.url,
            self.dest,
            stall_timeout_s=5,
            connect_timeout_s=5,
            chunk_size=10,
            retries=2,
            use_curl_fallback=False,
        )
        self.assertEqual(result, self.dest)
        self.assertEqual(self.dest.read_bytes(), self.BODY)
        self.assertEqual(_StallHandler.requests_seen, 2)


class FetchSampleTests(unittest.TestCase):
    def test_licence_gate_blocks_before_http(self) -> None:
        # MixSet is the one wave-1 dataset whose licence is unresolved.
        client = mock.MagicMock()
        with self.assertRaises(DatasetLicenceError):
            fetch_sample(get_spec("mixset"), "default", "train", 5, client=client)
        client.rows.assert_not_called()

    def test_licence_gate_blocks_detectrl_before_http(self) -> None:
        # DetectRL is licence-blocked like MixSet: the gate fires
        # before any fetch attempt is made.
        client = mock.MagicMock()
        with self.assertRaises(DatasetLicenceError):
            fetch_sample(get_spec("detectrl"), "default", "train", 5, client=client)
        client.rows.assert_not_called()

    def test_licence_gate_blocks_m4_before_http(self) -> None:
        # M4 is licence-blocked like MixSet: the gate fires before
        # any fetch attempt is made.
        client = mock.MagicMock()
        with self.assertRaises(DatasetLicenceError):
            fetch_sample(get_spec("m4"), "default", "train", 5, client=client)
        client.rows.assert_not_called()

    def test_licence_gate_blocks_m4gt_bench_before_http(self) -> None:
        # M4GT-Bench is licence-blocked like MixSet: the gate fires
        # before any fetch attempt is made.
        client = mock.MagicMock()
        with self.assertRaises(DatasetLicenceError):
            fetch_sample(get_spec("m4gt_bench"), "default", "train", 5, client=client)
        client.rows.assert_not_called()

    def test_pagination(self) -> None:
        spec = get_spec("beemo")
        client = mock.MagicMock()
        client.rows.side_effect = [
            [{"text": f"t{i}", "label": 0} for i in range(100)],
            [{"text": f"t{i}", "label": 0} for i in range(100, 150)],
        ]
        rows = fetch_sample(spec, "default", "train", 150, client=client)
        self.assertEqual(len(rows), 150)
        self.assertEqual(client.rows.call_count, 2)

    def test_short_page_raises(self) -> None:
        spec = get_spec("beemo")
        client = mock.MagicMock()
        client.rows.return_value = []
        with self.assertRaises(DatasetFetchError):
            fetch_sample(spec, "default", "train", 10, client=client)

    def test_nonpositive_n_raises(self) -> None:
        with self.assertRaises(ValueError):
            fetch_sample(get_spec("beemo"), "default", "train", 0)


class CacheTests(unittest.TestCase):
    def test_round_trip_and_manifest(self) -> None:
        spec = get_spec("beemo")
        rows = [_row("hello world", LABEL_HUMAN), _row("machine text here", LABEL_MACHINE)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, manifest_file = write_sample_cache(spec, "default", "train", rows, cache_dir=root)
            self.assertTrue(path.exists())
            self.assertTrue(manifest_file.exists())
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            self.assertEqual(manifest["rows"], 2)
            self.assertEqual(manifest["dataset"], "beemo")
            self.assertEqual(manifest["licence"], spec.licence)
            import hashlib

            self.assertEqual(
                manifest["file_sha256"],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            back = read_sample_cache(spec, "default", "train", cache_dir=root)
            self.assertEqual([r.text for r in back], ["hello world", "machine text here"])
            self.assertEqual([r.label for r in back], [LABEL_HUMAN, LABEL_MACHINE])

    def test_filename_override_coexists_with_default(self) -> None:
        """U4: a second sample of the same config/split can coexist."""
        spec = get_spec("beemo")
        rows = [_row("hello world", LABEL_HUMAN)]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            default_path, _ = write_sample_cache(spec, "default", "train", rows, cache_dir=root)
            seg_path, seg_manifest = write_sample_cache(
                spec,
                "default",
                "train",
                rows,
                cache_dir=root,
                filename="train-segments.jsonl",
            )
            self.assertEqual(seg_path.name, "train-segments.jsonl")
            self.assertEqual(seg_manifest.name, "train-segments.manifest.json")
            self.assertNotEqual(default_path, seg_path)
            # The default cache is untouched by the override write.
            self.assertTrue(default_path.exists())
            manifest = json.loads(seg_manifest.read_text(encoding="utf-8"))
            self.assertEqual(manifest["file"], "train-segments.jsonl")
            back = read_sample_cache(
                spec, "default", "train", cache_dir=root, filename="train-segments.jsonl"
            )
            self.assertEqual([r.text for r in back], ["hello world"])
            # A path traversal filename is refused.
            with self.assertRaises(ValueError):
                write_sample_cache(
                    spec, "default", "train", rows, cache_dir=root, filename="../escape.jsonl"
                )
            with self.assertRaises(ValueError):
                read_sample_cache(
                    spec, "default", "train", cache_dir=root, filename="../escape.jsonl"
                )

    def test_missing_cache_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError):
            read_sample_cache(get_spec("beemo"), "default", "train", cache_dir=Path(tmp))

    def test_jsonl_shape_is_fingerprint_compatible(self) -> None:
        # benchmark.fingerprint_dataset hashes {"text": ...} per line; the
        # cache must carry text + label on every line.
        row = _row("some text", LABEL_HUMAN)
        data = row.to_jsonl()
        self.assertIn("text", data)
        self.assertIn("label", data)
        self.assertEqual(data["text"], "some text")


class StridedSampleTests(unittest.TestCase):
    def test_sample_offsets_evenly_spaced(self) -> None:
        self.assertEqual(sample_offsets(100, 4), [0, 25, 50, 75])
        self.assertEqual(sample_offsets(10, 10), list(range(10)))
        self.assertEqual(sample_offsets(319071, 1), [0])

    def test_sample_offsets_rejects_bad_inputs(self) -> None:
        for total, n in ((0, 1), (10, 0), (10, 11)):
            with self.assertRaises(ValueError):
                sample_offsets(total, n)

    def test_fetch_strided_sample_uses_offsets(self) -> None:
        client = mock.MagicMock()
        client.rows.side_effect = lambda *a, **k: [{"offset": k["offset"]}]
        rows = fetch_strided_sample(get_spec("raid"), "raid", "train", 4, 100, client=client)
        self.assertEqual([r["offset"] for r in rows], [0, 25, 50, 75])

    def test_fetch_strided_sample_empty_page_raises(self) -> None:
        client = mock.MagicMock()
        client.rows.return_value = []
        with self.assertRaises(DatasetFetchError):
            fetch_strided_sample(get_spec("raid"), "raid", "train", 2, 100, client=client)


class MapperTests(unittest.TestCase):
    def test_raid_human_and_machine(self) -> None:
        human = map_row(
            "raid",
            {"id": "a", "generation": "human text", "model": "human", "domain": "news"},
            "raid",
            "train",
        )[0]
        self.assertEqual((human.label, human.regime), (0, "raid"))
        machine = map_row(
            "raid",
            {
                "id": "b",
                "generation": "machine text",
                "model": "gpt4",
                "domain": "news",
                "attack": "none",
            },
            "raid",
            "train",
        )[0]
        self.assertEqual(machine.label, 1)
        self.assertEqual(machine.meta["model"], "gpt4")

    def test_raid_test_split_is_unlabelled(self) -> None:
        (row,) = map_row("raid", {"id": "c", "generation": "test text"}, "raid_test", "test")
        self.assertIsNone(row.label)

    def test_mage_flips_inverted_polarity(self) -> None:
        (machine,) = map_row(
            "mage", {"text": "m", "label": 0, "src": "cmv_machine_gpt4"}, "default", "train"
        )
        self.assertEqual(machine.label, 1)
        (human,) = map_row(
            "mage", {"text": "h", "label": 1, "src": "cmv_human"}, "default", "train"
        )
        self.assertEqual(human.label, 0)
        self.assertTrue(human.source_id.startswith("mage:"))

    def test_mage_polarity_mismatch_fails_closed(self) -> None:
        with self.assertRaises(DatasetFetchError):
            map_row("mage", {"text": "x", "label": 0, "src": "cmv_human"}, "default", "train")
        with self.assertRaises(DatasetFetchError):
            map_row(
                "mage", {"text": "x", "label": 1, "src": "cmv_machine_gpt4"}, "default", "train"
            )

    def test_beemo_expands_to_kinds(self) -> None:
        row = {
            "id": 7,
            "category": "Closed QA",
            "model": "zephyr-7b-beta",
            "prompt_id": "p1",
            "human_output": "human answer",
            "model_output": "machine answer",
            "human_edits": "human rewrite",
            "llama-3.1-70b_edits": "[{'P1': 'llama light'}, {'P2': 'llama mid'}, {'P3': 'llama heavy'}]",
            "gpt-4o_edits": "[{'P1': 'gpt light'}, {'P2': 'gpt mid'}, {'P3': 'gpt heavy'}]",
        }
        rows = map_row("beemo", row, "default", "train")
        by_kind = {r.meta["kind"]: r for r in rows}
        self.assertEqual(len(rows), 9)
        self.assertEqual(by_kind["human"].label, 0)
        self.assertEqual(by_kind["model_output"].label, 1)
        self.assertEqual(by_kind["human_edits"].label, 0)
        self.assertEqual(by_kind["llama-3.1-70b_P1"].label, 1)
        self.assertEqual(by_kind["gpt-4o_P3"].text, "gpt heavy")
        self.assertEqual(by_kind["human"].source_id, "beemo-7:human")

    def test_beemo_bad_edits_literal_fails_closed(self) -> None:
        row = {
            "id": 1,
            "human_output": "h",
            "model_output": "m",
            "human_edits": "",
            "llama-3.1-70b_edits": "not a literal",
            "gpt-4o_edits": "[{'P1': 'x'}]",
        }
        with self.assertRaises(DatasetFetchError):
            map_row("beemo", row, "default", "train")

    def test_opai_bench_v0_human_and_partial_unlabelled(self) -> None:
        base = {
            "record_id": "opt-1",
            "text": "some document",
            "version": "v0",
            "generator": "gemini-2.5-flash",
            "domain": "abstracts",
            "document_hash_id": "d1",
        }
        (human,) = map_row(
            "opai_bench",
            {
                **base,
                "ai_sentence_ratio": 0.0,
                "sentences": '["First sentence.", "Second sentence.", "Third sentence."]',
                "sentence_labels": "[0, 0, 0]",
                "ai_spans_char": "[]",
            },
            "default",
            "train",
        )
        self.assertEqual(human.label, 0)
        self.assertEqual(
            human.meta["sentences"], ["First sentence.", "Second sentence.", "Third sentence."]
        )
        self.assertEqual(human.meta["sentence_labels"], [0, 0, 0])
        self.assertEqual(human.meta["ai_spans_char"], [])
        (full,) = map_row(
            "opai_bench",
            {
                **base,
                "record_id": "opt-2",
                "ai_sentence_ratio": 1.0,
                "sentences": '["First sentence.", "Second sentence.", "Third sentence."]',
                "sentence_labels": "[1, 1, 1]",
                "ai_spans_char": "[[0, 13]]",
            },
            "default",
            "train",
        )
        self.assertEqual(full.label, 1)
        (partial,) = map_row(
            "opai_bench",
            {
                **base,
                "record_id": "opt-3",
                "ai_sentence_ratio": 0.2,
                "sentences": '["One.", "Two.", "Three.", "Four.", "Five."]',
                "sentence_labels": "[0, 1, 0, 0, 0]",
                "ai_spans_char": "[[5, 9]]",
            },
            "default",
            "train",
        )
        self.assertIsNone(partial.label)
        self.assertEqual(partial.meta["ai_sentence_ratio"], 0.2)
        self.assertEqual(partial.meta["sentence_labels"], [0, 1, 0, 0, 0])
        self.assertEqual(partial.meta["ai_spans_char"], [[5, 9]])

    def test_opai_bench_segment_fields_fail_closed(self) -> None:
        """U4: segment ground truth is validated, never silently dropped."""
        base = {
            "record_id": "opt-9",
            "text": "some document here",
            "version": "v4",
            "generator": "gemini-2.5-flash",
            "domain": "essays",
            "document_hash_id": "d9",
            "ai_sentence_ratio": 0.5,
            "sentences": '["First sentence.", "Second sentence."]',
            "sentence_labels": "[0, 1]",
            "ai_spans_char": "[[0, 5]]",
        }
        # Missing segment fields on the verified default schema.
        for field in ("sentences", "sentence_labels", "ai_spans_char"):
            row = {k: v for k, v in base.items() if k != field}
            with self.assertRaises(DatasetFetchError):
                map_row("opai_bench", row, "default", "train")
        # Malformed JSON.
        with self.assertRaises(DatasetFetchError):
            map_row("opai_bench", {**base, "sentences": "[not json"}, "default", "train")
        # Length mismatch between sentences and labels.
        with self.assertRaises(DatasetFetchError):
            map_row("opai_bench", {**base, "sentence_labels": "[0]"}, "default", "train")
        # Non-binary label.
        with self.assertRaises(DatasetFetchError):
            map_row("opai_bench", {**base, "sentence_labels": "[0, 2]"}, "default", "train")
        # Span outside the text.
        with self.assertRaises(DatasetFetchError):
            map_row("opai_bench", {**base, "ai_spans_char": "[[0, 9999]]"}, "default", "train")
        # Labels disagreeing with the document-level ratio map fine:
        # the ratio and the labels were computed on slightly different
        # segmentations (6/500 sampled rows disagree, max |diff| 0.032),
        # so the mapper preserves both and the measurement reports the
        # agreement instead of asserting it.
        (disagreeing,) = map_row(
            "opai_bench",
            {**base, "sentence_labels": "[0, 0]", "ai_sentence_ratio": 0.5},
            "default",
            "train",
        )
        self.assertEqual(disagreeing.meta["sentence_labels"], [0, 0])
        self.assertEqual(disagreeing.meta["ai_sentence_ratio"], 0.5)
        # Already-decoded lists are accepted (tests / cached rows).
        (row_out,) = map_row(
            "opai_bench",
            {
                **base,
                "sentences": ["First sentence.", "Second sentence."],
                "sentence_labels": [0, 1],
                "ai_spans_char": [[0, 5]],
            },
            "default",
            "train",
        )
        self.assertEqual(row_out.meta["sentences"], ["First sentence.", "Second sentence."])
        # The ablations config is unverified for these fields: rows
        # without them map fine, rows with them preserve them.
        (ablation,) = map_row(
            "opai_bench",
            {
                k: v
                for k, v in base.items()
                if k not in ("sentences", "sentence_labels", "ai_spans_char")
            },
            "ablations",
            "train",
        )
        self.assertNotIn("sentences", ablation.meta)
        (ablation_with,) = map_row("opai_bench", base, "ablations", "train")
        self.assertEqual(ablation_with.meta["sentence_labels"], [0, 1])

    def test_mixset_mapper_refuses(self) -> None:
        # Licence gate fires first (DatasetLicenceError); even if it
        # did not, the mapper itself refuses on unverified polarity.
        with self.assertRaises(DatasetLicenceError):
            map_row("mixset", {"text": "x", "binary": 1}, "default", "train")

    def test_detectrl_mapper_refuses(self) -> None:
        # Licence gate fires first (DatasetLicenceError); even if it
        # did not, the mapper itself refuses — the licence is
        # unresolved AND no live row has been inspected, so the field
        # names inside the benchmark JSONs are unverified.
        with self.assertRaises(DatasetLicenceError):
            map_row("detectrl", {"text": "x"}, "default", "train")
        with self.assertRaises(DatasetFetchError) as caught:
            _map_detectrl({"text": "x"}, "default", "train")
        message = str(caught.exception)
        self.assertIn("licence unresolved", message)
        self.assertIn("no live row inspected", message)
        self.assertIn("refusing to map", message)

    def test_m4gt_bench_mapper_refuses(self) -> None:
        # Licence gate fires first (DatasetLicenceError); even if it
        # did not, the mapper itself refuses — the licence is
        # unresolved AND no live row has been inspected, so the field
        # names inside the Drive JSONL files are unverified.
        with self.assertRaises(DatasetLicenceError):
            map_row("m4gt_bench", {"text": "x"}, "default", "train")
        with self.assertRaises(DatasetFetchError) as caught:
            _map_m4gt_bench({"text": "x"}, "default", "train")
        message = str(caught.exception)
        self.assertIn("licence unresolved", message)
        self.assertIn("no live row inspected", message)
        self.assertIn("refusing to map", message)

    def test_m4_mapper_refuses(self) -> None:
        # Licence gate fires first (DatasetLicenceError); even if it
        # did not, the mapper itself refuses — the licence is
        # unresolved AND no live row has been inspected, so the
        # documented schema is unconfirmed against data.
        with self.assertRaises(DatasetLicenceError):
            map_row("m4", {"prompt": "x", "human_text": "h"}, "default", "train")
        with self.assertRaises(DatasetFetchError) as caught:
            _map_m4({"prompt": "x", "human_text": "h"}, "default", "train")
        message = str(caught.exception)
        self.assertIn("licence unresolved", message)
        self.assertIn("no live row inspected", message)
        self.assertIn("refusing to map", message)

    def test_ghostwriter_labels_and_regimes(self) -> None:
        base = {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "text": "some article text",
            "domain": "cnn_news",
            "date": "2022-09-23T00:00:00",
            "source": "https://www.kaggle.com/datasets/xyz",
            "lang": "en-EN",
            "agent": "human",
            "type": "fulltext",
        }
        (human,) = map_row("ghostwriter", {**base, "label": 0}, "default", "train")
        self.assertEqual((human.label, human.regime), (0, "raw"))
        self.assertEqual(human.source_id, base["id"])
        self.assertEqual(human.meta["domain"], "cnn_news")
        self.assertEqual(human.meta["date"], "2022-09-23T00:00:00")
        (machine,) = map_row(
            "ghostwriter", {**base, "label": 1, "agent": "gpt-4"}, "default", "train"
        )
        self.assertEqual((machine.label, machine.regime), (1, "raw"))
        self.assertEqual(machine.meta["agent"], "gpt-4")
        # Fusion rows take no binary label (mixed-origin, U4 spine).
        (fusion,) = map_row(
            "ghostwriter",
            {**base, "label": 2, "domain": "gutenberg", "agent": "fusion-model"},
            "default",
            "train",
        )
        self.assertIsNone(fusion.label)
        self.assertEqual(fusion.regime, "mixed-origin")

    def test_ghostwriter_date_is_kept_raw(self) -> None:
        # `date` formats are inconsistent across rows; the mapper must
        # never parse them — an unparseable value passes through as-is.
        (row,) = map_row(
            "ghostwriter",
            {
                "id": "abc",
                "text": "t",
                "domain": "bundestag",
                "label": 0,
                "date": "01,July,2004",
                "lang": "de-DE",
                "agent": "human",
                "type": "chunk",
                "source": "uuid-1__[0:500]",
            },
            "default",
            "train",
        )
        self.assertEqual(row.meta["date"], "01,July,2004")
        self.assertEqual(row.meta["type"], "chunk")

    def test_ghostwriter_unknown_domain_fails_closed(self) -> None:
        # A row whose domain has no recorded licence is refused.
        with self.assertRaises(DatasetFetchError):
            map_row(
                "ghostwriter",
                {
                    "id": "abc",
                    "text": "t",
                    "domain": "ninth_domain",
                    "label": 0,
                },
                "default",
                "train",
            )
        with self.assertRaises(DatasetFetchError):
            map_row(
                "ghostwriter",
                {"id": "abc", "text": "t", "label": 0},
                "default",
                "train",
            )

    def test_ghostwriter_bad_label_fails_closed(self) -> None:
        base = {"id": "abc", "text": "t", "domain": "cnn_news"}
        for bad in (3, -1, "1", None, True):
            with self.subTest(bad=bad), self.assertRaises(DatasetFetchError):
                map_row("ghostwriter", {**base, "label": bad}, "default", "train")

    def test_ghostwriter_missing_text_or_id_fails_closed(self) -> None:
        with self.assertRaises(DatasetFetchError):
            map_row(
                "ghostwriter",
                {"id": "abc", "text": "  ", "domain": "cnn_news", "label": 0},
                "default",
                "train",
            )
        with self.assertRaises(DatasetFetchError):
            map_row(
                "ghostwriter",
                {"text": "t", "domain": "cnn_news", "label": 0},
                "default",
                "train",
            )


class DetectRLXMapperTests(unittest.TestCase):
    """DetectRL-X mapper: one row per text field, no numeric label."""

    def setUp(self) -> None:
        self.base = {
            "human_written_text": "a human paragraph about history",
            "llm_generated_text": "a machine paragraph about history",
            "lang": "english",
            "model": "gpt-4o",
            "split": "train",
            "domain": "Wiki",
        }

    def test_both_text_fields_map_to_labelled_raw_rows(self) -> None:
        rows = map_row("detectrl_x", dict(self.base), "binary", "train", row_index=7)
        self.assertEqual(len(rows), 2)
        human, machine = rows
        self.assertEqual((human.label, human.regime), (0, "raw"))
        self.assertEqual((machine.label, machine.regime), (1, "raw"))
        self.assertEqual(human.text, "a human paragraph about history")
        self.assertEqual(machine.text, "a machine paragraph about history")
        # No id field exists in the file: source_id is file + row index.
        self.assertEqual(human.source_id, f"detectrl-x:{DETECTRL_X_FILE}:7:human")
        self.assertEqual(machine.source_id, f"detectrl-x:{DETECTRL_X_FILE}:7:llm")
        for row in rows:
            self.assertEqual(row.dataset, "detectrl_x")
            self.assertEqual(row.config, "binary")
            self.assertEqual(row.split, "train")
            self.assertEqual(
                row.meta,
                {
                    "lang": "english",
                    "model": "gpt-4o",
                    "split": "train",
                    "domain": "Wiki",
                    "file": DETECTRL_X_FILE,
                },
            )

    def test_ternary_refined_text_is_mixed_origin_without_label(self) -> None:
        # Ternary files add llm_refined_text; the refined row never
        # takes a binary label (same rule as the OpAI-Bench partials).
        row = dict(self.base, llm_refined_text="a refined paragraph")
        rows = map_row("detectrl_x", row, "binary", "train", row_index=3)
        self.assertEqual(len(rows), 3)
        refined = rows[2]
        self.assertIsNone(refined.label)
        self.assertEqual(refined.regime, "mixed-origin")
        self.assertEqual(refined.source_id, f"detectrl-x:{DETECTRL_X_FILE}:3:refined")

    def test_missing_row_index_fails_closed(self) -> None:
        # No id field exists, so an index-less mapping would invent an
        # identity; refuse instead.
        with self.assertRaises(DatasetFetchError):
            map_row("detectrl_x", dict(self.base), "binary", "train")

    def test_missing_or_empty_text_field_fails_closed(self) -> None:
        for missing in ("human_written_text", "llm_generated_text"):
            with self.subTest(missing=missing):
                row = dict(self.base)
                del row[missing]
                with self.assertRaises(DatasetFetchError):
                    map_row("detectrl_x", row, "binary", "train", row_index=0)
        with self.assertRaises(DatasetFetchError):
            map_row(
                "detectrl_x",
                dict(self.base, human_written_text="   "),
                "binary",
                "train",
                row_index=0,
            )
        # A row with neither text field.
        with self.assertRaises(DatasetFetchError):
            map_row(
                "detectrl_x",
                {"lang": "english", "model": "gpt-4o", "split": "train", "domain": "Wiki"},
                "binary",
                "train",
                row_index=0,
            )

    def test_unknown_enum_values_fail_closed(self) -> None:
        cases = [
            {"lang": "klingon"},
            {"lang": "en"},
            {"model": "gpt-5"},
            {"domain": "Blog"},
            {"domain": "news"},
        ]
        for patch in cases:
            with self.subTest(patch=patch), self.assertRaises(DatasetFetchError):
                map_row(
                    "detectrl_x",
                    dict(self.base, **patch),
                    "binary",
                    "train",
                    row_index=0,
                )

    def test_split_mismatch_fails_closed(self) -> None:
        # The row's own split field is cross-checked against the split
        # being mapped; a train row must not land in a test cache.
        with self.assertRaises(DatasetFetchError):
            map_row("detectrl_x", dict(self.base), "binary", "test", row_index=0)
        with self.assertRaises(DatasetFetchError):
            map_row(
                "detectrl_x",
                dict(self.base, split="test"),
                "binary",
                "train",
                row_index=0,
            )

    def test_empty_refined_text_fails_closed(self) -> None:
        with self.assertRaises(DatasetFetchError):
            map_row(
                "detectrl_x",
                dict(self.base, llm_refined_text="  "),
                "binary",
                "train",
                row_index=0,
            )

    def test_all_declared_langs_models_domains_map(self) -> None:
        # Every enum value in the spec maps; the mapper is not
        # English-only by accident.
        for lang in (
            "arabic",
            "chinese",
            "english",
            "french",
            "german",
            "portuguese",
            "russian",
            "spanish",
        ):
            rows = map_row(
                "detectrl_x",
                dict(self.base, lang=lang),
                "binary",
                "train",
                row_index=0,
            )
            self.assertEqual(len(rows), 2)
        for model in ("deepseek-v3", "gemini-2.5-flash", "gpt-4o", "qwen-max"):
            rows = map_row(
                "detectrl_x",
                dict(self.base, model=model),
                "binary",
                "train",
                row_index=0,
            )
            self.assertEqual(len(rows), 2)
        for domain in ("Academic", "News", "Novel", "Wiki", "SEO", "Webtext"):
            rows = map_row(
                "detectrl_x",
                dict(self.base, domain=domain),
                "binary",
                "train",
                row_index=0,
            )
            self.assertEqual(len(rows), 2)


class DetectRLXFileTests(unittest.TestCase):
    """Streaming JSON-array reader + sampler for the ~879 MB file.

    No network and no real dataset text: the fixtures are tiny
    synthetic arrays written to a temp dir.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _write_array(self, rows: list[dict], name: str = "f.json") -> Path:
        path = self.dir / name
        path.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
        return path

    def _row(self, split: str, lang: str = "english") -> dict:
        return {
            "human_written_text": f"human {split} {lang}",
            "llm_generated_text": f"machine {split} {lang}",
            "lang": lang,
            "model": "gpt-4o",
            "split": split,
            "domain": "Wiki",
        }

    def test_iter_yields_index_and_row_in_order(self) -> None:
        path = self._write_array([self._row("train"), self._row("test"), self._row("train")])
        got = list(iter_detectrl_x_rows(path))
        self.assertEqual([i for i, _ in got], [0, 1, 2])
        self.assertEqual([r["split"] for _, r in got], ["train", "test", "train"])

    def test_iter_tolerates_whitespace_and_newlines(self) -> None:
        path = self.dir / "pretty.json"
        path.write_text(
            "[\n  "
            + json.dumps(self._row("train"))
            + ",\n  "
            + json.dumps(self._row("test"))
            + "\n]\n",
            encoding="utf-8",
        )
        self.assertEqual(len(list(iter_detectrl_x_rows(path))), 2)

    def test_iter_rejects_jsonl_and_bare_object(self) -> None:
        jsonl = self.dir / "rows.jsonl"
        jsonl.write_text(json.dumps(self._row("train")) + "\n", encoding="utf-8")
        with self.assertRaises(DatasetFetchError):
            list(iter_detectrl_x_rows(jsonl))
        bare = self.dir / "bare.json"
        bare.write_text(json.dumps(self._row("train")), encoding="utf-8")
        with self.assertRaises(DatasetFetchError):
            list(iter_detectrl_x_rows(bare))

    def test_iter_rejects_truncated_array(self) -> None:
        path = self.dir / "trunc.json"
        path.write_text("[" + json.dumps(self._row("train")) + ",", encoding="utf-8")
        with self.assertRaises(DatasetFetchError):
            list(iter_detectrl_x_rows(path))

    def test_iter_rejects_non_object_element(self) -> None:
        path = self.dir / "bad.json"
        path.write_text('["not an object"]', encoding="utf-8")
        with self.assertRaises(DatasetFetchError):
            list(iter_detectrl_x_rows(path))

    def test_sample_counts_per_split_and_collects_offsets(self) -> None:
        rows = [self._row("train") for _ in range(10)] + [self._row("test") for _ in range(6)]
        path = self._write_array(rows)
        train, test, counts = sample_detectrl_x_rows(path, [0, 5, 9], [0, 5])
        self.assertEqual(counts, {"train": 10, "test": 6, "total": 16})
        self.assertEqual([i for i, _ in train], [0, 5, 9])
        self.assertEqual([i for i, _ in test], [10, 15])
        self.assertTrue(all(r["split"] == "train" for _, r in train))
        self.assertTrue(all(r["split"] == "test" for _, r in test))

    def test_sample_short_sample_fails_closed(self) -> None:
        path = self._write_array([self._row("train") for _ in range(4)])
        with self.assertRaises(DatasetFetchError):
            sample_detectrl_x_rows(path, [0, 1, 2, 3, 4], [])

    def test_sample_unexpected_split_fails_closed(self) -> None:
        row = self._row("train")
        row["split"] = "validation"
        path = self._write_array([row])
        with self.assertRaises(DatasetFetchError):
            sample_detectrl_x_rows(path, [0], [])

    def test_verify_file_size_and_hash(self) -> None:
        import hashlib

        import textforensics.datasets as datasets_module

        data = b"small fake file"
        path = self.dir / "fake.json"
        path.write_bytes(data)
        expected = hashlib.sha256(data).hexdigest()
        with (
            mock.patch.object(datasets_module, "DETECTRL_X_BYTES", len(data)),
            mock.patch.object(datasets_module, "DETECTRL_X_SHA256", expected),
        ):
            self.assertEqual(verify_detectrl_x_file(path), path)
        with (
            mock.patch.object(datasets_module, "DETECTRL_X_BYTES", len(data)),
            mock.patch.object(datasets_module, "DETECTRL_X_SHA256", "0" * 64),
            self.assertRaises(DatasetFetchError),
        ):
            verify_detectrl_x_file(path)
        with (
            mock.patch.object(datasets_module, "DETECTRL_X_BYTES", len(data) + 1),
            self.assertRaises(DatasetFetchError),
        ):
            verify_detectrl_x_file(path)
        with self.assertRaises(DatasetFetchError):
            verify_detectrl_x_file(self.dir / "missing.json")

    def test_download_uses_shared_downloader_with_expected_hash(self) -> None:
        import textforensics.datasets as datasets_module

        seen: dict[str, object] = {}

        def _fake_download(url, dest, **kwargs):
            seen["url"] = url
            seen["dest"] = dest
            seen.update(kwargs)
            return Path(dest)

        with mock.patch.object(datasets_module, "download_large_file", side_effect=_fake_download):
            result = download_detectrl_x(cache_dir=self.dir)
        self.assertEqual(seen["url"], DETECTRL_X_URL)
        self.assertEqual(seen["dest"], self.dir / "detectrl_x" / DETECTRL_X_FILE)
        self.assertEqual(seen["expected_sha256"], DETECTRL_X_SHA256)
        self.assertEqual(seen["expected_bytes"], DETECTRL_X_BYTES)
        self.assertEqual(result, self.dir / "detectrl_x" / DETECTRL_X_FILE)
        self.assertEqual(
            detectrl_x_raw_path(cache_dir=self.dir),
            self.dir / "detectrl_x" / DETECTRL_X_FILE,
        )


if __name__ == "__main__":
    unittest.main()
