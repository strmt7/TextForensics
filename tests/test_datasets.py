"""Tests for the wave-1 dataset loaders (transport, specs, cache).

No network is used here: every HTTP call is mocked. Live downloads are
covered by the smoke tests in the measurement script, which are skipped
without network/cache.
"""

import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

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
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(payload)):
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
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(splits_payload)):
            self.assertEqual(
                DatasetsServerClient(retries=0).splits("yaful/MAGE"), splits_payload["splits"]
            )
        with mock.patch("urllib.request.urlopen", return_value=_fake_response(size_payload)):
            self.assertEqual(
                DatasetsServerClient(retries=0).size("yaful/MAGE")["dataset"]["num_rows"], 436606
            )

    def test_retries_then_raises(self) -> None:
        with (
            mock.patch(
                "urllib.request.urlopen", side_effect=urllib.error.URLError("down")
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

        with mock.patch("urllib.request.urlopen", side_effect=_flaky):
            payload = DatasetsServerClient(retries=3, timeout_s=1)._get_json(
                "/rows", {"dataset": "x"}
            )
        self.assertEqual(payload, {"rows": [{"row": {"a": 1}}]})
        self.assertEqual(calls["n"], 3)


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
            "urllib.request.urlopen",
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
                "urllib.request.urlopen",
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

        with mock.patch("urllib.request.urlopen", side_effect=_urlopen):
            download_large_file("https://example.invalid/file.bin", self.dest)
        self.assertEqual(seen["range"], "bytes=6-")
        self.assertEqual(self.dest.read_bytes(), b"hello world")

    def test_server_ignoring_range_restarts_from_zero(self) -> None:
        part = Path(str(self.dest) + ".part")
        part.write_bytes(b"stale partial")
        with mock.patch(
            "urllib.request.urlopen",
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

        with mock.patch("urllib.request.urlopen", side_effect=_flaky):
            download_large_file("https://example.invalid/file.bin", self.dest, retries=2)
        self.assertEqual(self.dest.read_bytes(), b"data")
        self.assertEqual(calls["n"], 2)

    def test_404_fails_immediately_without_retry(self) -> None:
        with (
            mock.patch(
                "urllib.request.urlopen",
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
        with mock.patch("urllib.request.urlopen") as urlopen:
            result = download_large_file(
                "https://example.invalid/file.bin", self.dest, expected_sha256=expected
            )
        urlopen.assert_not_called()
        self.assertEqual(result, self.dest)

    def test_expected_byte_count_mismatch_raises(self) -> None:
        with (
            mock.patch(
                "urllib.request.urlopen",
                return_value=self._fake_download_response(b"short"),
            ),
            self.assertRaises(DownloadError),
        ):
            download_large_file("https://example.invalid/file.bin", self.dest, expected_bytes=100)
        self.assertFalse(self.dest.exists())


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
        (human,) = map_row("opai_bench", {**base, "ai_sentence_ratio": 0.0}, "default", "train")
        self.assertEqual(human.label, 0)
        (full,) = map_row(
            "opai_bench",
            {**base, "record_id": "opt-2", "ai_sentence_ratio": 1.0},
            "default",
            "train",
        )
        self.assertEqual(full.label, 1)
        (partial,) = map_row(
            "opai_bench",
            {**base, "record_id": "opt-3", "ai_sentence_ratio": 0.2},
            "default",
            "train",
        )
        self.assertIsNone(partial.label)
        self.assertEqual(partial.meta["ai_sentence_ratio"], 0.2)

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
