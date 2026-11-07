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
    LABEL_HUMAN,
    LABEL_MACHINE,
    DatasetFetchError,
    DatasetLicenceError,
    DatasetsServerClient,
    DownloadError,
    NormalizedRow,
    cache_path,
    default_cache_dir,
    download_large_file,
    fetch_sample,
    fetch_strided_sample,
    get_spec,
    manifest_path,
    map_row,
    read_sample_cache,
    require_licence,
    sample_offsets,
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
        for key in ("raid", "mage", "beemo", "mixset", "opai_bench", "ghostwriter"):
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

    def test_wave1_specs_have_no_domain_licences(self) -> None:
        # The optional field defaults to None so wave-1 specs are untouched.
        for key in ("raid", "mage", "beemo", "mixset", "opai_bench"):
            self.assertIsNone(get_spec(key).domain_licences)

    def test_unresolved_licences_block_fetch(self) -> None:
        # MixSet has no licence on any source checked 2026-11-06; the
        # gate stays closed until the authors clarify.
        with self.assertRaises(DatasetLicenceError):
            require_licence(get_spec("mixset"))


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


if __name__ == "__main__":
    unittest.main()
