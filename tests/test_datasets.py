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
    NormalizedRow,
    cache_path,
    default_cache_dir,
    fetch_sample,
    get_spec,
    manifest_path,
    read_sample_cache,
    require_licence,
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
        for key in ("raid", "mage", "beemo", "mixset", "opai_bench"):
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


if __name__ == "__main__":
    unittest.main()
