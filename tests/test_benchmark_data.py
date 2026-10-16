import csv
import json
import tempfile
import unittest
from pathlib import Path

from textforensics.benchmark_data import (
    NORMALIZED_SCHEMA,
    normalize_detectrlx_json,
    normalize_m4_jsonl,
    normalize_raid_csv,
)


def read_jsonl(path: Path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class BenchmarkDataTests(unittest.TestCase):
    def test_raid_csv_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "raid.csv"
            output = Path(tmp) / "normalized.jsonl"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "id",
                        "model",
                        "generation",
                        "domain",
                        "attack",
                        "decoding",
                        "repetition_penalty",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "id": "h1",
                        "model": "human",
                        "generation": "Human control text.",
                        "domain": "news",
                        "attack": "none",
                        "decoding": "",
                        "repetition_penalty": "",
                    }
                )
                writer.writerow(
                    {
                        "id": "a1",
                        "model": "gpt-test",
                        "generation": "Generated control text.",
                        "domain": "news",
                        "attack": "none",
                        "decoding": "sampling",
                        "repetition_penalty": "1.0",
                    }
                )

            manifest = normalize_raid_csv(
                source,
                output,
                dataset_revision="raid-test-revision",
                split="train",
            )
            rows = read_jsonl(output)
            self.assertEqual(len(rows), 2)
            self.assertEqual({row["label"] for row in rows}, {"human", "ai"})
            self.assertEqual(rows[0]["schema"], NORMALIZED_SCHEMA)
            self.assertEqual(manifest["human_count"], 1)
            self.assertEqual(manifest["ai_count"], 1)
            manifest_text = output.with_suffix(
                ".jsonl.manifest.json"
            ).read_text(encoding="utf-8")
            self.assertNotIn("Human control text", manifest_text)

    def test_m4_deduplicates_human_controls_across_generators(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "arxiv_modelA.jsonl"
            second = Path(tmp) / "arxiv_modelB.jsonl"
            output = Path(tmp) / "m4.jsonl"
            common = {
                "prompt": "prompt",
                "human_text": "Shared human text.",
                "source": "arxiv",
                "source_ID": "123",
            }
            first.write_text(
                json.dumps(
                    {
                        **common,
                        "machine_text": "Generated A.",
                        "model": "modelA",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            second.write_text(
                json.dumps(
                    {
                        **common,
                        "machine_text": "Generated B.",
                        "model": "modelB",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = normalize_m4_jsonl(
                [first, second],
                output,
                dataset_revision="m4-test-revision",
                split="test",
            )
            rows = read_jsonl(output)
            self.assertEqual(sum(row["label"] == "human" for row in rows), 1)
            self.assertEqual(sum(row["label"] == "ai" for row in rows), 2)
            self.assertEqual(manifest["example_count"], 3)
            self.assertEqual(set(manifest["generators"]), {"modelA", "modelB"})

    def test_detectrlx_streaming_array_and_refined_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "detectrlx.json"
            output = Path(tmp) / "detectrlx.jsonl"
            source.write_text(
                json.dumps(
                    [
                        {
                            "human_written_text": "Human text.",
                            "llm_generated_text": "Generated text.",
                            "llm_refined_text": "Refined generated text.",
                            "lang": "english",
                            "model": "gpt-test",
                            "split": "test",
                            "domain": "News",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            normalize_detectrlx_json(
                source,
                output,
                dataset_revision="detectrlx-test-revision",
                subset="ternary",
            )
            rows = read_jsonl(output)
            self.assertEqual(len(rows), 2)
            self.assertNotIn(
                "Refined generated text.",
                {row["text"] for row in rows},
            )

            normalize_detectrlx_json(
                source,
                output,
                dataset_revision="detectrlx-test-revision",
                subset="ternary",
                include_refined_as_ai=True,
            )
            rows = read_jsonl(output)
            self.assertEqual(len(rows), 3)
            refined = [
                row for row in rows if row["transformation"] == "llm_refined"
            ]
            self.assertEqual(len(refined), 1)
            self.assertEqual(refined[0]["label"], "ai")

    def test_revision_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "empty.csv"
            source.write_text("", encoding="utf-8")
            with self.assertRaises(ValueError):
                normalize_raid_csv(
                    source,
                    Path(tmp) / "out.jsonl",
                    dataset_revision="",
                    split="train",
                )


if __name__ == "__main__":
    unittest.main()
