# Benchmark dataset normalization

TextForensics does not vendor RAID, M4, DetectRL, DetectRL-X, or other third-party corpora. Their licenses/data policies remain independent.

Instead, local source files can be normalized into:

`textforensics.benchmark-example/v1`

Each record preserves:
- stable sample ID;
- human/AI label;
- benchmark text;
- dataset and immutable revision supplied by the user;
- split;
- source ID where available;
- language;
- domain;
- generator;
- transformation/revision regime;
- source-file SHA-256;
- source-specific non-text metadata.

A companion manifest contains only hashes/counts/metadata. It intentionally excludes benchmark text.

## RAID

Obtain RAID using its official package/repository and export the desired labeled split to CSV.

```bash
textforensics dataset raid raid-train.csv \
  --revision <RAID_COMMIT_OR_DATASET_REVISION> \
  --split train \
  --output raid-train.normalized.jsonl
```

The adapter follows official RAID semantics:
- `model == human` → human;
- every other model → AI;
- `attack`, domain, decoding and repetition-penalty metadata are preserved.

For official leaderboard submissions, follow RAID's own test-set/evaluation protocol rather than treating hidden test labels as locally available.

## M4

Pass one or more official M4 JSONL files:

```bash
textforensics dataset m4 data/arxiv_*.jsonl \
  --revision <M4_COMMIT_OR_DATA_REVISION> \
  --split test \
  --output m4-arxiv.normalized.jsonl
```

M4 files pair `human_text` and `machine_text`. When several generator files share the same human source, TextForensics deduplicates the human control by source/text fingerprint so adding generators does not multiply the human class.

## DetectRL-X

For the 2026 DetectRL-X public JSON arrays:

```bash
textforensics dataset detectrlx binary_english_open.json \
  --revision <DATASET_REVISION> \
  --subset binary \
  --output detectrlx-en.normalized.jsonl
```

Ternary records can include `llm_refined_text`. TextForensics excludes refined text by default because silently collapsing a ternary benchmark into a binary task changes benchmark semantics.

For an explicitly documented binary projection:

```bash
textforensics dataset detectrlx ternary_english_open.json \
  --revision <DATASET_REVISION> \
  --subset ternary \
  --include-refined-as-ai \
  --output detectrlx-en-ternary-projected.jsonl
```

Those records are tagged `transformation=llm_refined` and `binary_projection=true`.

## Revision policy

`--revision` is mandatory.

Use an immutable source identifier whenever possible:
- repository commit SHA;
- dataset revision ID;
- release/tag plus an independently recorded file hash.

The normalizer also hashes every local source file and the generated normalized JSONL.

## Data handling

The normalized JSONL contains the benchmark text and is subject to source-dataset licensing/data-governance requirements.

The manifest contains no benchmark text and can be archived with benchmark run artifacts.
