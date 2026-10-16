from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


NORMALIZED_SCHEMA = "textforensics.benchmark-example/v1"
MANIFEST_SCHEMA = "textforensics.benchmark-normalization/v1"


@dataclass(frozen=True, slots=True)
class NormalizedExample:
    schema: str
    sample_id: str
    label: str
    text: str
    dataset: str
    dataset_revision: str
    split: str
    source_id: str | None = None
    language: str | None = None
    domain: str | None = None
    generator: str | None = None
    transformation: str | None = None
    source_file_sha256: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["metadata"] = payload["metadata"] or {}
        return payload


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_id(*parts: Any) -> str:
    encoded = "".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _require_revision(revision: str) -> str:
    value = str(revision).strip()
    if not value:
        raise ValueError("dataset_revision must be a non-empty immutable identifier.")
    return value


def _clean_optional(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered or None


def _validate_example(example: NormalizedExample) -> None:
    if example.schema != NORMALIZED_SCHEMA:
        raise ValueError("Unsupported normalized benchmark schema.")
    if example.label not in {"human", "ai"}:
        raise ValueError("Normalized label must be 'human' or 'ai'.")
    if not example.sample_id:
        raise ValueError("sample_id must not be empty.")
    if not example.text.strip():
        raise ValueError("Normalized benchmark text must not be empty.")
    if not example.dataset.strip() or not example.dataset_revision.strip():
        raise ValueError("dataset and dataset_revision must not be empty.")
    if not example.split.strip():
        raise ValueError("split must not be empty.")
    if example.source_file_sha256 is not None:
        value = example.source_file_sha256
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("source_file_sha256 must be a lowercase SHA-256 hex digest.")


def _write_examples(
    output_path: str | Path,
    examples: Iterable[NormalizedExample],
    *,
    dataset: str,
    dataset_revision: str,
    source_files: list[dict[str, Any]],
    adapter: str,
) -> dict[str, Any]:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    total = human = ai = 0
    languages: set[str] = set()
    domains: set[str] = set()
    generators: set[str] = set()
    transformations: set[str] = set()

    with output.open("w", encoding="utf-8", newline="
") as handle:
        for example in examples:
            _validate_example(example)
            payload = example.to_dict()
            handle.write(
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "
"
            )
            total += 1
            if example.label == "human":
                human += 1
            else:
                ai += 1
            if example.language:
                languages.add(example.language)
            if example.domain:
                domains.add(example.domain)
            if example.generator:
                generators.add(example.generator)
            if example.transformation:
                transformations.add(example.transformation)

    if total == 0:
        output.unlink(missing_ok=True)
        raise ValueError("Normalization emitted no benchmark examples.")

    normalized_sha = file_sha256(output)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "adapter": adapter,
        "dataset": dataset,
        "dataset_revision": dataset_revision,
        "normalized_file": output.name,
        "normalized_sha256": normalized_sha,
        "example_count": total,
        "human_count": human,
        "ai_count": ai,
        "languages": sorted(languages),
        "domains": sorted(domains),
        "generators": sorted(generators),
        "transformations": sorted(transformations),
        "source_files": source_files,
        "raw_text_included": False,
        "notes": (
            "The manifest contains hashes and metadata only. The normalized JSONL "
            "contains benchmark text and must be handled according to the source "
            "dataset license and data policy."
        ),
    }
    manifest_path = output.with_suffix(output.suffix + ".manifest.json")
    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
        )
        + "
",
        encoding="utf-8",
    )
    return manifest


def normalize_raid_csv(
    input_path: str | Path,
    output_path: str | Path,
    *,
    dataset_revision: str,
    split: str,
) -> dict[str, Any]:
    """Normalize an official RAID CSV export without requiring pandas/raid-bench.

    Expected official columns include id, model, domain, attack, generation,
    decoding and repetition_penalty. Human rows use model == "human".
    """

    revision = _require_revision(dataset_revision)
    source = Path(input_path)
    source_sha = file_sha256(source)
    source_meta = [
        {
            "path": source.name,
            "sha256": source_sha,
            "format": "raid_csv",
        }
    ]

    def examples() -> Iterator[NormalizedExample]:
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"id", "model", "generation", "domain", "attack"}
            missing = sorted(required - set(reader.fieldnames or ()))
            if missing:
                raise ValueError(
                    "RAID CSV is missing required columns: " + ", ".join(missing)
                )
            for row_number, row in enumerate(reader, start=2):
                text = str(row.get("generation") or "").strip()
                if not text:
                    continue
                model = str(row.get("model") or "").strip()
                label = "human" if model.lower() == "human" else "ai"
                source_id = _clean_optional(row.get("id"))
                sample_id = _stable_id(
                    "raid",
                    revision,
                    split,
                    source_id or row_number,
                    label,
                )
                metadata = {
                    key: row.get(key)
                    for key in (
                        "adv_source_id",
                        "source_id",
                        "decoding",
                        "repetition_penalty",
                        "title",
                    )
                    if row.get(key) not in {None, ""}
                }
                yield NormalizedExample(
                    schema=NORMALIZED_SCHEMA,
                    sample_id=sample_id,
                    label=label,
                    text=text,
                    dataset="RAID",
                    dataset_revision=revision,
                    split=split,
                    source_id=source_id,
                    language="en",
                    domain=_clean_optional(row.get("domain")),
                    generator=None if label == "human" else model or None,
                    transformation=_clean_optional(row.get("attack")) or "none",
                    source_file_sha256=source_sha,
                    metadata=metadata,
                )

    return _write_examples(
        output_path,
        examples(),
        dataset="RAID",
        dataset_revision=revision,
        source_files=source_meta,
        adapter="raid_csv/v1",
    )


_M4_LANGUAGE_BY_DOMAIN = {
    "arabic": "ar",
    "bulgarian_true_and_fake_news": "bg",
    "germanwikipedia": "de",
    "id-newspaper": "id",
    "qazh": "kk",
    "russian": "ru",
    "urdu": "ur",
    "urdu-news": "ur",
    "arxiv": "en",
    "peerread": "en",
    "reddit": "en",
    "wikipedia": "en",
    "wikihow": "en",
}


def _m4_domain_from_name(path: Path) -> str:
    stem = path.stem
    if stem.endswith("_human"):
        return stem[: -len("_human")]
    if "_" not in stem:
        return stem
    return stem.rsplit("_", 1)[0]


def normalize_m4_jsonl(
    input_paths: Iterable[str | Path],
    output_path: str | Path,
    *,
    dataset_revision: str,
    split: str,
) -> dict[str, Any]:
    """Normalize one or more official M4 JSONL files.

    The official M4 format contains prompt, human_text, machine_text, model,
    source and source_ID. Human controls are deduplicated across model files
    using a stable source/text fingerprint so combining generators does not
    multiply the same human sample.
    """

    revision = _require_revision(dataset_revision)
    paths = [Path(path) for path in input_paths]
    if not paths:
        raise ValueError("At least one M4 JSONL file is required.")

    source_hashes = {path: file_sha256(path) for path in paths}
    source_meta = [
        {"path": path.name, "sha256": source_hashes[path], "format": "m4_jsonl"}
        for path in paths
    ]

    def examples() -> Iterator[NormalizedExample]:
        seen_humans: set[str] = set()
        for path in paths:
            source_sha = source_hashes[path]
            domain = _m4_domain_from_name(path)
            language = _M4_LANGUAGE_BY_DOMAIN.get(domain)
            with path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"{path.name}:{line_number} is not valid JSON."
                        ) from exc
                    if not isinstance(row, dict):
                        raise ValueError(
                            f"{path.name}:{line_number} must be a JSON object."
                        )

                    source_id = _clean_optional(
                        row.get("source_ID") or row.get("source_id")
                    )
                    source_name = _clean_optional(row.get("source"))
                    human_text = str(row.get("human_text") or "").strip()
                    machine_text = str(row.get("machine_text") or "").strip()
                    generator = _clean_optional(row.get("model"))
                    prompt = _clean_optional(row.get("prompt"))

                    if human_text:
                        human_key = _stable_id(
                            source_name,
                            source_id,
                            human_text,
                        )
                        if human_key not in seen_humans:
                            seen_humans.add(human_key)
                            yield NormalizedExample(
                                schema=NORMALIZED_SCHEMA,
                                sample_id=_stable_id(
                                    "M4",
                                    revision,
                                    split,
                                    human_key,
                                    "human",
                                ),
                                label="human",
                                text=human_text,
                                dataset="M4",
                                dataset_revision=revision,
                                split=split,
                                source_id=source_id,
                                language=language,
                                domain=domain,
                                generator=None,
                                transformation="none",
                                source_file_sha256=source_sha,
                                metadata={
                                    "source": source_name,
                                    "prompt_present": bool(prompt),
                                },
                            )

                    if machine_text:
                        yield NormalizedExample(
                            schema=NORMALIZED_SCHEMA,
                            sample_id=_stable_id(
                                "M4",
                                revision,
                                split,
                                path.name,
                                source_id or line_number,
                                generator,
                                "ai",
                            ),
                            label="ai",
                            text=machine_text,
                            dataset="M4",
                            dataset_revision=revision,
                            split=split,
                            source_id=source_id,
                            language=language,
                            domain=domain,
                            generator=generator,
                            transformation="none",
                            source_file_sha256=source_sha,
                            metadata={
                                "source": source_name,
                                "prompt_present": bool(prompt),
                            },
                        )

    return _write_examples(
        output_path,
        examples(),
        dataset="M4",
        dataset_revision=revision,
        source_files=source_meta,
        adapter="m4_jsonl/v1",
    )


def _iter_json_array(path: Path, *, chunk_size: int = 1024 * 1024) -> Iterator[Any]:
    """Stream a top-level JSON array using only the Python standard library."""

    decoder = json.JSONDecoder()
    buffer = ""
    started = False
    finished = False

    with path.open("r", encoding="utf-8") as handle:
        while not finished:
            chunk = handle.read(chunk_size)
            eof = not chunk
            buffer += chunk
            position = 0

            while True:
                while position < len(buffer) and buffer[position].isspace():
                    position += 1

                if not started:
                    if position >= len(buffer):
                        break
                    if buffer[position] != "[":
                        raise ValueError(f"{path.name} must contain a JSON array.")
                    started = True
                    position += 1
                    continue

                while position < len(buffer) and (
                    buffer[position].isspace() or buffer[position] == ","
                ):
                    position += 1

                if position < len(buffer) and buffer[position] == "]":
                    finished = True
                    position += 1
                    break

                if position >= len(buffer):
                    break

                try:
                    value, end = decoder.raw_decode(buffer, position)
                except json.JSONDecodeError:
                    break
                yield value
                position = end

            buffer = buffer[position:]
            if eof:
                if not finished:
                    if buffer.strip():
                        raise ValueError(f"{path.name} contains incomplete JSON.")
                    raise ValueError(f"{path.name} is missing the closing JSON array.")
                if buffer.strip():
                    raise ValueError(f"{path.name} has trailing content after the JSON array.")

    if not started:
        raise ValueError(f"{path.name} is empty.")


def normalize_detectrlx_json(
    input_path: str | Path,
    output_path: str | Path,
    *,
    dataset_revision: str,
    subset: str = "binary",
    include_refined_as_ai: bool = False,
) -> dict[str, Any]:
    """Normalize DetectRL-X public JSON arrays.

    Binary records contain human_written_text and llm_generated_text plus
    language/model/split/domain. Ternary records may additionally contain
    llm_refined_text. Refined text is excluded by default to avoid silently
    collapsing a ternary benchmark into binary labels.
    """

    revision = _require_revision(dataset_revision)
    subset = subset.strip().lower()
    if subset not in {"binary", "ternary"}:
        raise ValueError("subset must be 'binary' or 'ternary'.")

    source = Path(input_path)
    source_sha = file_sha256(source)
    source_meta = [
        {
            "path": source.name,
            "sha256": source_sha,
            "format": f"detectrlx_{subset}_json",
        }
    ]

    def examples() -> Iterator[NormalizedExample]:
        for index, row in enumerate(_iter_json_array(source)):
            if not isinstance(row, dict):
                raise ValueError(
                    f"{source.name} item {index} must be a JSON object."
                )
            human = str(row.get("human_written_text") or "").strip()
            generated = str(row.get("llm_generated_text") or "").strip()
            refined = str(row.get("llm_refined_text") or "").strip()
            if not human or not generated:
                raise ValueError(
                    f"{source.name} item {index} lacks required human/generated text."
                )

            split = _clean_optional(row.get("split")) or "unknown"
            language = _clean_optional(row.get("lang"))
            domain = _clean_optional(row.get("domain"))
            generator = _clean_optional(row.get("model"))
            pair_id = _stable_id(
                "DetectRL-X",
                revision,
                source_sha,
                index,
                split,
                language,
                domain,
                generator,
            )

            common = {
                "dataset": "DetectRL-X",
                "dataset_revision": revision,
                "split": split,
                "source_id": pair_id,
                "language": language,
                "domain": domain,
                "source_file_sha256": source_sha,
            }
            yield NormalizedExample(
                schema=NORMALIZED_SCHEMA,
                sample_id=_stable_id(pair_id, "human"),
                label="human",
                text=human,
                generator=None,
                transformation="none",
                metadata={"subset": subset},
                **common,
            )
            yield NormalizedExample(
                schema=NORMALIZED_SCHEMA,
                sample_id=_stable_id(pair_id, "generated"),
                label="ai",
                text=generated,
                generator=generator,
                transformation="generated",
                metadata={"subset": subset},
                **common,
            )

            if refined and include_refined_as_ai:
                yield NormalizedExample(
                    schema=NORMALIZED_SCHEMA,
                    sample_id=_stable_id(pair_id, "refined"),
                    label="ai",
                    text=refined,
                    generator=generator,
                    transformation="llm_refined",
                    metadata={
                        "subset": subset,
                        "binary_projection": True,
                    },
                    **common,
                )

    return _write_examples(
        output_path,
        examples(),
        dataset="DetectRL-X",
        dataset_revision=revision,
        source_files=source_meta,
        adapter=f"detectrlx_{subset}_json/v1",
    )
