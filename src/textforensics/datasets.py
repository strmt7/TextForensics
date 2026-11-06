"""Benchmark dataset loaders — Phase 3, datasets wave 1.

Loaders for the five wave-1 evaluation datasets (RAID, MAGE, Beemo, MixSet,
OpAI-Bench), all fetched from Hugging Face through the public
datasets-server HTTP API.

Design rules
------------
* Standard library only. The forensic core has zero third-party
  dependencies (AGENTS.md rule 14); the loaders use ``urllib`` against
  ``https://datasets-server.huggingface.co`` and never require the
  ``datasets`` package. Full-corpus parquet evaluation is future work
  (U1/U3) and would use ``datasets`` as an optional extra then.
* No network at import time. Every fetch goes through
  :class:`DatasetsServerClient`, which is constructed explicitly.
* Licence gate (hard rule). A dataset may not be fetched — not even one
  row — until its licence is resolved and recorded in its
  :class:`DatasetSpec` with ``licence_status == "verified"``. The gate is
  enforced in code (:func:`require_licence`), not by convention.
* TextForensics label convention. Normalised rows use ``label == 1`` for
  machine-generated / machine-involved text and ``label == 0`` for human
  text, matching PAN subtask 1. Datasets whose native polarity differs
  (MAGE: 0 = machine, 1 = human) are flipped by their mapper, and the
  flip is documented on the mapper, not hidden.
* No raw text leaves the cache. Loaders write normalised rows as JSONL to
  a local cache directory (XDG cache by default, see
  :func:`default_cache_dir`); run artifacts record hashes and counts,
  never raw text. Dataset text is never committed to the repo.
* Determinism. Samples are the first *n* rows by server row index
  (paginated, 100 rows per request); no randomness, no wall-clock in
  output. A cache manifest records source URL, fetch date, row count and
  file SHA-256 so a sample can be re-verified later.
* Disjointness. Cache files are JSONL with ``text``/``label`` fields, the
  exact format :func:`textforensics.benchmark.fingerprint_dataset` and
  :func:`textforensics.benchmark.check_disjointness` consume, so split
  disjointness is checked with the existing fail-closed machinery.

Wave-1 scope only. RealDet / CrisisFake have no verified route (no
loader), PAN 2025 is wave 2 (gated on TIRA registration), MultiSocial
was dropped by Greg's decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DATASETS_SERVER_BASE = "https://datasets-server.huggingface.co"
ROWS_PER_REQUEST = 100
DEFAULT_TIMEOUT_S = 30
DEFAULT_RETRIES = 3

# TextForensics label convention: 1 = machine-generated / machine-involved,
# 0 = human. Mirrors PAN subtask 1 (class 1 = machine, 0 = human).
LABEL_MACHINE = 1
LABEL_HUMAN = 0

# Editing regimes, using the U1 vocabulary (research §2.2).
REGIME_RAW = "raw"
REGIME_PARAPHRASED = "paraphrased"
REGIME_HUMAN_EDITED = "human-edited"
REGIME_LLM_EDITED = "llm-edited"
REGIME_MIXED_ORIGIN = "mixed-origin"

LICENCE_VERIFIED = "verified"
LICENCE_UNRESOLVED = "unresolved"


class DatasetError(Exception):
    """Base error for dataset loader failures."""


class DatasetLicenceError(DatasetError):
    """Raised when a fetch is attempted before licence resolution."""


class DatasetFetchError(DatasetError):
    """Raised when the datasets-server API cannot serve a request."""


@dataclass(frozen=True)
class DatasetSpec:
    """Static, citable facts about one benchmark dataset.

    The licence fields are the pre-download gate: ``licence_status`` must
    be ``"verified"`` (with ``licence`` naming the exact licence string
    as stated by the source) before any row may be fetched.
    """

    key: str
    name: str
    hf_id: str
    paper: str
    source_url: str
    licence: str | None
    licence_note: str
    licence_status: str
    configs: tuple[str, ...]
    splits: tuple[tuple[str, str], ...]  # (config, split) pairs
    notes: str
    citation: str


@dataclass(frozen=True)
class NormalizedRow:
    """One evaluation row in TextForensics convention.

    ``label`` is 1 for machine-generated / machine-involved text, 0 for
    human text, and None where the origin is ambiguous (mixed-origin rows
    carry their regime and coverage in ``meta`` instead of a clean label).
    ``text`` is the raw text as served; it lives only in the local cache,
    never in a run artifact.
    """

    text: str
    label: int | None
    dataset: str
    config: str
    split: str
    source_id: str
    regime: str
    meta: dict[str, Any] = field(default_factory=dict)

    def to_jsonl(self) -> dict[str, Any]:
        """Serialise for the JSONL cache (benchmark-fingerprint format)."""
        return {
            "text": self.text,
            "label": self.label,
            "dataset": self.dataset,
            "config": self.config,
            "split": self.split,
            "source_id": self.source_id,
            "regime": self.regime,
            "meta": self.meta,
        }


SPECS: dict[str, DatasetSpec] = {
    "raid": DatasetSpec(
        key="raid",
        name="RAID",
        hf_id="liamdugan/raid",
        paper="Dugan et al., ACL 2024, arXiv:2405.07940",
        source_url="https://huggingface.co/datasets/liamdugan/raid",
        licence="MIT",
        licence_note="Verified 2026-11-06 from the HF API record "
        "(license:mit), GitHub repo metadata (MIT) and the LICENSE file "
        "(Copyright (c) 2024- Liam Dugan). Caveat: the MIT text covers "
        "the distribution; the underlying human source texts (arXiv, NYT, "
        "Reddit, IMDb, Wikipedia, books, code, Czech/German news) carry "
        "their own upstream licences, which RAID does not address. "
        "Retain the copyright notice in copies. HF parquet conversion "
        "is partial (endpoint reports partial=true; viewer exposes the "
        "first 5 GB) — row counts are the loaded counts, not estimates.",
        licence_status=LICENCE_VERIFIED,
        configs=("raid", "raid_test"),
        splits=(("raid", "train"), ("raid", "extra"), ("raid_test", "test")),
        notes="Legacy-generator robustness slice (2022-23 generators). "
        "Test split is unlabelled in the CSV distribution; do NOT train "
        "on test. RAID-trained detectors evaluated on RAID test are "
        "in-distribution by construction — never present as OOD.",
        citation="Dugan et al., RAID: A Shared Benchmark for Robust "
        "Evaluation of Machine-Generated Text Detectors, ACL 2024.",
    ),
    "mage": DatasetSpec(
        key="mage",
        name="MAGE",
        hf_id="yaful/MAGE",
        paper="Li et al., arXiv:2305.13242",
        source_url="https://huggingface.co/datasets/yaful/MAGE",
        licence="Apache-2.0 (LICENSE file, repo metadata, HF tag); README "
        "badge asserts CC BY 4.0 — record both, attribute the authors",
        licence_note="Verified 2026-11-06: LICENSE file, GitHub metadata "
        "and HF API tag all say Apache-2.0, but the README licence badge "
        "reads CC BY 4.0. Both readings are permissive (no NC/ND/"
        "research-only restriction), so local evaluation is permitted "
        "under either; attribute the MAGE authors in any case. Upstream "
        "caveat as with RAID: human texts come from 10 source datasets "
        "whose own licences are not stated.",
        licence_status=LICENCE_VERIFIED,
        configs=("default",),
        splits=(
            ("default", "train"),
            ("default", "validation"),
            ("default", "test"),
        ),
        notes="Multi-generator OOD + paraphrase split. Native label "
        "polarity is INVERTED vs the TextForensics convention (0 = "
        "machine, 1 = human); the mapper flips it. Report per-testbed, "
        "never one pooled accuracy.",
        citation="Li et al., MAGE: Machine-generated Text Detection in the Wild, arXiv:2305.13242.",
    ),
    "beemo": DatasetSpec(
        key="beemo",
        name="Beemo",
        hf_id="toloka/beemo",
        paper="Artemova et al., arXiv:2411.04032, NAACL 2025",
        source_url="https://huggingface.co/datasets/toloka/beemo",
        licence="MIT (card) with field-level carve-outs: prompts + "
        "human_output from No Robots are CC-BY-NC-4.0; model_output and "
        "LLM-edited versions follow the underlying LLM licences",
        licence_note="Do NOT cite 'MIT' alone — the CC-BY-NC-4.0 carve-out "
        "on the human half is non-commercial and governs TextForensics "
        "use of human_output. Verified from the HF card (lines 522, "
        "672-680) in the Phase 3 research, 2026-11-06.",
        licence_status=LICENCE_VERIFIED,
        configs=("default",),
        splits=(("default", "train"),),
        notes="Expert-edited regime (the hard slice). One row holds "
        "several texts (human_output, model_output, human_edits, "
        "llama-3.1-70b_edits P1-P3, gpt-4o_edits P1-P3); the mapper emits "
        "one normalised row per text. 2,187 rows on HF, ~19.6k text "
        "variants in total. No train/test split — single benchmark set. "
        "Evaluate expert-edited vs LLM-edited separately; do not pool.",
        citation="Artemova et al., Beemo: Benchmark for Expert-Edited "
        "Machine-Generated Text, NAACL 2025.",
    ),
    "mixset": DatasetSpec(
        key="mixset",
        name="MixSet",
        hf_id="ONE-Lab/MixSet",
        paper="Zhang et al., NAACL 2024 Findings, arXiv:2401.05952",
        source_url="https://huggingface.co/datasets/ONE-Lab/MixSet",
        licence=None,
        licence_note="NO LICENCE FOUND anywhere checked 2026-11-06 (HF "
        "card: empty yaml metadata, no licence field; GitHub repo: no "
        "licence field, no LICENSE file; READMEs: no statement; paper is "
        "CC BY 4.0 on arXiv — that covers the paper, NOT the dataset). "
        "The authors invite evaluation use, but that is not a licence. "
        "DO NOT FETCH until clarified: contact the authors for a licence "
        "statement, or proceed only on an explicit 'evaluation use only, "
        "no redistribution, no derived artefacts' decision. The loader "
        "is code-complete and tested with mocks; live rows and run "
        "artifacts are deferred.",
        licence_status=LICENCE_UNRESOLVED,
        configs=("default",),
        splits=(("default", "train"), ("default", "test")),
        notes="Mixed-origin spine for U4 (later). AI-revised human text "
        "+ human-revised machine text; 5 operations (polish token / "
        "sentence, rewrite, adapt, humanize). Report by operation / "
        "category, never one pooled accuracy.",
        citation="Zhang et al., MixSet: A Large-Scale Dataset for "
        "Detecting Mixed Human and AI-Generated Text, NAACL 2024.",
    ),
    "opai_bench": DatasetSpec(
        key="opai_bench",
        name="OpAI-Bench",
        hf_id="OpAI-Bench1/OpAI-Bench",
        paper="Bsharat et al., arXiv:2606.06481",
        source_url="https://huggingface.co/datasets/OpAI-Bench1/OpAI-Bench",
        licence="Apache-2.0",
        licence_note="Verified 2026-11-06; the known conflict is resolved "
        "in favour of Apache-2.0: HF card 'Licensing and Reuse' section "
        "quotes Apache-2.0, HF tag is apache-2.0, README badge is "
        "Apache-2.0, and the LICENSE file is an abbreviated Apache-2.0 "
        "(37 lines — hence GitHub's 'Other (NOASSERTION)' detection "
        "artefact, which is not a competing licence). The LICENSE file "
        "closes with 'Copyright 2026 Anonymous' (anonymisation "
        "placeholder). Card notes the text is not redacted (may contain "
        "public names, emails, URLs) and the intended use is research / "
        "evaluation of AI-text detection.",
        licence_status=LICENCE_VERIFIED,
        configs=("default", "ablations"),
        splits=(
            ("default", "train"),
            ("default", "dev"),
            ("default", "test"),
            ("ablations", "train"),
            ("ablations", "dev"),
            ("ablations", "test"),
        ),
        notes="Progressive-edit spine for U4 (later). 9 versions v0-v8 "
        "per document, cumulative editing, AI sentence coverage "
        "0/15/25/40/50/60/75/90/100%. Non-monotonic detection: "
        "intermediate mixed versions (esp. v4, 50% + compression) are "
        "harder than either pure endpoint. Evaluate per-version / per-op, "
        "never only endpoints. Qwen3-8B is the held-out generator.",
        citation="Bsharat et al., OpAI-Bench: A Benchmark for Detecting "
        "Progressively AI-Edited Text, arXiv:2606.06481.",
    ),
}


def get_spec(key: str) -> DatasetSpec:
    """Return the spec for a wave-1 dataset key, or raise KeyError."""
    return SPECS[key]


def require_licence(spec: DatasetSpec) -> None:
    """Enforce the pre-download licence gate.

    Raises:
        DatasetLicenceError: If the dataset's licence is unresolved.
    """
    if spec.licence_status != LICENCE_VERIFIED or not spec.licence:
        raise DatasetLicenceError(
            f"Licence for {spec.name} ({spec.hf_id}) is unresolved: "
            f"{spec.licence_note} Resolve it and record it in the spec "
            "before any download."
        )


def default_cache_dir() -> Path:
    """Local cache directory for downloaded dataset samples.

    XDG cache by default; override with TEXTFORENSICS_DATASETS_DIR.
    The cache lives outside the repo so dataset text is never committed.
    """
    override = os.environ.get("TEXTFORENSICS_DATASETS_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "textforensics" / "datasets"


def cache_path(key: str, config: str, split: str, *, cache_dir: Path | None = None) -> Path:
    """JSONL cache file for one fetched sample."""
    root = cache_dir or default_cache_dir()
    return root / key / config / f"{split}.jsonl"


def manifest_path(key: str, config: str, split: str, *, cache_dir: Path | None = None) -> Path:
    """Manifest file next to a cache file (source, date, counts, hash)."""
    return cache_path(key, config, split, cache_dir=cache_dir).with_suffix(".manifest.json")


class DatasetsServerClient:
    """Minimal client for the Hugging Face datasets-server API.

    Uses only the standard library. The API serves parquet-converted
    datasets: ``/splits`` and ``/size`` for metadata, ``/rows`` for
    paginated row fetches (at most 100 rows per request). No state is
    kept between calls, so the client is safe to construct per use.
    """

    def __init__(
        self,
        base_url: str = DATASETS_SERVER_BASE,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        retries: int = DEFAULT_RETRIES,
        user_agent: str = "TextForensics/0.2.0 (research evaluation)",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.retries = retries
        self.user_agent = user_agent

    def _get_json(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        url = f"{self.base_url}{path}?{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                    return json.loads(response.read().decode("utf-8"))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(2**attempt)
        raise DatasetFetchError(f"GET {url} failed after {self.retries + 1} attempts: {last_error}")

    def splits(self, hf_id: str) -> list[dict[str, Any]]:
        """Return the (config, split) pairs the server knows for a dataset."""
        payload = self._get_json("/splits", {"dataset": hf_id})
        return list(payload.get("splits", []))

    def size(self, hf_id: str) -> dict[str, Any]:
        """Return the server's row/byte counts for a dataset."""
        payload = self._get_json("/size", {"dataset": hf_id})
        return dict(payload.get("size", {}))

    def rows(
        self,
        hf_id: str,
        config: str,
        split: str,
        *,
        offset: int = 0,
        length: int = ROWS_PER_REQUEST,
    ) -> list[dict[str, Any]]:
        """Fetch one page of rows (at most 100) for a config/split."""
        if length > ROWS_PER_REQUEST:
            raise ValueError(f"datasets-server serves at most {ROWS_PER_REQUEST} rows per request")
        payload = self._get_json(
            "/rows",
            {
                "dataset": hf_id,
                "config": config,
                "split": split,
                "offset": str(offset),
                "length": str(length),
            },
        )
        return [row["row"] for row in payload.get("rows", [])]


def fetch_sample(
    spec: DatasetSpec,
    config: str,
    split: str,
    n: int,
    *,
    client: DatasetsServerClient | None = None,
    cache_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Fetch the first ``n`` raw rows of a config/split, paginated.

    Enforces the licence gate. Rows are returned in server row-index
    order (deterministic); no randomness is involved. Raises
    :class:`DatasetFetchError` if the server returns fewer rows than
    requested without explanation (a short page is treated as an error,
    never silently padded).
    """
    require_licence(spec)
    if n <= 0:
        raise ValueError("n must be positive")
    client = client or DatasetsServerClient()
    rows: list[dict[str, Any]] = []
    offset = 0
    while len(rows) < n:
        before = len(rows)
        page = client.rows(
            spec.hf_id, config, split, offset=offset, length=min(ROWS_PER_REQUEST, n - len(rows))
        )
        if not page:
            raise DatasetFetchError(
                f"{spec.hf_id} {config}/{split}: server returned {len(rows)} rows, "
                f"fewer than the requested {n}"
            )
        rows.extend(page)
        offset += len(page)
        if len(rows) == before:
            # A page that adds no rows would loop forever; refuse instead.
            raise DatasetFetchError(
                f"{spec.hf_id} {config}/{split}: server page at offset "
                f"{offset - len(page)} added no rows"
            )
    return rows[:n]


def write_sample_cache(
    spec: DatasetSpec,
    config: str,
    split: str,
    normalized: list[NormalizedRow],
    *,
    cache_dir: Path | None = None,
    fetched_from: str | None = None,
) -> tuple[Path, Path]:
    """Write normalised rows as JSONL cache + manifest, return both paths.

    The manifest records the source, the fetch date, the row count and
    the SHA-256 of the cache file, so a cached sample can be re-verified
    without re-downloading.
    """
    from datetime import date

    path = cache_path(spec.key, config, split, cache_dir=cache_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(row.to_jsonl(), ensure_ascii=False, sort_keys=True) for row in normalized]
    content = "\n".join(lines) + ("\n" if lines else "")
    path.write_text(content, encoding="utf-8")
    file_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    manifest = {
        "dataset": spec.key,
        "hf_id": spec.hf_id,
        "config": config,
        "split": split,
        "licence": spec.licence,
        "fetched_from": fetched_from or DATASETS_SERVER_BASE,
        "fetch_date": date.today().isoformat(),
        "rows": len(normalized),
        "file": path.name,
        "file_sha256": file_sha256,
    }
    manifest_file = manifest_path(spec.key, config, split, cache_dir=cache_dir)
    manifest_file.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path, manifest_file


def read_sample_cache(
    spec: DatasetSpec,
    config: str,
    split: str,
    *,
    cache_dir: Path | None = None,
) -> list[NormalizedRow]:
    """Read normalised rows back from a JSONL cache file."""
    path = cache_path(spec.key, config, split, cache_dir=cache_dir)
    if not path.exists():
        raise FileNotFoundError(f"No cached sample for {spec.key} {config}/{split}: {path}")
    rows: list[NormalizedRow] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        rows.append(
            NormalizedRow(
                text=data["text"],
                label=data["label"],
                dataset=data["dataset"],
                config=data["config"],
                split=data["split"],
                source_id=data["source_id"],
                regime=data["regime"],
                meta=data.get("meta", {}),
            )
        )
    return rows
