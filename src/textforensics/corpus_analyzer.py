"""Text corpus analyzer for TextForensics.

Provides corpus-level statistics, diversity metrics, and anomaly detection
across multiple documents. Useful for understanding false positive patterns
and building detector benchmarks.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "CorpusAnalyzer",
    "CorpusStats",
    "CorpusError",
]


class CorpusError(Exception):
    """Base exception for corpus analysis errors."""

    pass


@dataclass
class CorpusStats:
    """Statistics for a text corpus."""

    total_documents: int = 0
    total_words: int = 0
    total_sentences: int = 0
    total_characters: int = 0
    mean_document_length: float = 0.0
    median_document_length: float = 0.0
    stdev_document_length: float = 0.0
    vocabulary_size: int = 0
    type_token_ratio: float = 0.0
    hapax_ratio: float = 0.0  # Ratio of words appearing exactly once
    mean_sentence_length: float = 0.0
    document_lengths: list[int] = field(default_factory=list)
    top_terms: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_documents": self.total_documents,
            "total_words": self.total_words,
            "total_sentences": self.total_sentences,
            "total_characters": self.total_characters,
            "mean_document_length": self.mean_document_length,
            "median_document_length": self.median_document_length,
            "stdev_document_length": self.stdev_document_length,
            "vocabulary_size": self.vocabulary_size,
            "type_token_ratio": self.type_token_ratio,
            "hapax_ratio": self.hapax_ratio,
            "mean_sentence_length": self.mean_sentence_length,
            "document_lengths": self.document_lengths,
            "top_terms": self.top_terms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CorpusStats:
        return cls(
            total_documents=int(data.get("total_documents", 0)),
            total_words=int(data.get("total_words", 0)),
            total_sentences=int(data.get("total_sentences", 0)),
            total_characters=int(data.get("total_characters", 0)),
            mean_document_length=float(data.get("mean_document_length", 0.0)),
            median_document_length=float(data.get("median_document_length", 0.0)),
            stdev_document_length=float(data.get("stdev_document_length", 0.0)),
            vocabulary_size=int(data.get("vocabulary_size", 0)),
            type_token_ratio=float(data.get("type_token_ratio", 0.0)),
            hapax_ratio=float(data.get("hapax_ratio", 0.0)),
            mean_sentence_length=float(data.get("mean_sentence_length", 0.0)),
            document_lengths=list(data.get("document_lengths", [])),
            top_terms=[(t, c) for t, c in data.get("top_terms", [])],
        )


class CorpusAnalyzer:
    """Analyzer for text corpora with statistical and diversity metrics.

    Provides:
    - Corpus-level statistics (word/sentence counts, document lengths)
    - Vocabulary diversity metrics (type-token ratio, hapax ratio)
    - Term frequency analysis
    - Outlier detection for document length
    """

    def __init__(self, *, top_n_terms: int = 20):
        self.top_n_terms = top_n_terms
        self._documents: list[dict[str, Any]] = []
        self._term_counter = Counter()
        self._vocabulary: set[str] = set()

    def add_document(
        self,
        text: str,
        *,
        document_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Add a document to the corpus.

        Args:
            text: Document text.
            document_id: Optional document identifier.
            metadata: Optional metadata for the document.

        Returns:
            Dictionary with per-document statistics.
        """
        if not isinstance(text, str):
            raise CorpusError("Text must be a string")

        # Compute document statistics
        words = text.split()
        word_count = len(words)
        sentences = self._split_sentences(text)
        sentence_count = len(sentences)
        char_count = len(text)

        # Update corpus-level tracking
        for word in words:
            normalized = word.lower().strip(".,!?;:'\"()[]{}")
            if normalized:
                self._term_counter[normalized] += 1
                self._vocabulary.add(normalized)

        doc_stats = {
            "document_id": document_id,
            "word_count": word_count,
            "sentence_count": sentence_count,
            "character_count": char_count,
            "metadata": metadata or {},
            "content_hash": self._hash_text(text),
        }

        self._documents.append(doc_stats)
        return doc_stats

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @staticmethod
    def _split_sentences(text: str) -> list[str]:
        """Split text into sentences using simple heuristics."""
        # Simple sentence splitting on periods, exclamation marks, question marks
        import re

        sentences = re.split(r"[.!?]+[\s\n]+", text)
        return [s.strip() for s in sentences if s.strip()]

    def compute_stats(self) -> CorpusStats:
        """Compute corpus-level statistics.

        Returns:
            CorpusStats with aggregated metrics.
        """
        if not self._documents:
            return CorpusStats()

        doc_lengths = [d["word_count"] for d in self._documents]
        total_words = sum(doc_lengths)
        total_sentences = sum(d["sentence_count"] for d in self._documents)
        total_chars = sum(d["character_count"] for d in self._documents)

        # Vocabulary metrics
        total_terms = sum(self._term_counter.values())
        hapax_count = sum(1 for c in self._term_counter.values() if c == 1)
        vocabulary_size = len(self._vocabulary)
        type_token_ratio = vocabulary_size / total_terms if total_terms > 0 else 0.0
        hapax_ratio = hapax_count / vocabulary_size if vocabulary_size > 0 else 0.0

        # Document length statistics
        mean_length = statistics.mean(doc_lengths) if doc_lengths else 0.0
        median_length = statistics.median(doc_lengths) if doc_lengths else 0.0
        stdev_length = statistics.stdev(doc_lengths) if len(doc_lengths) > 1 else 0.0

        # Sentence statistics
        mean_sentence_length = total_words / total_sentences if total_sentences > 0 else 0.0

        # Top terms
        top_terms = self._term_counter.most_common(self.top_n_terms)

        return CorpusStats(
            total_documents=len(self._documents),
            total_words=total_words,
            total_sentences=total_sentences,
            total_characters=total_chars,
            mean_document_length=mean_length,
            median_document_length=median_length,
            stdev_document_length=stdev_length,
            vocabulary_size=vocabulary_size,
            type_token_ratio=type_token_ratio,
            hapax_ratio=hapax_ratio,
            mean_sentence_length=mean_sentence_length,
            document_lengths=doc_lengths,
            top_terms=top_terms,
        )

    def detect_outliers(
        self,
        *,
        method: str = "iqr",
        threshold: float = 1.5,
    ) -> list[dict[str, Any]]:
        """Detect outlier documents by length.

        Args:
            method: "iqr" or "zscore"
            threshold: Threshold for outlier detection.

        Returns:
            List of outlier document info.
        """
        if not self._documents:
            return []

        doc_lengths = [d["word_count"] for d in self._documents]
        outliers = []

        if method == "iqr":
            sorted_lengths = sorted(doc_lengths)
            n = len(sorted_lengths)
            q1_idx = n // 4
            q3_idx = 3 * n // 4
            q1 = sorted_lengths[q1_idx]
            q3 = sorted_lengths[q3_idx]
            iqr = q3 - q1
            lower_bound = q1 - threshold * iqr
            upper_bound = q3 + threshold * iqr

            for i, d in enumerate(self._documents):
                if doc_lengths[i] < lower_bound or doc_lengths[i] > upper_bound:
                    outliers.append(
                        {
                            "document_id": d["document_id"],
                            "word_count": doc_lengths[i],
                            "outlier_type": "low" if doc_lengths[i] < lower_bound else "high",
                            "bounds": (lower_bound, upper_bound),
                        }
                    )

        elif method == "zscore":
            if len(doc_lengths) < 2:
                return []
            mean = statistics.mean(doc_lengths)
            stdev = statistics.stdev(doc_lengths)
            if stdev == 0:
                return []

            for i, d in enumerate(self._documents):
                z = (doc_lengths[i] - mean) / stdev
                if abs(z) > threshold:
                    outliers.append(
                        {
                            "document_id": d["document_id"],
                            "word_count": doc_lengths[i],
                            "zscore": z,
                            "outlier_type": "low" if z < 0 else "high",
                        }
                    )

        else:
            raise CorpusError(f"Unknown outlier method: {method}")

        return outliers

    def term_frequency(self, term: str) -> int:
        """Get frequency of a specific term."""
        return self._term_counter.get(term.lower(), 0)

    def get_vocabulary(self) -> set[str]:
        """Get the corpus vocabulary."""
        return set(self._vocabulary)

    def document_count(self) -> int:
        """Get the number of documents in the corpus."""
        return len(self._documents)

    def clear(self) -> None:
        """Clear all documents and reset state."""
        self._documents.clear()
        self._term_counter.clear()
        self._vocabulary.clear()


def load_corpus_from_jsonl(path: str, analyzer: CorpusAnalyzer) -> None:
    """Load a corpus from a JSONL file.

    Expected format: one JSON object per line with 'text' field.
    """
    with open(path, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusError(f"Line {line_num}: invalid JSON") from exc

            text = row.get("text")
            if text is None:
                raise CorpusError(f"Line {line_num}: missing 'text' field")

            analyzer.add_document(
                text,
                document_id=row.get("id", f"doc_{line_num}"),
                metadata={k: v for k, v in row.items() if k != "text"},
            )


def save_stats_to_json(stats: CorpusStats, path: str) -> None:
    """Save corpus statistics to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")


def load_stats_from_json(path: str) -> CorpusStats:
    """Load corpus statistics from a JSON file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return CorpusStats.from_dict(data)
