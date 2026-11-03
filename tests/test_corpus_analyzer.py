"""Tests for Text Corpus Analyzer."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from textforensics.corpus_analyzer import (
    CorpusAnalyzer,
    CorpusError,
    CorpusStats,
    load_corpus_from_jsonl,
    load_stats_from_json,
    save_stats_to_json,
)


class TestCorpusAnalyzer:
    def test_empty_corpus(self):
        """Empty corpus should return zero stats."""
        analyzer = CorpusAnalyzer()
        stats = analyzer.compute_stats()
        assert stats.total_documents == 0
        assert stats.total_words == 0
        assert stats.vocabulary_size == 0

    def test_add_single_document(self):
        """Adding a document should track statistics."""
        analyzer = CorpusAnalyzer()
        doc = analyzer.add_document("The quick brown fox jumps over the lazy dog.")

        assert doc["word_count"] == 9
        assert doc["sentence_count"] == 1
        assert doc["content_hash"] is not None

    def test_add_multiple_documents(self):
        """Adding multiple documents should aggregate statistics."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("First document text.")
        analyzer.add_document("Second document text.")
        analyzer.add_document("Third document text.")

        assert analyzer.document_count() == 3

        stats = analyzer.compute_stats()
        assert stats.total_documents == 3
        assert stats.total_words > 0
        assert stats.vocabulary_size > 0

    def test_vocabulary_tracking(self):
        """Vocabulary should be tracked across documents."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("The cat sat on the mat.")
        analyzer.add_document("The dog sat on the rug.")

        vocab = analyzer.get_vocabulary()
        assert "cat" in vocab
        assert "dog" in vocab
        assert "sat" in vocab

    def test_type_token_ratio(self):
        """Type-token ratio should be computed."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("The quick brown fox.")
        analyzer.add_document("The lazy dog sleeps.")

        stats = analyzer.compute_stats()
        assert 0 < stats.type_token_ratio <= 1

    def test_hapax_ratio(self):
        """Hapax ratio should count unique words."""
        analyzer = CorpusAnalyzer()
        # Most words appear once = high hapax ratio
        analyzer.add_document("The quick brown fox jumps.")
        analyzer.add_document("A lazy dog sleeps deeply.")

        stats = analyzer.compute_stats()
        assert 0 < stats.hapax_ratio <= 1

    def test_top_terms(self):
        """Top terms should be most frequent."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("The cat. The cat. The cat.")
        analyzer.add_document("The dog.")

        stats = analyzer.compute_stats()
        assert len(stats.top_terms) > 0
        assert stats.top_terms[0][0] == "the"
        assert stats.top_terms[0][1] == 4

    def test_term_frequency(self):
        """Term frequency should be counted."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("Hello world. Hello again.")
        analyzer.add_document("Hello there.")

        assert analyzer.term_frequency("hello") == 3
        assert analyzer.term_frequency("world") == 1
        assert analyzer.term_frequency("nonexistent") == 0

    def test_document_lengths(self):
        """Document lengths should be tracked."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("One two three.")  # 3 words
        analyzer.add_document("Four five six seven eight.")  # 5 words

        stats = analyzer.compute_stats()
        assert stats.document_lengths == [3, 5]
        assert stats.mean_document_length == 4.0
        assert stats.median_document_length == 4.0

    def test_sentence_statistics(self):
        """Sentence statistics should be computed."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("First sentence. Second sentence. Third sentence.")

        stats = analyzer.compute_stats()
        assert stats.total_sentences == 3

    def test_mean_sentence_length(self):
        """Mean sentence length should be computed."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("Two words here. Four words are here.")

        stats = analyzer.compute_stats()
        # 7 total words / 2 sentences = 3.5
        assert stats.mean_sentence_length == 3.5

    def test_clear(self):
        """Clearing should reset the analyzer."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("Some text.")
        analyzer.clear()

        assert analyzer.document_count() == 0
        assert len(analyzer.get_vocabulary()) == 0

    def test_invalid_input(self):
        """Non-string input should raise error."""
        analyzer = CorpusAnalyzer()
        with pytest.raises(CorpusError):
            analyzer.add_document(123)


class TestOutlierDetection:
    def test_iqr_outliers(self):
        """IQR method should detect outliers."""
        analyzer = CorpusAnalyzer()
        # Add documents with varying lengths
        for i in range(10):
            text = " ".join(["word"] * (10 + i))
            analyzer.add_document(text)
        # Add extreme outlier
        analyzer.add_document(" ".join(["extreme"] * 100))

        outliers = analyzer.detect_outliers(method="iqr")
        assert len(outliers) > 0
        assert any(o["outlier_type"] == "high" for o in outliers)

    def test_zscore_outliers(self):
        """Z-score method should detect outliers."""
        analyzer = CorpusAnalyzer()
        for i in range(20):
            text = " ".join(["word"] * (10 + i % 3))
            analyzer.add_document(text)
        # Add extreme outlier
        analyzer.add_document(" ".join(["extreme"] * 500))

        outliers = analyzer.detect_outliers(method="zscore", threshold=2.0)
        assert len(outliers) > 0

    def test_no_outliers_uniform(self):
        """Uniform documents should have no outliers."""
        analyzer = CorpusAnalyzer()
        for i in range(20):
            analyzer.add_document("Same length text here.")

        outliers = analyzer.detect_outliers(method="iqr")
        assert len(outliers) == 0

    def test_unknown_method_raises(self):
        """Unknown method should raise error."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("Some text.")

        with pytest.raises(CorpusError):
            analyzer.detect_outliers(method="unknown")


class TestCorpusStats:
    def test_stats_roundtrip(self):
        """Stats serialization should preserve data."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("The quick brown fox.")
        analyzer.add_document("Jumps over the lazy dog.")

        stats = analyzer.compute_stats()
        d = stats.to_dict()

        stats2 = CorpusStats.from_dict(d)
        assert stats2.total_documents == stats.total_documents
        assert stats2.total_words == stats.total_words
        assert stats2.vocabulary_size == stats.vocabulary_size


class TestCorpusIO:
    def test_jsonl_load(self):
        """Loading from JSONL should work."""
        analyzer = CorpusAnalyzer()

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.jsonl"
            with path.open("w", encoding="utf-8") as f:
                f.write(json.dumps({"id": "doc1", "text": "First document."}) + "\n")
                f.write(json.dumps({"id": "doc2", "text": "Second document."}) + "\n")

            load_corpus_from_jsonl(str(path), analyzer)
            assert analyzer.document_count() == 2

    def test_jsonl_load_invalid(self):
        """Invalid JSONL should raise error."""
        analyzer = CorpusAnalyzer()

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.jsonl"
            with path.open("w", encoding="utf-8") as f:
                f.write("not valid json\n")

            with pytest.raises(CorpusError):
                load_corpus_from_jsonl(str(path), analyzer)

    def test_jsonl_load_missing_text(self):
        """Missing text field should raise error."""
        analyzer = CorpusAnalyzer()

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.jsonl"
            with path.open("w", encoding="utf-8") as f:
                f.write(json.dumps({"id": "doc1"}) + "\n")

            with pytest.raises(CorpusError):
                load_corpus_from_jsonl(str(path), analyzer)

    def test_stats_save_load(self):
        """Saving and loading stats should work."""
        analyzer = CorpusAnalyzer()
        analyzer.add_document("The quick brown fox.")

        stats = analyzer.compute_stats()

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stats.json"
            save_stats_to_json(stats, str(path))
            loaded = load_stats_from_json(str(path))

            assert loaded.total_documents == stats.total_documents
            assert loaded.vocabulary_size == stats.vocabulary_size


if __name__ == "__main__":
    pytest.main([__file__, "-v"])