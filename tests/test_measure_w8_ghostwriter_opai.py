"""Tests for scripts/measure_w8_ghostwriter_opai.py (W8 Worker C).

Only the pure helpers are tested here: partition rule, average
precision, content hashing, shingle near-duplicate grouping, and the
cluster bootstrap. No network, no detector runs, no cache writes —
the measurement script itself is exercised by its own run artifacts
(EV-20261116-dataset-ghostwriter / EV-20261116-dataset-opai-bench).
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from measure_w8_ghostwriter_opai import (  # noqa: E402
    DEV_BUCKETS,
    FINAL_BUCKETS,
    FIT_BUCKETS,
    average_precision,
    cluster_bootstrap_ci,
    content_hash,
    dedupe_by_content,
    ghostwriter_offsets,
    group_ghostwriter_rows,
    partition_counts,
    partition_of,
    sensitivity_attribution,
    shingle_jaccard,
    word_shingles,
)


def test_partition_rule_covers_all_buckets_deterministically():
    seen = Counter(partition_of(f"group-{i}") for i in range(500))
    assert set(seen) == {"fit", "dev", "final-test"}
    assert partition_of("some-group") == partition_of("some-group")
    assert frozenset(range(10)) == FIT_BUCKETS | DEV_BUCKETS | FINAL_BUCKETS
    assert not (
        FIT_BUCKETS & DEV_BUCKETS or FIT_BUCKETS & FINAL_BUCKETS or DEV_BUCKETS & FINAL_BUCKETS
    )


def test_average_precision_perfect_and_worst():
    assert average_precision([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0
    worst = average_precision([1, 1, 0, 0], [0.1, 0.2, 0.8, 0.9])
    assert 0.0 < worst < 0.5
    # Single positive ranked first scores 1.0; ranked last scores 1/n_pos... check the value.
    assert average_precision([0, 0, 1], [0.9, 0.8, 0.1]) == 1 / 3


def test_average_precision_needs_both_classes():
    try:
        average_precision([0, 0], [0.1, 0.2])
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_content_hash_stable_and_text_sensitive():
    assert content_hash("hello") == content_hash("hello")
    assert content_hash("hello") != content_hash("Hello")
    assert content_hash("hello") != content_hash("hello ")


def test_shingle_jaccard_identical_and_disjoint():
    text = "one two three four five six seven eight nine ten eleven twelve"
    shingles = word_shingles(text)
    assert len(shingles) == 5  # 12 words -> 5 8-shingles
    assert shingle_jaccard(shingles, shingles) == 1.0
    assert shingle_jaccard(shingles, set()) == 0.0
    assert word_shingles("too short") == set()


def _row(source_id, text, label=0):
    return SimpleNamespace(source_id=source_id, text=text, label=label)


def test_group_ghostwriter_rows_exact_duplicates_share_group():
    rows = [
        _row("a", "word " * 40),
        _row("b", "word " * 40),  # byte-identical text, different id
        _row("c", "completely different text " * 10),
    ]
    groups = group_ghostwriter_rows(rows)
    assert groups["a"] == groups["b"]
    assert groups["a"] != groups["c"]


def test_group_ghostwriter_rows_near_duplicates_merge():
    base = " ".join(f"token{i}" for i in range(60))
    near = " ".join(f"token{i}" for i in range(60)).replace("token59", "changed59")
    rows = [_row("a", base), _row("b", near), _row("c", "zebra " * 40)]
    groups = group_ghostwriter_rows(rows)
    assert groups["a"] == groups["b"]
    assert groups["a"] != groups["c"]


def test_dedupe_by_content_keeps_first_and_records_drop():
    rows = [
        _row("a", "same text " * 10, 1),
        _row("b", "same text " * 10, 1),
        _row("c", "other " * 10, 0),
    ]
    kept, dropped = dedupe_by_content(rows, pool_label="test")
    assert [r.source_id for r in kept] == ["a", "c"]
    assert len(dropped) == 1
    assert dropped[0]["source_id"] == "b"
    assert dropped[0]["duplicates_kept_source_id"] == "a"


def test_ghostwriter_offsets_disjoint_from_u1_grid():
    from textforensics.datasets import sample_offsets

    new = ghostwriter_offsets()
    assert len(new) == 2000
    assert len(set(new)) == 2000
    assert not (set(new) & set(sample_offsets(332224, 500)))


def test_partition_counts_counts_labels_only():
    rows = [
        (_row("a", "x " * 10, 0), "fit"),
        (_row("b", "y " * 10, 1), "final-test"),
        (_row("c", "z " * 10, None), "final-test"),
    ]
    counts = partition_counts(rows)
    assert counts["fit"] == {"rows": 1, "n_human": 1, "n_ai": 0, "n_unlabelled": 0}
    assert counts["final-test"] == {"rows": 2, "n_human": 0, "n_ai": 1, "n_unlabelled": 1}
    assert counts["dev"] == {"rows": 0, "n_human": 0, "n_ai": 0, "n_unlabelled": 0}


def _scored(source_id, score, reliability, domain="student_essays", lang="en-EN"):
    row = SimpleNamespace(source_id=source_id, meta={"domain": domain, "lang": lang})
    return {"row": row, "score": score, "reliability": reliability}


def test_sensitivity_attribution_flags_u1_top_row():
    human = [
        _scored("u1-row", 0.674, 0.7746),
        _scored("new-row-1", 0.6496, 0.7895),
        _scored("new-row-2", 0.6445, 0.8307),
    ]
    cache_of = {
        "u1-row": "train.jsonl",
        "new-row-1": "train-2000.jsonl",
        "new-row-2": "train-2000.jsonl",
    }
    detail = sensitivity_attribution(human, cache_of)
    assert detail["top_human_row"]["is_u1_row"] is True
    assert detail["top_human_row"]["score"] == 0.674
    assert detail["new_sample_human_rows_in_final_test"] == 2
    assert detail["new_sample_max_human_score"] == 0.6496
    assert detail["new_sample_k_at_threshold_0_66"] == 0


def test_sensitivity_attribution_fresh_top_row():
    human = [_scored("new-row-1", 0.66, 0.9), _scored("new-row-2", 0.5, 0.9)]
    cache_of = {"new-row-1": "train-2000.jsonl", "new-row-2": "train-2000.jsonl"}
    detail = sensitivity_attribution(human, cache_of)
    assert detail["top_human_row"]["is_u1_row"] is False
    assert detail["new_sample_k_at_threshold_0_66"] == 1


def test_cluster_bootstrap_ci_contains_point_estimate():
    labels = [0, 0, 1, 1] * 25
    scores = [0.1, 0.2, 0.8, 0.9] * 25
    groups = [f"g{i % 10}" for i in range(100)]
    result = cluster_bootstrap_ci("auroc", labels, scores, groups, resamples=100)
    assert result["value"] == 1.0
    assert result["ci_lower"] <= result["value"] <= result["ci_upper"]
    assert result["resamples"] + result["resamples_skipped_no_class"] == 100
