import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from textforensics.benchmark import (
    DatasetFingerprint,
    DatasetFormatError,
    _compute_content_hash,
    _compute_sample_hashes,
    _iter_jsonl_samples,
    _load_scores,
    _metrics,
    benchmark_jsonl,
    benchmark_with_calibration_jsonl,
    calibrate_threshold_jsonl,
    check_disjointness,
    dataset_sha256,
    fingerprint_dataset,
    load_calibration_artifact,
    load_fingerprint,
    save_fingerprint,
    validate_calibration_artifact,
    validate_disjointness,
    verify_fingerprint,
)

HUMAN = (
    "I ran the test twice this morning. The first result looked wrong, "
    "so I changed the cable and wrote the new values in my notebook."
)
AI = (
    "Furthermore, it is important to note that this robust solution "
    "seamlessly unlocks the potential of an ever-evolving landscape."
)


def write_dataset(path: Path, human_suffix: str = "", ai_suffix: str = "") -> None:
    rows = [
        {"label": "human", "text": HUMAN + human_suffix},
        {"label": "human", "text": HUMAN + " Another observation." + human_suffix},
        {"label": "ai", "text": AI + ai_suffix},
        {"label": "ai", "text": AI + " Moreover, this approach is multifaceted." + ai_suffix},
    ]
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


class BenchmarkTests(unittest.TestCase):
    def test_dataset_fingerprint_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            first = dataset_sha256(path)
            second = dataset_sha256(path)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 64)

    def test_invalid_jsonl_fails_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label":"human"}\n', encoding="utf-8")
            with self.assertRaises(DatasetFormatError):
                benchmark_jsonl(path)

    def test_calibration_artifact_is_explicitly_calibration_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            self.assertEqual(
                artifact["mode"],
                "calibration_only_not_final_evaluation",
            )
            self.assertEqual(
                artifact["calibration_dataset_sha256"],
                dataset_sha256(path),
            )
            validate_calibration_artifact(artifact)

    def test_same_dataset_is_rejected_for_held_out_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            with self.assertRaises(ValueError):
                benchmark_with_calibration_jsonl(path, artifact)

    def test_separate_evaluation_dataset_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            calibration = Path(tmp) / "calibration.jsonl"
            evaluation = Path(tmp) / "evaluation.jsonl"
            write_dataset(calibration)
            write_dataset(
                evaluation,
                human_suffix=" This is the evaluation split.",
                ai_suffix=" This is a separate evaluation sample.",
            )
            artifact = calibrate_threshold_jsonl(calibration, target_fpr=0.0)
            result = benchmark_with_calibration_jsonl(
                evaluation,
                artifact,
            )
            self.assertEqual(result["mode"], "held_out_evaluation")
            self.assertNotEqual(
                result["dataset_sha256"],
                result["calibration_dataset_sha256"],
            )
            self.assertIn("false_positive_rate", result)
            self.assertIn("true_positive_rate", result)

    def test_mismatched_detector_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calibration.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path)
            artifact["detector_version"] = "wrong"
            with self.assertRaises(ValueError):
                validate_calibration_artifact(artifact)

    def test_fixed_threshold_benchmark_is_labeled_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            result = benchmark_jsonl(path, threshold=0.5)
            self.assertEqual(result["mode"], "diagnostic_fixed_threshold")
            self.assertEqual(result["evaluated"], 4)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Mutation kill tests (Phase 5 survivors wave, full 909-item session on
# textforensics.benchmark at 8e6ffd1: 909 total, 237 killed, 672 surviving).
# Each test below pins exact observable behaviour — a count, a metric
# value, an error message, or a raised exception — that distinguishes the
# original from one or more surviving mutants. Indices [n] refer to the
# classification table in the wave report.
# ---------------------------------------------------------------------------

HUMAN_HIGH = (
    "Furthermore, it is important to note that this robust solution "
    "seamlessly unlocks the potential of an ever-evolving landscape. "
    "I wrote this myself in my notebook after running the test twice "
    "this morning."
)
AI_LOW = (
    "I ran the test twice this morning. The first result looked wrong, "
    "so I changed the cable and wrote the new values in my notebook."
)


def write_rows(path: Path, rows) -> None:
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def write_calibration_fixture(path: Path) -> None:
    """Six rows with known scores: humans 0.2791 / 0.177 / 0.6719,
    ais 0.6628 / 0.4808 / 0.2791 (see _load_scores)."""
    write_rows(
        path,
        [
            {"label": "human", "text": HUMAN},
            {"label": "human", "text": HUMAN + " Another observation."},
            {"label": "human", "text": HUMAN_HIGH},
            {"label": "ai", "text": AI},
            {"label": "ai", "text": AI + " Moreover, this approach is multifaceted."},
            {"label": "ai", "text": AI_LOW},
        ],
    )


class BenchmarkMutationKillTests(unittest.TestCase):
    """Behaviour tests that distinguish the original benchmark.py from each
    killable surviving cosmic-ray mutant in the Phase 5 survivors batch.
    Every assertion is an exact observable value, never merely that a call
    succeeds. Annotation BitOr mutants (165) and the four chunk-size
    NumberReplacer mutants are equivalent, not killable; see
    mutation-baseline.toml.
    """

    # -- _metrics exact values ([2]-[9], [49]-[82], [115], [117]-[238],
    #    [415]-[500], [522]-[555], [559]-[573], [669]) --------------------

    def test_metrics_mixed_rows_exact_values(self):
        # tp=2, fp=2, tn=1, fn=1, total 6.
        rows = [
            ("ai", 0.9),
            ("ai", 0.8),
            ("ai", 0.2),
            ("human", 0.9),
            ("human", 0.7),
            ("human", 0.3),
        ]
        result = _metrics(rows, 0.5)
        self.assertEqual(result["evaluated"], 6)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (2, 2, 1, 1))
        self.assertEqual(result["accuracy"], 0.5)
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["true_positive_rate"], 0.6667)
        self.assertEqual(result["false_positive_rate"], 0.6667)
        self.assertEqual(result["false_negative_rate"], 0.3333)
        self.assertEqual(result["specificity"], 0.3333)
        self.assertEqual(result["threshold"], 0.5)

    def test_metrics_balanced_rows_exact_values(self):
        # tp=fp=tn=fn=3, total 12: every metric is 0.5 and every
        # (x + y) sum is 6, which no other binary operator reproduces
        # (x|y, x&y, x^y, x-y, x*y, x/y, x//y, x%y, x**y, x<<y, x>>y
        # all differ from 6 for x == y == 3).
        rows = (
            [("ai", 0.9), ("ai", 0.8), ("ai", 0.7)]
            + [("ai", 0.2), ("ai", 0.1), ("ai", 0.0)]
            + [("human", 0.9), ("human", 0.8), ("human", 0.7)]
            + [("human", 0.2), ("human", 0.1), ("human", 0.0)]
        )
        result = _metrics(rows, 0.5)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (3, 3, 3, 3))
        self.assertEqual(result["accuracy"], 0.5)
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["true_positive_rate"], 0.5)
        self.assertEqual(result["false_positive_rate"], 0.5)
        self.assertEqual(result["false_negative_rate"], 0.5)
        self.assertEqual(result["specificity"], 0.5)

    def test_metrics_empty_rows_return_zero(self):
        result = _metrics([], 0.5)
        self.assertEqual(result["evaluated"], 0)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (0, 0, 0, 0))
        self.assertEqual(result["accuracy"], 0.0)
        self.assertEqual(result["precision"], 0.0)
        self.assertEqual(result["true_positive_rate"], 0.0)
        self.assertEqual(result["false_positive_rate"], 0.0)
        self.assertEqual(result["false_negative_rate"], 0.0)
        self.assertEqual(result["specificity"], 0.0)

    def test_metrics_score_equal_to_threshold_counts_as_ai(self):
        # The boundary case: score == threshold is "ai" (>=), which
        # kills the GtE_Gt / GtE_NotEq / GtE_IsNot replacements.
        result = _metrics([("ai", 0.5), ("human", 0.5)], 0.5)
        self.assertEqual((result["tp"], result["fp"]), (1, 1))

    def test_metrics_nonfinite_threshold_raises(self):
        with self.assertRaises(ValueError):
            _metrics([("ai", 0.9)], float("inf"))

    # -- _load_scores strict / non-strict ([0], [1], [28], [39]-[48],
    #    [504], [611]-[614], [620] is equivalent, see baseline) ----------

    def test_load_scores_invalid_json_strict_raises_dataset_format_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label": "human", "text": "x"}\nnot json\n', encoding="utf-8")
            with self.assertRaisesRegex(DatasetFormatError, r"Line 2 is not valid JSON\."):
                _load_scores(path)

    def test_load_scores_invalid_json_line_number_uses_one_based_count(self):
        # enumerate(start=1): a bad line in third position reports Line 3.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n'
                '{"label": "ai", "text": "' + AI + '"}\n'
                "{oops}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DatasetFormatError, r"Line 3 is not valid JSON\."):
                _load_scores(path)

    def test_load_scores_invalid_json_non_strict_skips_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            write_dataset(path)
            with path.open("a", encoding="utf-8") as handle:
                handle.write("not json\n")
            rows, skipped = _load_scores(path, strict=False)
            self.assertEqual(len(rows), 4)
            self.assertEqual(skipped, 1)

    def test_load_scores_non_dict_row_strict_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text(
                '[1, 2]\n{"label": "human", "text": "' + HUMAN + '"}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(DatasetFormatError, r"Line 1 must be a JSON object\."):
                _load_scores(path)

    def test_load_scores_non_dict_row_non_strict_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n[1, 2]\n'
                '{"label": "ai", "text": "' + AI + '"}\n',
                encoding="utf-8",
            )
            rows, skipped = _load_scores(path, strict=False)
            self.assertEqual(len(rows), 2)
            self.assertEqual(skipped, 1)

    def test_load_scores_bad_label_strict_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"label": "other", "text": "' + HUMAN + '"}\n', encoding="utf-8")
            with self.assertRaisesRegex(DatasetFormatError, r"Line 1 requires label 'human'/'ai'"):
                _load_scores(path)

    def test_load_scores_bad_label_non_strict_skips_mid_file(self):
        # The bad row sits mid-file: a continue->break mutant would drop
        # the valid rows after it.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n'
                '{"label": "other", "text": "nonsense"}\n'
                '{"label": "ai", "text": "' + AI + '"}\n',
                encoding="utf-8",
            )
            rows, skipped = _load_scores(path, strict=False)
            self.assertEqual(len(rows), 2)
            self.assertEqual(skipped, 1)

    def test_load_scores_missing_or_empty_text_non_strict_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            path.write_text(
                '{"label": "human"}\n'
                '{"label": "human", "text": "   "}\n'
                '{"label": "human", "text": 42}\n'
                '{"label": "human", "text": "' + HUMAN + '"}\n',
                encoding="utf-8",
            )
            rows, skipped = _load_scores(path, strict=False)
            self.assertEqual(len(rows), 1)
            self.assertEqual(skipped, 3)

    def test_load_scores_blank_lines_are_skipped_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blank.jsonl"
            path.write_text(
                '\n{"label": "human", "text": "' + HUMAN + '"}\n\n'
                '{"label": "ai", "text": "' + AI + '"}\n\n',
                encoding="utf-8",
            )
            rows, skipped = _load_scores(path, strict=False)
            self.assertEqual(len(rows), 2)
            self.assertEqual(skipped, 0)

    def test_load_scores_label_is_normalised(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.jsonl"
            path.write_text(
                '{"label": " Human ", "text": "' + HUMAN + '"}\n'
                '{"label": "AI", "text": "' + AI + '"}\n',
                encoding="utf-8",
            )
            rows, skipped = _load_scores(path)
            self.assertEqual([label for label, _ in rows], ["human", "ai"])
            self.assertEqual(skipped, 0)

    def test_load_scores_strict_is_keyword_only(self):
        # The `*` in the signature is a real contract: passing strict
        # positionally must raise TypeError (kills the `*` -> `/` mutant).
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            with self.assertRaises(TypeError):
                _load_scores(path, False)

    # -- benchmark_jsonl defaults ([48], [49], [83], [84]) ---------------

    def test_benchmark_jsonl_default_threshold_exact_metrics(self):
        # Scores: humans 0.2791 / 0.177, ais 0.6628 / 0.4808 at the
        # default threshold 0.5 -> tp=1, fn=1, tn=2, fp=0.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            result = benchmark_jsonl(path)
            self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (1, 0, 2, 1))
            self.assertEqual(result["evaluated"], 4)
            self.assertEqual(result["accuracy"], 0.75)
            self.assertEqual(result["precision"], 1.0)
            self.assertEqual(result["true_positive_rate"], 0.5)
            self.assertEqual(result["false_positive_rate"], 0.0)
            self.assertEqual(result["false_negative_rate"], 0.5)
            self.assertEqual(result["specificity"], 1.0)
            self.assertEqual(result["skipped"], 0)

    def test_benchmark_jsonl_extreme_thresholds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            all_ai = benchmark_jsonl(path, threshold=0.0)
            self.assertEqual((all_ai["tp"], all_ai["fp"], all_ai["tn"], all_ai["fn"]), (2, 2, 0, 0))
            all_human = benchmark_jsonl(path, threshold=1.0)
            self.assertEqual(
                (all_human["tp"], all_human["fp"], all_human["tn"], all_human["fn"]),
                (0, 0, 2, 2),
            )

    def test_benchmark_jsonl_non_strict_reports_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            write_dataset(path)
            with path.open("a", encoding="utf-8") as handle:
                handle.write("not json\n")
            result = benchmark_jsonl(path, strict=False)
            self.assertEqual(result["evaluated"], 4)
            self.assertEqual(result["skipped"], 1)

    # -- calibrate_threshold_jsonl ([10], [53], [54], [58]-[61], [85],
    #    [86], [415]-[500] Div at L172/173, [556]-[586] GtE/LtE/Gt,
    #    [633], [663]-[668] USub) ----------------------------------------

    def test_calibrate_six_row_fixture_target_half(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cal.jsonl"
            write_calibration_fixture(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.5)
            self.assertEqual(artifact["recommended_threshold"], 0.4808)
            self.assertEqual(artifact["observed_false_positive_rate"], 0.3333)
            self.assertEqual(artifact["observed_true_positive_rate"], 0.6667)
            self.assertEqual(artifact["human_samples"], 3)
            self.assertEqual(artifact["ai_samples"], 3)

    def test_calibrate_six_row_fixture_target_third(self):
        # fpr == target exactly at the winning threshold: the boundary
        # case that kills the `<=` -> `>` / `>=` / `is not` / `!=`
        # replacements at L174.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cal.jsonl"
            write_calibration_fixture(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=1 / 3)
            self.assertEqual(artifact["recommended_threshold"], 0.4808)
            self.assertEqual(artifact["observed_false_positive_rate"], 0.3333)
            self.assertEqual(artifact["observed_true_positive_rate"], 0.6667)

    def test_calibrate_six_row_fixture_target_one(self):
        # Two candidates share the top tpr (1.0) with different fpr
        # (1.0 vs 2/3): the -fpr tiebreak is load-bearing here, which
        # kills the -fpr -> fpr / not-fpr replacements at L175.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cal.jsonl"
            write_calibration_fixture(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=1.0)
            self.assertEqual(artifact["recommended_threshold"], 0.2791)
            self.assertEqual(artifact["observed_false_positive_rate"], 0.6667)
            self.assertEqual(artifact["observed_true_positive_rate"], 1.0)

    def test_calibrate_four_row_fixture_target_half(self):
        # Two candidates share tpr 1.0 with fpr 0.5 vs 0.0: the winner
        # is the fpr-0.0 one, killing the -fpr -> fpr replacement.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cal.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.5)
            self.assertEqual(artifact["recommended_threshold"], 0.4808)
            self.assertEqual(artifact["observed_false_positive_rate"], 0.0)
            self.assertEqual(artifact["observed_true_positive_rate"], 1.0)

    def test_calibrate_target_zero_picks_nextafter_max(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cal.jsonl"
            write_calibration_fixture(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            self.assertEqual(artifact["recommended_threshold"], 0.6719000000000002)
            self.assertEqual(artifact["observed_false_positive_rate"], 0.0)
            self.assertEqual(artifact["observed_true_positive_rate"], 0.0)

    def test_calibrate_target_out_of_range_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cal.jsonl"
            write_dataset(path)
            for bad in (-0.5, -1.0, 1.5, 2.0):
                with self.assertRaises(ValueError, msg=f"target_fpr={bad}"):
                    calibrate_threshold_jsonl(path, target_fpr=bad)

    def test_calibrate_requires_both_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            humans_only = Path(tmp) / "humans.jsonl"
            write_rows(
                humans_only,
                [
                    {"label": "human", "text": HUMAN},
                    {"label": "human", "text": HUMAN + " Another observation."},
                ],
            )
            with self.assertRaises(ValueError):
                calibrate_threshold_jsonl(humans_only)
            ais_only = Path(tmp) / "ais.jsonl"
            write_rows(
                ais_only,
                [
                    {"label": "ai", "text": AI},
                    {"label": "ai", "text": AI + " Moreover, this approach is multifaceted."},
                ],
            )
            with self.assertRaises(ValueError):
                calibrate_threshold_jsonl(ais_only)

    def test_calibrate_strict_default_rejects_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\nnot json\n', encoding="utf-8"
            )
            with self.assertRaises(DatasetFormatError):
                calibrate_threshold_jsonl(path)

    # -- validate_calibration_artifact / load_calibration_artifact
    #    ([11], [589]-[608] NotEq, [634], [635], [654]) ------------------

    def _valid_artifact(self, tmp: Path) -> dict:
        path = tmp / "cal.jsonl"
        write_dataset(path)
        return calibrate_threshold_jsonl(path)

    def test_validate_rejects_wrong_schema_both_directions(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for wrong in ("aaa", "zzz"):
                bad = dict(artifact, schema=wrong)
                with self.assertRaises(ValueError, msg=f"schema={wrong}"):
                    validate_calibration_artifact(bad)

    def test_validate_rejects_wrong_detector_id_both_directions(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for wrong in ("aaa", "zzz"):
                bad = dict(artifact, detector_id=wrong)
                with self.assertRaises(ValueError, msg=f"detector_id={wrong}"):
                    validate_calibration_artifact(bad)

    def test_validate_rejects_wrong_detector_version_both_directions(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for wrong in ("aaa", "zzz"):
                bad = dict(artifact, detector_version=wrong)
                with self.assertRaises(ValueError, msg=f"detector_version={wrong}"):
                    validate_calibration_artifact(bad)

    def test_validate_accepts_fresh_equal_strings(self):
        # The validated strings are built dynamically so they are equal
        # in value but distinct objects: an `is not` replacement for
        # `!=` would wrongly reject them.
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            fresh = dict(artifact)
            fresh["schema"] = "".join(["textforensics.calibration", "/v1"])
            fresh["detector_id"] = "".join(["textforensics/builtin", "-heuristic"])
            fresh["detector_version"] = "".join(["0", ".1.0"])
            validate_calibration_artifact(fresh)

    def test_validate_missing_required_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for field in (
                "schema",
                "detector_id",
                "detector_version",
                "recommended_threshold",
                "calibration_dataset_sha256",
            ):
                bad = dict(artifact)
                del bad[field]
                with self.assertRaisesRegex(ValueError, field, msg=f"missing {field}"):
                    validate_calibration_artifact(bad)

    def test_validate_rejects_bool_and_non_numeric_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for bad_threshold in (True, False, "0.5", None):
                bad = dict(artifact, recommended_threshold=bad_threshold)
                with self.assertRaises(ValueError, msg=f"threshold={bad_threshold!r}"):
                    validate_calibration_artifact(bad)

    def test_validate_rejects_non_finite_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for bad_threshold in (float("inf"), float("nan")):
                bad = dict(artifact, recommended_threshold=bad_threshold)
                with self.assertRaises(ValueError, msg=f"threshold={bad_threshold!r}"):
                    validate_calibration_artifact(bad)

    def test_validate_rejects_bad_fingerprint_lengths(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for bad_fp in ("a" * 63, "a" * 65):
                bad = dict(artifact, calibration_dataset_sha256=bad_fp)
                with self.assertRaises(ValueError, msg=f"fingerprint len={len(bad_fp)}"):
                    validate_calibration_artifact(bad)

    def test_validate_rejects_non_hex_and_non_string_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            for bad_fp in ("g" * 64, "G" * 64, 123, None):
                bad = dict(artifact, calibration_dataset_sha256=bad_fp)
                with self.assertRaises(ValueError, msg=f"fingerprint={bad_fp!r}"):
                    validate_calibration_artifact(bad)

    def test_load_calibration_artifact_rejects_non_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact.json"
            path.write_text("[1, 2]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be a JSON object"):
                load_calibration_artifact(path)

    def test_load_calibration_artifact_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            path = Path(tmp) / "artifact.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            loaded = load_calibration_artifact(path)
            self.assertEqual(loaded, artifact)

    def test_load_calibration_artifact_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError):
            load_calibration_artifact(Path(tmp) / "nope.json")

    # -- benchmark_with_calibration_jsonl ([505], [534], [638]) ----------

    def test_held_out_evaluation_with_greater_sha_succeeds(self):
        # The evaluation file's sha256 sorts ABOVE the calibration
        # file's sha256, so an `==` -> `>=` replacement would wrongly
        # reject it as the same dataset.
        with tempfile.TemporaryDirectory() as tmp:
            calibration = Path(tmp) / "calibration.jsonl"
            evaluation = Path(tmp) / "evaluation.jsonl"
            write_dataset(calibration)
            write_dataset(
                evaluation,
                human_suffix=" eval 1",
                ai_suffix=" eval 1",
            )
            self.assertGreater(dataset_sha256(evaluation), dataset_sha256(calibration))
            artifact = calibrate_threshold_jsonl(calibration, target_fpr=0.0)
            result = benchmark_with_calibration_jsonl(evaluation, artifact)
            self.assertEqual(result["mode"], "held_out_evaluation")

    def test_held_out_evaluation_allows_same_dataset_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            result = benchmark_with_calibration_jsonl(path, artifact, allow_same_dataset=True)
            self.assertEqual(result["mode"], "held_out_evaluation")

    def test_benchmark_with_calibration_strict_is_keyword_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            with self.assertRaises(TypeError):
                benchmark_with_calibration_jsonl(path, artifact, False)

    # -- DatasetFingerprint ([12], [13], [64], [65], [66], [67], [91],
    #    [92], [113], [114], [511]-[521], [640], [641], [655]) -----------

    def test_fingerprint_defaults(self):
        fp = DatasetFingerprint(name="RAID", version="1.0", split="test", dataset_hash="x" * 64)
        self.assertEqual(fp.sample_count, 0)
        self.assertEqual(fp.filters, {})
        self.assertEqual(fp.content_hashes, ())
        self.assertEqual(fp.dataset_hash, "x" * 64)
        self.assertTrue(fp.created_at)

    def test_fingerprint_is_frozen_and_slotted(self):
        fp = DatasetFingerprint(name="RAID", version="1.0", split="test", dataset_hash="x" * 64)
        with self.assertRaises(AttributeError):
            fp.name = "other"
        self.assertFalse(hasattr(fp, "__dict__"))

    def test_fingerprint_post_init_preserves_explicit_timestamp(self):
        fp = DatasetFingerprint(
            name="RAID",
            version="1.0",
            split="test",
            dataset_hash="x" * 64,
            created_at="2026-01-02T03:04:05+00:00",
        )
        self.assertEqual(fp.created_at, "2026-01-02T03:04:05+00:00")

    def test_fingerprint_to_dict_exact(self):
        fp = DatasetFingerprint(
            name="RAID",
            version="1.0",
            split="test",
            dataset_hash="a" * 64,
            filters={"domain": "news"},
            sample_count=2,
            content_hashes=("h1", "h2"),
            created_at="2026-01-02T03:04:05+00:00",
        )
        self.assertEqual(
            fp.to_dict(),
            {
                "schema": "textforensics.dataset-fingerprint/v1",
                "name": "RAID",
                "version": "1.0",
                "split": "test",
                "filters": {"domain": "news"},
                "sample_count": 2,
                "content_hashes": ["h1", "h2"],
                "dataset_hash": "a" * 64,
                "created_at": "2026-01-02T03:04:05+00:00",
            },
        )

    def test_fingerprint_from_dict_missing_field_names_it(self):
        data = {"name": "RAID", "version": "1.0", "split": "test"}
        with self.assertRaisesRegex(ValueError, r"Missing required fields: dataset_hash"):
            DatasetFingerprint.from_dict(data)

    def test_fingerprint_from_dict_missing_each_field(self):
        full = {
            "name": "RAID",
            "version": "1.0",
            "split": "test",
            "dataset_hash": "a" * 64,
        }
        for field in ("name", "version", "split", "dataset_hash"):
            data = dict(full)
            del data[field]
            with self.assertRaisesRegex(
                ValueError, rf"Missing required fields: {field}", msg=f"missing {field}"
            ):
                DatasetFingerprint.from_dict(data)

    def test_fingerprint_from_dict_defaults(self):
        fp = DatasetFingerprint.from_dict(
            {"name": "RAID", "version": "1.0", "split": "test", "dataset_hash": "a" * 64}
        )
        self.assertEqual(fp.sample_count, 0)
        self.assertEqual(fp.filters, {})
        self.assertEqual(fp.content_hashes, ())
        self.assertTrue(fp.created_at)

    def test_fingerprint_from_dict_round_trip(self):
        fp = DatasetFingerprint(
            name="RAID",
            version="2.0",
            split="calibration",
            dataset_hash="b" * 64,
            filters={"lang": "en"},
            sample_count=7,
            content_hashes=("h1", "h2"),
            created_at="2026-01-02T03:04:05+00:00",
        )
        restored = DatasetFingerprint.from_dict(fp.to_dict())
        self.assertEqual(restored, fp)

    # -- _compute_content_hash / _compute_sample_hashes / _iter_jsonl_samples
    #    ([14]-[19], [95]-[102], [116], [620]-[625] except equivalents,
    #    [642], [644], [645] are equivalent, see baseline, [656]-[658],
    #    [670], [671]) -----------------------------------------------------

    def test_compute_content_hash_is_canonical_json(self):
        text = "caf\u00e9 \u2603"
        expected = hashlib.sha256(
            json.dumps(
                {"text": text}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(_compute_content_hash(text), expected)

    def test_compute_content_hash_non_ascii_is_not_escaped(self):
        # ensure_ascii=False: the raw non-ASCII bytes are hashed, so a
        # mutant flipping ensure_ascii to True changes the digest.
        ascii_hash = _compute_content_hash("hello")
        non_ascii_hash = _compute_content_hash("caf\u00e9")
        self.assertNotEqual(ascii_hash, non_ascii_hash)
        expected = hashlib.sha256('{"text":"caf\u00e9"}'.encode("utf-8")).hexdigest()
        self.assertEqual(non_ascii_hash, expected)

    def test_iter_jsonl_samples_yields_rows_and_skips_blanks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            path.write_text('\n{"a": 1}\n\n{"b": 2}\n', encoding="utf-8")
            self.assertEqual(list(_iter_jsonl_samples(path)), [{"a": 1}, {"b": 2}])

    def test_iter_jsonl_samples_invalid_json_names_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text('{"a": 1}\n{oops}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"Line 2 is not valid JSON:"):
                list(_iter_jsonl_samples(path))

    def test_compute_sample_hashes_counts_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            hashes, count = _compute_sample_hashes(path)
            self.assertEqual(count, 4)
            self.assertEqual(len(hashes), 4)
            self.assertEqual(len(set(hashes)), 4)

    def test_compute_sample_hashes_include_text_changes_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            plain, _ = _compute_sample_hashes(path)
            with_text, _ = _compute_sample_hashes(path, include_text=True)
            self.assertNotEqual(plain, with_text)

    def test_compute_sample_hashes_include_text_hashes_label_and_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            hashes, _ = _compute_sample_hashes(path, include_text=True)
            expected = hashlib.sha256(
                json.dumps(
                    {"label": "human", "text": HUMAN},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            self.assertIn(expected, hashes)

    def test_compute_sample_hashes_non_ascii_differs_by_escaping(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_rows(path, [{"label": "human", "text": "caf\u00e9 \u2603"}])
            hashes, count = _compute_sample_hashes(path, include_text=True)
            self.assertEqual(count, 1)
            expected = hashlib.sha256(
                json.dumps(
                    {"label": "human", "text": "caf\u00e9 \u2603"},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            self.assertEqual(hashes, [expected])

    def test_compute_sample_hashes_non_string_text_uses_text_only_hash(self):
        # include_text=True with a non-string text must fall back to the
        # text-only branch (kills the `and` -> `or` replacement).
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_rows(path, [{"label": "human", "text": 42}])
            hashes, count = _compute_sample_hashes(path, include_text=True)
            self.assertEqual(count, 1)
            expected = hashlib.sha256(
                json.dumps(
                    {"text": 42}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode("utf-8")
            ).hexdigest()
            self.assertEqual(hashes, [expected])

    def test_compute_sample_hashes_row_without_label_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_rows(
                path,
                [
                    {"label": "human", "text": HUMAN},
                    {"text": "no label here"},
                    {"label": "ai", "text": AI},
                ],
            )
            hashes, count = _compute_sample_hashes(path)
            self.assertEqual(count, 2)
            self.assertEqual(len(hashes), 2)

    def test_compute_sample_hashes_strict_invalid_json_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n{oops}\n', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, r"Line 2 is not valid JSON"):
                _compute_sample_hashes(path)

    def test_compute_sample_hashes_non_strict_skips_bad_lines_mid_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n{oops}\n'
                '{"label": "ai", "text": "' + AI + '"}\n',
                encoding="utf-8",
            )
            hashes, count = _compute_sample_hashes(path, strict=False)
            self.assertEqual(count, 2)
            self.assertEqual(len(hashes), 2)

    def test_compute_sample_hashes_non_dict_strict_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text("[1, 2]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"Line 1 must be a JSON object"):
                _compute_sample_hashes(path)

    def test_compute_sample_hashes_non_dict_non_strict_skips_mid_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n[1, 2]\n'
                '{"label": "ai", "text": "' + AI + '"}\n',
                encoding="utf-8",
            )
            hashes, count = _compute_sample_hashes(path, strict=False)
            self.assertEqual(count, 2)
            self.assertEqual(len(hashes), 2)

    def test_compute_sample_hashes_blank_lines_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blank.jsonl"
            path.write_text(
                '\n{"label": "human", "text": "' + HUMAN + '"}\n\n'
                '{"label": "ai", "text": "' + AI + '"}\n',
                encoding="utf-8",
            )
            hashes, count = _compute_sample_hashes(path)
            self.assertEqual(count, 2)

    def test_compute_sample_hashes_strict_is_keyword_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            with self.assertRaises(TypeError):
                _compute_sample_hashes(path, False)

    # -- fingerprint_dataset ([20], [506], [622], [626], [636], [638]) ---

    def test_fingerprint_dataset_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID", "1.0.0", "test", filters={"domain": "news"})
            self.assertEqual(fp.name, "RAID")
            self.assertEqual(fp.version, "1.0.0")
            self.assertEqual(fp.split, "test")
            self.assertEqual(fp.filters, {"domain": "news"})
            self.assertEqual(fp.sample_count, 4)
            self.assertEqual(len(fp.content_hashes), 4)
            self.assertEqual(fp.content_hashes, tuple(sorted(fp.content_hashes)))
            self.assertEqual(fp.dataset_hash, dataset_sha256(path))

    def test_fingerprint_dataset_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(FileNotFoundError):
            fingerprint_dataset(Path(tmp) / "nope.jsonl", "RAID")

    def test_fingerprint_dataset_filters_default_is_empty_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            self.assertEqual(fp.filters, {})

    def test_fingerprint_dataset_include_text_changes_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            plain = fingerprint_dataset(path, "RAID")
            with_text = fingerprint_dataset(path, "RAID", include_text=True)
            self.assertNotEqual(plain.content_hashes, with_text.content_hashes)
            self.assertEqual(plain.sample_count, with_text.sample_count)
            self.assertEqual(plain.dataset_hash, with_text.dataset_hash)

    def test_fingerprint_dataset_strict_default_rejects_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n{oops}\n', encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                fingerprint_dataset(path, "RAID")

    def test_fingerprint_dataset_same_rows_different_order_same_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path1)
            rows = [
                {"label": "ai", "text": AI + " Moreover, this approach is multifaceted."},
                {"label": "ai", "text": AI},
                {"label": "human", "text": HUMAN + " Another observation."},
                {"label": "human", "text": HUMAN},
            ]
            write_rows(path2, rows)
            fp1 = fingerprint_dataset(path1, "RAID")
            fp2 = fingerprint_dataset(path2, "RAID")
            self.assertEqual(fp1.content_hashes, fp2.content_hashes)
            self.assertEqual(fp1.sample_count, fp2.sample_count)

    # -- verify_fingerprint ([21]-[23], [31], [32], [76]-[81], [103]-[108],
    #    [587], [588], [593]-[610], [627], [647], [648], [660]) -----------

    def test_verify_fingerprint_matching_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            result = verify_fingerprint(path, fp)
            self.assertTrue(result["valid"])
            self.assertEqual(result["errors"], [])

    def test_verify_fingerprint_missing_file_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            result = verify_fingerprint(Path(tmp) / "gone.jsonl", fp)
            self.assertFalse(result["valid"])
            self.assertEqual(result["errors"], ["Dataset file not found"])

    def test_verify_fingerprint_tampered_file_reports_both_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"label": "ai", "text": AI_LOW}) + "\n")
            result = verify_fingerprint(path, fp)
            self.assertFalse(result["valid"])
            self.assertEqual(len(result["errors"]), 2)
            self.assertTrue(result["errors"][0].startswith("File hash mismatch. Expected: "))
            self.assertIn("Sample count mismatch. Expected: 4, Got: 5", result["errors"])

    def test_verify_fingerprint_hash_mismatch_message_shows_16_chars(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            wrong = fp.__class__(
                name=fp.name,
                version=fp.version,
                split=fp.split,
                filters=fp.filters,
                sample_count=fp.sample_count,
                content_hashes=fp.content_hashes,
                dataset_hash="f" * 64,
                created_at=fp.created_at,
            )
            result = verify_fingerprint(path, wrong)
            self.assertFalse(result["valid"])
            self.assertEqual(
                result["errors"],
                [f"File hash mismatch. Expected: {'f' * 16}..., Got: {fp.dataset_hash[:16]}..."],
            )

    def test_verify_fingerprint_count_mismatch_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            for wrong_count in (3, 5):
                wrong = fp.__class__(
                    name=fp.name,
                    version=fp.version,
                    split=fp.split,
                    filters=fp.filters,
                    sample_count=wrong_count,
                    content_hashes=fp.content_hashes,
                    dataset_hash=fp.dataset_hash,
                    created_at=fp.created_at,
                )
                result = verify_fingerprint(path, wrong)
                self.assertFalse(result["valid"], msg=f"sample_count={wrong_count}")
                self.assertEqual(
                    result["errors"],
                    [f"Sample count mismatch. Expected: {wrong_count}, Got: 4"],
                )

    def test_verify_fingerprint_hash_below_and_above_expected(self):
        # The `!=` -> `>` / `<` / `<=` / `>=` replacements at L520 only
        # differ from `!=` on one side of the comparison, so both
        # directions of wrong hash are exercised.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            for wrong_hash in ("0" * 64, "f" * 64):
                wrong = fp.__class__(
                    name=fp.name,
                    version=fp.version,
                    split=fp.split,
                    filters=fp.filters,
                    sample_count=fp.sample_count,
                    content_hashes=fp.content_hashes,
                    dataset_hash=wrong_hash,
                    created_at=fp.created_at,
                )
                result = verify_fingerprint(path, wrong)
                self.assertFalse(result["valid"], msg=f"hash={wrong_hash[:4]}...")
                self.assertEqual(len(result["errors"]), 1)

    def test_verify_fingerprint_invalid_json_reports_count_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n{oops}\n', encoding="utf-8"
            )
            fp = fingerprint_dataset(path, "RAID", strict=False)
            result = verify_fingerprint(path, fp)
            self.assertFalse(result["valid"])
            self.assertEqual(len(result["errors"]), 1)
            self.assertTrue(result["errors"][0].startswith("Failed to count samples: "))

    def test_verify_fingerprint_directory_reports_hash_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            result = verify_fingerprint(Path(tmp), fp)
            self.assertFalse(result["valid"])
            self.assertEqual(len(result["errors"]), 1)
            self.assertTrue(result["errors"][0].startswith("Failed to compute file hash: "))

    def test_verify_fingerprint_strict_default_rejects_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            write_rows(
                path,
                [
                    {"label": "human", "text": HUMAN},
                    {"label": "ai", "text": AI},
                ],
            )
            fp = fingerprint_dataset(path, "RAID")
            with path.open("a", encoding="utf-8") as handle:
                handle.write("{oops}\n")
            # The file now has 2 good rows + 1 bad line: the hash no
            # longer matches AND strict counting fails, so verification
            # reports both failures.
            result = verify_fingerprint(path, fp)
            self.assertFalse(result["valid"])
            self.assertEqual(len(result["errors"]), 2)
            self.assertTrue(result["errors"][1].startswith("Failed to count samples: "))

    # -- check_disjointness / validate_disjointness ([24], [26], [27],
    #    [33], [34], [109], [110], [125]-[141], [239]-[249], [628]-[632],
    #    [649], [650], [662], [669] is in _metrics) ----------------------

    def test_disjoint_datasets_are_disjoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path1)
            write_dataset(path2, human_suffix=" eval", ai_suffix=" eval")
            fp1 = fingerprint_dataset(path1, "A")
            fp2 = fingerprint_dataset(path2, "B")
            result = check_disjointness(path1, fp1, path2, fp2)
            self.assertTrue(result["disjoint"])
            self.assertEqual(result["shared_samples"], 0)
            self.assertEqual(result["shared_hashes"], [])
            self.assertTrue(result["verified"])
            self.assertEqual(result["errors"], [])

    def test_overlapping_datasets_report_shared_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path1)
            write_rows(
                path2,
                [
                    {"label": "human", "text": HUMAN},
                    {"label": "ai", "text": AI + " different tail"},
                ],
            )
            fp1 = fingerprint_dataset(path1, "A")
            fp2 = fingerprint_dataset(path2, "B")
            result = check_disjointness(path1, fp1, path2, fp2)
            self.assertFalse(result["disjoint"])
            self.assertEqual(result["shared_samples"], 1)
            self.assertEqual(
                result["shared_hashes"], sorted(set(fp1.content_hashes) & set(fp2.content_hashes))
            )
            self.assertTrue(result["verified"])

    def test_disjointness_with_itself_is_fully_shared(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "A")
            result = check_disjointness(path, fp, path, fp)
            self.assertFalse(result["disjoint"])
            self.assertEqual(result["shared_samples"], 4)
            self.assertEqual(len(result["shared_hashes"]), 4)

    def test_disjointness_missing_path1_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path2)
            fp2 = fingerprint_dataset(path2, "B")
            dummy = DatasetFingerprint(name="A", version="1", split="t", dataset_hash="x" * 64)
            result = check_disjointness(Path(tmp) / "gone.jsonl", dummy, path2, fp2)
            self.assertFalse(result["disjoint"])
            self.assertFalse(result["verified"])
            self.assertEqual(len(result["errors"]), 1)
            self.assertTrue(result["errors"][0].startswith("Could not compute hashes for path1: "))
            self.assertEqual(result["warnings"], result["errors"])

    def test_disjointness_missing_path2_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            write_dataset(path1)
            fp1 = fingerprint_dataset(path1, "A")
            dummy = DatasetFingerprint(name="B", version="1", split="t", dataset_hash="x" * 64)
            result = check_disjointness(path1, fp1, Path(tmp) / "gone.jsonl", dummy)
            self.assertFalse(result["disjoint"])
            self.assertFalse(result["verified"])
            self.assertEqual(len(result["errors"]), 1)
            self.assertTrue(result["errors"][0].startswith("Could not compute hashes for path2: "))

    def test_disjointness_bad_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            path1.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\n{oops}\n', encoding="utf-8"
            )
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path2)
            fp2 = fingerprint_dataset(path2, "B")
            dummy = DatasetFingerprint(name="A", version="1", split="t", dataset_hash="x" * 64)
            result = check_disjointness(path1, dummy, path2, fp2)
            self.assertFalse(result["disjoint"])
            self.assertFalse(result["verified"])

    def test_disjointness_strict_is_keyword_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path1)
            write_dataset(path2)
            fp1 = fingerprint_dataset(path1, "A")
            fp2 = fingerprint_dataset(path2, "B")
            with self.assertRaises(TypeError):
                check_disjointness(path1, fp1, path2, fp2, False)

    def test_validate_disjointness_passes_for_disjoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path1)
            write_dataset(path2, human_suffix=" eval", ai_suffix=" eval")
            fp1 = fingerprint_dataset(path1, "A")
            fp2 = fingerprint_dataset(path2, "B")
            validate_disjointness(path1, fp1, path2, fp2)

    def test_validate_disjointness_raises_on_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path1 = Path(tmp) / "a.jsonl"
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path1)
            write_dataset(path2)
            fp1 = fingerprint_dataset(path1, "A")
            fp2 = fingerprint_dataset(path2, "B")
            with self.assertRaisesRegex(
                ValueError, r"Benchmark contamination detected: 4 overlapping"
            ):
                validate_disjointness(path1, fp1, path2, fp2)

    def test_validate_disjointness_raises_when_unverifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path2 = Path(tmp) / "b.jsonl"
            write_dataset(path2)
            fp2 = fingerprint_dataset(path2, "B")
            dummy = DatasetFingerprint(name="A", version="1", split="t", dataset_hash="x" * 64)
            with self.assertRaisesRegex(
                ValueError,
                r"Benchmark disjointness could not be verified: "
                r"Could not compute hashes for path1: .*"
                r"Refusing to treat unverifiable datasets as disjoint\.",
            ):
                validate_disjointness(Path(tmp) / "gone.jsonl", dummy, path2, fp2)

    # -- load_fingerprint / save_fingerprint ([25], [111], [112], [125],
    #    [126], [139]-[141], [151]-[153], [160]-[162], [169]-[171],
    #    [182]-[184], [200]-[202], [213]-[215], [224]-[226], [236]-[238],
    #    [623], [632], [651]-[653], [661]) --------------------------------

    def test_save_and_load_fingerprint_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID", "1.0.0", "test")
            object.__setattr__(fp, "created_at", "2026-01-02T03:04:05+00:00")
            saved = save_fingerprint(fp, Path(tmp) / "nested" / "dir" / "fp.json")
            self.assertEqual(saved, Path(tmp) / "nested" / "dir" / "fp.json")
            self.assertEqual(load_fingerprint(saved), fp)

    def test_save_fingerprint_exact_file_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = DatasetFingerprint(
                name="RAID",
                version="1.0",
                split="test",
                dataset_hash="a" * 64,
                filters={"domain": "news"},
                sample_count=2,
                content_hashes=("h1", "h2"),
                created_at="2026-01-02T03:04:05+00:00",
            )
            saved = save_fingerprint(fp, Path(tmp) / "fp.json")
            self.assertEqual(
                saved.read_text(encoding="utf-8"),
                json.dumps(fp.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            )

    def test_save_fingerprint_non_ascii_is_not_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            fp = DatasetFingerprint(
                name="caf\u00e9",
                version="1.0",
                split="test",
                dataset_hash="a" * 64,
                created_at="2026-01-02T03:04:05+00:00",
            )
            saved = save_fingerprint(fp, Path(tmp) / "fp.json")
            self.assertIn("caf\u00e9", saved.read_text(encoding="utf-8"))
            self.assertNotIn("\\u00e9", saved.read_text(encoding="utf-8"))

    def test_load_fingerprint_rejects_non_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fp.json"
            path.write_text("[1, 2]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must contain a JSON object"):
                load_fingerprint(path)

    def test_fingerprint_dataset_strict_is_keyword_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            with self.assertRaises(TypeError):
                fingerprint_dataset(path, "RAID", "1.0.0", "test", None, True, True)

    def test_verify_fingerprint_strict_is_keyword_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_dataset(path)
            fp = fingerprint_dataset(path, "RAID")
            with self.assertRaises(TypeError):
                verify_fingerprint(path, fp, False)

    # -- Second-round kills (proof run 1 left 41 unexplained: 13
    #    no-kind equivalents + 28 missed) ------------------------------

    def test_metrics_accuracy_and_precision_need_four_decimals(self):
        # tp=2, fp=1, tn=2, fn=2, total 7: accuracy 4/7 and precision
        # 2/3 both need four decimals, killing round(..., 4) -> 5 / 3.
        rows = [
            ("ai", 0.9),
            ("ai", 0.8),
            ("ai", 0.2),
            ("ai", 0.1),
            ("human", 0.9),
            ("human", 0.3),
            ("human", 0.2),
        ]
        result = _metrics(rows, 0.5)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (2, 1, 2, 2))
        self.assertEqual(result["accuracy"], 0.5714)
        self.assertEqual(result["precision"], 0.6667)

    def test_metrics_non_ai_label_counts_as_human(self):
        # _metrics treats any label other than "ai" as human. A label
        # that sorts below "ai" ("a" < "ai") kills the `label == "ai"`
        # -> `label <= "ai"` replacements at L89 and L91.
        rows = [("a", 0.9), ("human", 0.2)]
        result = _metrics(rows, 0.5)
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (0, 1, 1, 0))

    def test_load_scores_invalid_json_non_strict_mid_file(self):
        # The bad line sits mid-file: a continue->break mutant would
        # drop the valid row after it.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mixed.jsonl"
            path.write_text(
                '{"label": "human", "text": "' + HUMAN + '"}\nnot json\n'
                '{"label": "ai", "text": "' + AI + '"}\n',
                encoding="utf-8",
            )
            rows, skipped = _load_scores(path, strict=False)
            self.assertEqual(len(rows), 2)
            self.assertEqual(skipped, 1)

    def test_validate_rejects_smaller_wrong_detector_version(self):
        # "0.0.9" sorts BELOW "0.1.0": the `!=` -> `>` replacement
        # would wrongly accept it.
        with tempfile.TemporaryDirectory() as tmp:
            artifact = self._valid_artifact(Path(tmp))
            bad = dict(artifact, detector_version="0.0.9")
            with self.assertRaises(ValueError):
                validate_calibration_artifact(bad)

    def test_benchmark_with_calibration_strict_default_rejects_bad_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            write_rows(
                path,
                [
                    {"label": "human", "text": HUMAN},
                    {"label": "ai", "text": AI},
                ],
            )
            artifact = calibrate_threshold_jsonl(path, target_fpr=0.0)
            with path.open("a", encoding="utf-8") as handle:
                handle.write("not json\n")
            with self.assertRaises(DatasetFormatError):
                benchmark_with_calibration_jsonl(path, artifact)

    def test_compute_sample_hashes_unlabelled_non_ascii_row(self):
        # A LABELED row with include_text=False (the default) takes the
        # elif branch (L424): its ensure_ascii=False must hash the raw
        # non-ASCII bytes. (An unlabelled row is skipped outright.)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.jsonl"
            write_rows(path, [{"label": "human", "text": "caf\u00e9 \u2603"}])
            hashes, count = _compute_sample_hashes(path)
            self.assertEqual(count, 1)
            expected = hashlib.sha256(
                json.dumps(
                    {"text": "caf\u00e9 \u2603"},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            self.assertEqual(hashes, [expected])

    def test_verify_fingerprint_large_matching_dataset_is_valid(self):
        # 300 rows: count and sample_count are both 300, above the
        # CPython small-int cache, so the `!=` -> `is not` replacement
        # (distinct int objects) would wrongly report a mismatch.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.jsonl"
            write_rows(
                path,
                [
                    {"label": "human" if i % 2 == 0 else "ai", "text": HUMAN + f" row {i}"}
                    for i in range(300)
                ],
            )
            fp = fingerprint_dataset(path, "BIG")
            self.assertEqual(fp.sample_count, 300)
            result = verify_fingerprint(path, fp)
            self.assertTrue(result["valid"])
            self.assertEqual(result["errors"], [])

    def test_metrics_zero_denominator_component_gives_full_rate(self):
        # Guard `(a + b)` -> `(a * b)` differs when exactly one operand
        # is zero: the product is falsy while the sum is truthy.
        # fpr guard (fp=1, tn=0): 1.0, not the else-branch 0.0.
        result = _metrics([("human", 0.9), ("ai", 0.9)], 0.5)
        self.assertEqual(result["false_positive_rate"], 1.0)
        # fnr guard (fn=1, tp=0): 1.0.
        result = _metrics([("ai", 0.1)], 0.5)
        self.assertEqual(result["false_negative_rate"], 1.0)
        # tpr guard (tp=1, fn=0): 1.0.
        result = _metrics([("ai", 0.9)], 0.5)
        self.assertEqual(result["true_positive_rate"], 1.0)
