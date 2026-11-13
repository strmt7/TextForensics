"""W1 Worker D regression tests (audit wave W1).

Findings covered (all reproduced before fixing; see the part-report):
- IF-11: explanation export retains source sentences by default.
- C03: process metadata can export literal source text while declaring
  raw text absent (shared privacy helper in sealing.py).
- C06: optional seal-record cross-check decompresses entries after
  container rejection.
- C12: ordinary malformed shapes escape verification APIs as exceptions.
- CORE-07 (W1 side): Trust Map benign-stability never ``supported``
  from an incomplete probe set (trust.py + validation.py).
- CORE-09: the streaming dataset parser accepts invalid JSON arrays.
- Worker A fallout: casefile replay of a present-but-malformed
  ``robustness`` section (the golden-file regeneration is covered by
  tests/test_trust_integration.py::GoldenCaseFileTests).

Canary markers are synthetic and disposable; no real user text is used.
"""

import copy
import hashlib
import io
import json
import unittest
import zipfile
from pathlib import Path

from textforensics import _standalone_verify as standalone
from textforensics.casefile import (
    _hash_without_seal,
    _replay_trust_map,
    seal_case_file,
    write_case_file,
)
from textforensics.casefile import (
    verify_case_file as primary_verify_case_file,
)
from textforensics.datasets import (
    DatasetFetchError,
    _check_raw_json_nesting_depth,
    _json_value_depth,
    iter_detectrl_x_rows,
)
from textforensics.explain import (
    explain_verdict,
    load_explanation_report,
    save_explanation_report,
)
from textforensics.report import build_forensic_bundle
from textforensics.sealed_bundle import (
    COMMENT_PREFIX,
    MAX_ENTRY_BYTES,
    pack_sealed_bundle,
    verify_sealed_bundle,
)
from textforensics.sealing import (
    FORBIDDEN_RAW_TEXT_KEYS,
    check_case_portability,
)
from textforensics.trust import _stability_dimension
from textforensics.validation import _live_dimensions
from textforensics.verify import (
    verify_case_file as nversion_verify_case_file,
)
from textforensics.verify import (
    verify_case_file_combined,
    verify_case_file_path_combined,
)

CANARY_A = "CANARY-W1D-7f3a9-marker-sentence-one."
CANARY_B = "CANARY-W1D-7f3a9-marker-sentence-two."
UNICODE_SENTENCE = "Ünïcödé — naïve façade ☃ test sentence here."

LONG_TEXT = (
    "The committee met on Tuesday to review the quarterly figures and "
    "discuss the outlook for the coming year. The chair opened the meeting "
    "with a summary of the previous session, and the members agreed to "
    "focus on three items: revenue, staffing, and the maintenance budget. "
    "Revenue grew modestly in the first quarter, driven by new contracts "
    "in the northern region. Staffing remains tight, and the hiring plan "
    "was approved with minor changes. The maintenance budget was reduced "
    "after a review of the supplier quotes. The meeting ended with a plan "
    "to reconvene in four weeks to review progress on each item."
)


def _bundle_dict():
    bundle = build_forensic_bundle(LONG_TEXT, ledger_path=None).to_dict()
    for result in bundle.get("detector_results", []):
        result.pop("runtime_ms", None)
    for failure in bundle.get("detector_failures", []):
        failure.pop("runtime_ms", None)
    return bundle


def _sealed_case(**kwargs):
    return seal_case_file(
        _bundle_dict(),
        deterministic=True,
        fixed_timestamp="1970-01-01T00:00:00+00:00",
        **kwargs,
    )


def _rehash(case):
    """Recompute case_sha256 after mutating an unsealed case dict."""
    case["case_sha256"] = _hash_without_seal(case)
    return case


def _varying_score_fn(text):
    if "KEY" in text:
        return 0.9
    return 0.2


def _mpl_zip(files):
    """Build a deterministic MPL-normalised STORED zip from name -> bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            info.external_attr = 0o644 << 16
            zf.writestr(info, files[name])
        manifest_bytes = files.get("manifest.json", b"")
        zf.comment = (COMMENT_PREFIX + hashlib.sha256(manifest_bytes).hexdigest()).encode("ascii")
    return buf.getvalue()


class TestIF11DefaultRedaction(unittest.TestCase):
    def _report(self):
        text = f"{CANARY_A} {CANARY_B} A third ordinary sentence here. KEY finding stated here."
        return explain_verdict(text, _varying_score_fn, detector_id="d", detector_version="1.0")

    def test_default_save_contains_no_marker_text(self):
        import tempfile

        report = self._report()
        self.assertTrue(report.segment_attribution, "fixture must attribute segments")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "explanation.json"
            save_explanation_report(report, str(path))
            saved = path.read_text(encoding="utf-8")
        self.assertNotIn(CANARY_A, saved)
        self.assertNotIn(CANARY_B, saved)
        data = json.loads(saved)
        self.assertIs(data["raw_text_included"], False)

    def test_default_dict_and_summary_contain_no_marker_text(self):
        report = self._report()
        dumped = json.dumps(report.to_dict())
        self.assertNotIn(CANARY_A, dumped)
        self.assertNotIn(CANARY_B, dumped)
        summary = json.dumps(report.summary())
        self.assertNotIn(CANARY_A, summary)
        self.assertNotIn(CANARY_B, summary)
        # The summary must not leak text through the "most_*_segment" fields.
        self.assertIsNone(report.summary()["most_ai_driving_segment"])
        self.assertIsNone(report.summary()["most_human_driving_segment"])

    def test_default_dict_keeps_indices_and_hashes_useful(self):
        report = self._report()
        data = report.to_dict()
        attributions = data["segment_attribution"]
        self.assertEqual(
            [a["segment_index"] for a in attributions],
            [a.segment_index for a in report.segment_attribution],
        )
        for entry, attribution in zip(attributions, report.segment_attribution, strict=True):
            self.assertEqual(
                entry["segment_sha256"],
                hashlib.sha256(attribution.segment_text.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(entry["segment_length"], len(attribution.segment_text))
            self.assertNotIn("segment_text", entry)
        self.assertEqual(
            [a["segment_index"] for a in data["top_ai_driving"]],
            [a.segment_index for a in report.top_ai_driving],
        )
        # Top lists cannot bypass the default redaction.
        for entry in data["top_ai_driving"] + data["top_human_driving"]:
            self.assertNotIn("segment_text", entry)

    def test_summary_keeps_index_and_hash_without_text(self):
        report = self._report()
        summary = report.summary()
        self.assertIn("most_ai_driving_segment_index", summary)
        self.assertIn("most_ai_driving_segment_sha256", summary)
        self.assertEqual(
            summary["most_ai_driving_segment_index"],
            report.top_ai_driving[0].segment_index,
        )


class TestIF11ExplicitOptIn(unittest.TestCase):
    def test_opt_in_preserves_exact_unicode_text_and_round_trips(self):
        import tempfile

        text = (
            f"{CANARY_A} {UNICODE_SENTENCE} Another ordinary sentence here. "
            "KEY finding stated here."
        )
        report = explain_verdict(text, _varying_score_fn, detector_id="d", detector_version="1.0")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "explanation.json"
            save_explanation_report(report, str(path), include_raw_text=True)
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertIs(saved["raw_text_included"], True)
            loaded = load_explanation_report(str(path))
        self.assertEqual(
            [a.segment_text for a in loaded.segment_attribution],
            [a.segment_text for a in report.segment_attribution],
        )
        self.assertIn(UNICODE_SENTENCE, [a.segment_text for a in loaded.segment_attribution])
        self.assertEqual(loaded.text_sha256, report.text_sha256)

    def test_opt_in_dict_and_summary_preserve_text(self):
        text = f"{CANARY_A} {CANARY_B} KEY finding stated here."
        report = explain_verdict(text, _varying_score_fn, detector_id="d", detector_version="1.0")
        dumped = json.dumps(report.to_dict(include_raw_text=True))
        self.assertIn(CANARY_A, dumped)
        self.assertIn(CANARY_B, dumped)
        # The KEY sentence drives the verdict, so it tops the summary.
        self.assertEqual(
            report.summary(include_raw_text=True)["most_ai_driving_segment"],
            "KEY finding stated here.",
        )
        # Default remains redacted after an opt-in serialisation.
        self.assertNotIn(CANARY_A, json.dumps(report.to_dict()))


class TestC03WholeCasePrivacy(unittest.TestCase):
    def test_sealer_rejects_reviewer_raw_text(self):
        with self.assertRaises(ValueError) as ctx:
            _sealed_case(
                process={
                    "reviewer": {
                        "identity": "rev",
                        "role": "reviewer",
                        "reasoning": "checked",
                        "agreed_with_tool": True,
                        "raw_text": CANARY_A,
                    }
                }
            )
        self.assertIn("raw_text", str(ctx.exception))

    def test_sealer_rejects_forbidden_keys_in_every_section(self):
        # Appeal, limitations, and nested lists inside process items.
        cases = {
            "appeal": {
                "process": {"appeal": {"decider": "a", "raw_text": CANARY_A}},
            },
            "limitations": {
                "limitations": {
                    "plain_language": {
                        "score_not_probability": "x",
                        "authorship_warning": "y",
                        "human_fpr": "z",
                        "snippet": CANARY_A,
                    }
                }
            },
            "nested_list": {
                "process": {
                    "contrary_evidence": [
                        {"detector_id": "d", "excerpt": CANARY_A},
                    ]
                }
            },
        }
        for name, kwargs in cases.items():
            with self.subTest(section=name), self.assertRaises(ValueError):
                _sealed_case(**kwargs)

    def test_sealer_rejects_each_forbidden_key(self):
        for key in sorted(FORBIDDEN_RAW_TEXT_KEYS):
            with self.subTest(key=key), self.assertRaises(ValueError):
                _sealed_case(
                    process={
                        "reviewer": {
                            "identity": "rev",
                            "role": "reviewer",
                            "reasoning": "checked",
                            "agreed_with_tool": True,
                            key: CANARY_A,
                        }
                    }
                )

    def test_legitimate_free_text_reasoning_is_not_prohibited(self):
        # The check is key-based, never content-guessing: a canary as the
        # *value* of a legitimate free-text field must seal fine.
        case = _sealed_case(
            process={
                "reviewer": {
                    "identity": "rev",
                    "role": "reviewer",
                    "reasoning": f"Reviewer reasoning quoting the finding: {CANARY_A}",
                    "agreed_with_tool": True,
                }
            }
        )
        self.assertFalse(case["raw_text_included"])

    def test_imported_case_with_smuggled_keys_fails_verification(self):
        # Direct sealer, case writer, combined verifier, packer, and the
        # standalone verifier must all refuse the same smuggled case.
        case = _sealed_case()
        smuggled = copy.deepcopy(case)
        smuggled["process"]["reviewer"] = {
            "identity": "rev",
            "role": "reviewer",
            "reasoning": "checked",
            "agreed_with_tool": True,
            "raw_text": CANARY_A,
        }
        smuggled["custody"] = [{**entry, "source_text": CANARY_B} for entry in smuggled["custody"]]
        smuggled["validation_refs"] = [
            {**ref, "quote": CANARY_A} for ref in smuggled["validation_refs"]
        ]
        smuggled["limitations"]["counterfactuals"] = [
            {"excerpt": CANARY_B},
            *smuggled["limitations"]["counterfactuals"],
        ]
        _rehash(smuggled)
        self.assertNotEqual(check_case_portability(smuggled), [])
        self.assertIn("raw_text_present_in_case", primary_verify_case_file(smuggled)["errors"])
        combined = verify_case_file_combined(smuggled)
        self.assertFalse(combined["valid"])
        self.assertIn("raw_text_present_in_case", combined["errors"])
        self.assertFalse(nversion_verify_case_file(smuggled)["valid"])
        with self.assertRaises(Exception):
            pack_sealed_bundle(smuggled)

    def test_canary_absent_from_default_case_writer_output(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            write_case_file(
                path,
                _bundle_dict(),
                deterministic=True,
                fixed_timestamp="1970-01-01T00:00:00+00:00",
            )
            self.assertNotIn(CANARY_A, path.read_text(encoding="utf-8"))

    def test_standalone_verifier_rejects_smuggled_case(self):
        case = _sealed_case()
        smuggled = copy.deepcopy(case)
        smuggled["process"]["reviewer"] = {
            "identity": "rev",
            "role": "reviewer",
            "reasoning": "checked",
            "agreed_with_tool": True,
            "raw_text": CANARY_A,
        }
        _rehash(smuggled)
        archive, _record = pack_sealed_bundle(case)
        contents = {}
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for name in zf.namelist():
                contents[name] = zf.read(name)
        contents["case.json"] = json.dumps(
            smuggled, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        rebuilt = _mpl_zip(contents)
        report = standalone.verify_bundle_bytes(rebuilt)
        self.assertNotEqual(report["exit_code"], 0)

    def test_explicit_opt_in_is_labelled_and_not_portable(self):
        case = _sealed_case(
            include_raw_text=True,
            process={
                "reviewer": {
                    "identity": "rev",
                    "role": "reviewer",
                    "reasoning": "checked",
                    "agreed_with_tool": True,
                    "raw_text": CANARY_A,
                }
            },
        )
        # The opt-in is explicit and accurately labelled...
        self.assertIs(case["raw_text_included"], True)
        self.assertIn(CANARY_A, json.dumps(case))
        # ...but an opted-in case is NOT portable evidence: portable
        # verification refuses it rather than passing it off as clean.
        self.assertIn("raw_text_policy_violation", primary_verify_case_file(case)["errors"])
        self.assertFalse(verify_case_file_combined(case)["valid"])

    def test_standalone_forbidden_key_set_matches_canonical(self):
        self.assertEqual(set(standalone.FORBIDDEN_RAW_TEXT_KEYS), set(FORBIDDEN_RAW_TEXT_KEYS))


class TestC06SealRecordAfterRejection(unittest.TestCase):
    def _deflated_archive(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("case.json", b"x" * (1024 * 1024))
        return buf.getvalue()

    def _spy_reads(self):
        reads = []
        original = zipfile.ZipFile.read

        def spy(self, name, *args, **kwargs):
            reads.append(name)
            return original(self, name, *args, **kwargs)

        return reads, spy, original

    def test_rejected_compression_zero_untrusted_reads(self):
        data = self._deflated_archive()
        reads, spy, original = self._spy_reads()
        zipfile.ZipFile.read = spy
        try:
            result = verify_sealed_bundle(data, seal_record={"manifest": {}})
        finally:
            zipfile.ZipFile.read = original
        self.assertEqual(result["standalone"]["exit_code"], 1)
        self.assertEqual(reads, [])
        self.assertEqual(result["seal_record"]["status"], "unavailable")
        self.assertIn("seal_failed", result["seal_record"]["reason"])

    def test_malformed_container_zero_untrusted_reads(self):
        reads, spy, original = self._spy_reads()
        zipfile.ZipFile.read = spy
        try:
            result = verify_sealed_bundle(b"not a zip archive at all", seal_record={"manifest": {}})
        finally:
            zipfile.ZipFile.read = original
        self.assertEqual(result["standalone"]["exit_code"], 1)
        self.assertEqual(reads, [])
        self.assertEqual(result["seal_record"]["status"], "unavailable")

    def test_rejected_size_failure_zero_untrusted_reads(self):
        # A STORED bundle whose single entry exceeds the per-entry cap is
        # rejected by the standalone container checks; the cross-check
        # must not reread it.
        big = b"y" * (MAX_ENTRY_BYTES + 1)
        files = {"case.json": big, "manifest.json": b"{}"}
        data = _mpl_zip(files)
        reads, spy, original = self._spy_reads()
        zipfile.ZipFile.read = spy
        try:
            result = verify_sealed_bundle(data, seal_record={"manifest": {}})
        finally:
            zipfile.ZipFile.read = original
        self.assertEqual(result["standalone"]["exit_code"], 1)
        self.assertEqual(reads, [])
        self.assertEqual(result["seal_record"]["status"], "unavailable")

    def test_valid_bundle_seal_record_still_passes_without_untrusted_reads(self):
        case = _sealed_case()
        archive, record = pack_sealed_bundle(case)
        reads, spy, original = self._spy_reads()
        zipfile.ZipFile.read = spy
        try:
            result = verify_sealed_bundle(archive, seal_record=record)
        finally:
            zipfile.ZipFile.read = original
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["seal_record"]["errors"], [])
        self.assertEqual(reads, [])


class TestC12MalformedShapes(unittest.TestCase):
    def _payload_with_dimensions(self, dimensions):
        return {
            "schema": "textforensics.case-file/v2",
            "raw_text_included": False,
            "case_sha256": "0" * 64,
            "forensic_bundle": {
                "schema": "textforensics.forensic-bundle/v2",
                "content_sha256": "0" * 64,
                "input": {"raw_text_included": False},
                "trust_map": {
                    "schema": "textforensics.trust-map/v2",
                    "overall": "insufficient",
                    "dimensions": dimensions,
                },
                "detector_results": [],
            },
        }

    def test_none_dimension_is_structured_invalid_not_attribute_error(self):
        payload = self._payload_with_dimensions([None])
        result = nversion_verify_case_file(payload)
        self.assertFalse(result["valid"])
        combined = verify_case_file_combined(payload)
        self.assertFalse(combined["valid"])

    def test_non_dict_payload_is_structured_invalid(self):
        for bad in (["not", "a", "mapping"], "a string", 42, None):
            with self.subTest(bad=repr(bad)):
                self.assertFalse(nversion_verify_case_file(bad)["valid"])
                self.assertFalse(verify_case_file_combined(bad)["valid"])

    def test_non_list_detector_results_is_structured_invalid(self):
        payload = self._payload_with_dimensions([])
        payload["forensic_bundle"]["detector_results"] = {"not": "a list"}
        self.assertFalse(nversion_verify_case_file(payload)["valid"])
        self.assertFalse(verify_case_file_combined(payload)["valid"])

    def test_standalone_bad_manifest_paths_are_structured_invalid(self):
        manifest = {
            "schema": "textforensics.sealed-bundle-manifest/v1",
            "context": {},
            "files": [
                {"path": None, "sha256": "0" * 64, "size": 0},
                {"path": "case.json", "sha256": "0" * 64, "size": 0},
            ],
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        data = _mpl_zip({"case.json": b"{}", "manifest.json": manifest_bytes})
        report = standalone.verify_bundle_bytes(data)
        self.assertEqual(report["exit_code"], 1)

    def test_standalone_non_string_manifest_path_is_structured_invalid(self):
        manifest = {
            "schema": "textforensics.sealed-bundle-manifest/v1",
            "context": {},
            "files": [{"path": 42, "sha256": "0" * 64, "size": 0}],
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        data = _mpl_zip({"case.json": b"{}", "manifest.json": manifest_bytes})
        self.assertEqual(standalone.verify_bundle_bytes(data)["exit_code"], 1)

    def test_nested_non_object_json_is_structured_invalid_negative_control(self):
        # The audit's negative control: 2,201-byte nested non-object JSON
        # already returns structured invalid; it must keep doing so.
        import tempfile

        nested = "[" * 1100 + "]" * 1100  # 2,200 bytes of nested arrays
        self.assertEqual(len(nested), 2200)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text(nested, encoding="utf-8")
            result = verify_case_file_path_combined(path)
        self.assertFalse(result["valid"])
        self.assertIn("case file must be a JSON object", result["errors"])

    def test_deeply_nested_object_json_is_structured_invalid(self):
        # Same "never raises" contract for a deeply nested OBJECT: on
        # Python 3.11 the json C scanner shares the ~1000 Python
        # recursion limit, so parsing this raises RecursionError; the
        # loader must map it to a structured invalid instead of letting
        # it escape. The error wording is version-dependent (the object
        # parses on 3.12+, where it is rejected later for missing case
        # fields), so only the structured-invalid shape is asserted.
        import tempfile

        nested = '{"a": ' + "[" * 1100 + "]" * 1100 + "}"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            path.write_text(nested, encoding="utf-8")
            result = verify_case_file_path_combined(path)
        self.assertFalse(result["valid"])
        self.assertTrue(result["errors"])


class TestCore07TrustCompleteness(unittest.TestCase):
    def _row(
        self,
        verdict_stability,
        *,
        selected=4,
        attempted=4,
        succeeded=4,
        abstained=0,
        failed=0,
        with_completeness=True,
    ):
        row = {
            "detector_id": "d",
            "verdict_stability": verdict_stability,
            "native_score_range": 0.01,
        }
        if with_completeness:
            row["completeness"] = {
                "selected": selected,
                "attempted": attempted,
                "succeeded": succeeded,
                "abstained": abstained,
                "failed": failed,
            }
        return row

    def test_incomplete_probe_set_never_supported(self):
        row = self._row(1.0, succeeded=2, failed=2)
        dim = _stability_dimension([row], max_native_drift=0.10)
        self.assertNotEqual(dim.state, "supported")

    def test_incomplete_survivor_value_cannot_lift_partial_row(self):
        complete_partial = self._row(0.75)
        incomplete_perfect = self._row(1.0, succeeded=2, failed=2)
        dim = _stability_dimension([complete_partial, incomplete_perfect], max_native_drift=0.10)
        self.assertEqual(dim.state, "partial")

    def test_complete_stable_probe_set_stays_supported(self):
        dim = _stability_dimension([self._row(1.0)], max_native_drift=0.10)
        self.assertEqual(dim.state, "supported")

    def test_all_abstain_completeness_is_not_supported(self):
        row = self._row(None, succeeded=0, abstained=4)
        dim = _stability_dimension([row], max_native_drift=0.10)
        self.assertNotEqual(dim.state, "supported")

    def test_malformed_completeness_is_not_usable(self):
        row = self._row(1.0)
        row["completeness"] = {"selected": 4, "attempted": 99}
        dim = _stability_dimension([row], max_native_drift=0.10)
        self.assertNotEqual(dim.state, "supported")

    def test_legacy_row_without_completeness_keeps_prior_contract(self):
        # Rows sealed before completeness accounting existed carry no
        # completeness dict; their verdict_stability is used as before.
        dim = _stability_dimension([self._row(1.0, with_completeness=False)], max_native_drift=0.10)
        self.assertEqual(dim.state, "supported")

    def test_partial_measurements_stay_visible_with_denominators(self):
        row = self._row(1.0, succeeded=2, failed=2)
        dim = _stability_dimension([row], max_native_drift=0.10)
        completeness = dim.observed.get("completeness", [])
        self.assertTrue(
            any(entry.get("failed") == 2 and entry.get("selected") == 4 for entry in completeness),
            f"denominators missing from observed: {dim.observed}",
        )

    def test_validation_v3_path_also_never_supported_from_incomplete_set(self):
        row = self._row(1.0, succeeded=2, failed=2)
        _, stability = _live_dimensions([], [row], 0)
        self.assertNotEqual(stability.state, "supported")


class TestCore09StrictArrayGrammar(unittest.TestCase):
    def _write(self, tmp, name, blob):
        path = Path(tmp) / name
        path.write_bytes(blob)
        return path

    def test_three_recorded_invalid_examples_rejected(self):
        import tempfile

        cases = {
            "missing_comma": b'[{"a": 1} {"a": 2}]',
            "leading_trailing_commas": b'[,{"a": 1},]',
            "trailing_garbage": b'[{"a": 1}] garbage',
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name, blob in cases.items():
                with self.subTest(case=name), self.assertRaises(DatasetFetchError):
                    list(iter_detectrl_x_rows(self._write(tmp, name, blob)))

    def test_extra_array_or_object_after_close_rejected(self):
        import tempfile

        for name, blob in {
            "extra_array": b'[{"a": 1}] [{"a": 2}]',
            "extra_object": b'[{"a": 1}] {"a": 2}',
            "extra_scalar": b'[{"a": 1}] 42',
        }.items():
            with (
                tempfile.TemporaryDirectory() as tmp,
                self.subTest(case=name),
                self.assertRaises(DatasetFetchError),
            ):
                list(iter_detectrl_x_rows(self._write(tmp, name, blob)))

    def test_repeated_comma_and_trailing_comma_rejected(self):
        import tempfile

        for name, blob in {
            "repeated_comma": b'[{"a": 1},,{"a": 2}]',
            "trailing_comma": b'[{"a": 1},]',
        }.items():
            with (
                tempfile.TemporaryDirectory() as tmp,
                self.subTest(case=name),
                self.assertRaises(DatasetFetchError),
            ):
                list(iter_detectrl_x_rows(self._write(tmp, name, blob)))

    def test_truncation_rejected(self):
        import tempfile

        for name, blob in {
            "mid_object": b'[{"a": 1}, {"a": 2',
            "mid_string": b'[{"a": "abc',
            "no_close": b'[{"a": 1}, {"a": 2}]',
        }.items():
            with tempfile.TemporaryDirectory() as tmp, self.subTest(case=name):
                if name == "no_close":
                    # Sanity: this one is valid and must round-trip.
                    self.assertEqual(
                        len(list(iter_detectrl_x_rows(self._write(tmp, name, blob)))), 2
                    )
                else:
                    with self.assertRaises(DatasetFetchError):
                        list(iter_detectrl_x_rows(self._write(tmp, name, blob)))

    def test_malformed_unicode_rejected_boundedly(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "bad-utf8", b'[{"a": "\xff\xfe"}]')
            with self.assertRaises(DatasetFetchError):
                list(iter_detectrl_x_rows(path))
            truncated = self._write(tmp, "trunc-utf8", b'[{"a": "caf\xc3"}]')
            with self.assertRaises(DatasetFetchError):
                list(iter_detectrl_x_rows(truncated))

    def test_valid_empty_array_round_trips(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "empty", b"  [  ]  \n")
            self.assertEqual(list(iter_detectrl_x_rows(path)), [])

    def test_valid_multibuffer_array_round_trips(self):
        import tempfile

        rows = [{"a": i, "split": "train", "pad": "x" * 500} for i in range(3000)]
        blob = ("[" + ",".join(json.dumps(r) for r in rows) + "]").encode("utf-8")
        self.assertGreater(len(blob), 1 << 20, "fixture must span several 1 MiB buffers")
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "big", blob)
            got = list(iter_detectrl_x_rows(path))
        self.assertEqual([i for i, _ in got], list(range(3000)))
        self.assertEqual(got[2999][1]["a"], 2999)

    def test_tiny_object_budget_rejected_without_huge_allocation(self):
        import tempfile

        blob = b'[{"a": "' + b"x" * 5000 + b'"}]'
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "bigobj", blob)
            with self.assertRaises(DatasetFetchError):
                list(iter_detectrl_x_rows(path, max_object_bytes=100))

    def test_deep_nesting_rejected_boundedly(self):
        import tempfile

        blob = b'[{"a": ' + b"[" * 20000 + b"]" * 20000 + b"}]"
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "deep", blob)
            with self.assertRaises(DatasetFetchError):
                list(iter_detectrl_x_rows(path))

    def test_raw_nesting_depth_limit(self):
        # Direct unit test of the explicit depth bound: the limit is
        # enforced on the raw text before decoding, so it does not depend
        # on the json module raising RecursionError (which 3.14+ no
        # longer does for deep nesting).
        from textforensics.datasets import _DETECTRL_X_MAX_NESTING_DEPTH

        limit = _DETECTRL_X_MAX_NESTING_DEPTH
        # Shallow rows pass.
        _check_raw_json_nesting_depth('{"a": 1, "b": [1, 2]}', max_depth=limit, row_index=0)
        # Exactly at the limit passes; one level over is rejected.
        _check_raw_json_nesting_depth(
            '{"a": ' + "[" * (limit - 1) + "]" * (limit - 1) + "}",
            max_depth=limit,
            row_index=0,
        )
        with self.assertRaises(DatasetFetchError):
            _check_raw_json_nesting_depth(
                '{"a": ' + "[" * limit + "]" * limit + "}",
                max_depth=limit,
                row_index=0,
            )
        # Brackets inside strings are data, not structure.
        _check_raw_json_nesting_depth('{"a": "' + "[" * 500 + '"}', max_depth=limit, row_index=0)
        # A partial buffer (object still open) draws no conclusion.
        _check_raw_json_nesting_depth('{"a": ' + "[" * 50, max_depth=limit, row_index=0)
        # The scan stops at the current object's close, so a later deep
        # row in the same buffer is not blamed on this row.
        _check_raw_json_nesting_depth('{"a": 1} ' + "[" * 500, max_depth=limit, row_index=0)

    def test_json_value_depth_measures_nesting(self):
        self.assertEqual(_json_value_depth({"a": 1}), 1)
        self.assertEqual(_json_value_depth({"a": [1, 2]}), 2)
        self.assertEqual(_json_value_depth([[[{"a": 1}]]]), 4)
        self.assertEqual(_json_value_depth(42), 0)
        nested = {}
        cur = nested
        for _ in range(199):
            nxt = {}
            cur["a"] = nxt
            cur = nxt
        self.assertEqual(_json_value_depth(nested), 200)

    def test_deep_nesting_rejected_even_when_decoder_succeeds(self):
        # Simulates the Python 3.14+ behaviour, where the json C scanner
        # no longer raises RecursionError for deeply nested input: the
        # decoder returns a deeply nested value for shallow text, and
        # the decoded-value backstop must still reject it. (The raw-text
        # scan passes here because the text itself is shallow.)
        import tempfile
        from unittest import mock

        import textforensics.datasets as datasets_mod

        real_json = datasets_mod.json

        class _DeepDecoder:
            def raw_decode(self, s):
                obj = {}
                cur = obj
                for _ in range(200):
                    nxt = {}
                    cur["a"] = nxt
                    cur = nxt
                return obj, len(s)

        fake_json = mock.Mock()
        fake_json.JSONDecodeError = real_json.JSONDecodeError
        fake_json.JSONDecoder = _DeepDecoder
        blob = b'[{"a": 1}]'
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "fake-deep", blob)
            with (
                mock.patch.object(datasets_mod, "json", fake_json),
                self.assertRaises(DatasetFetchError),
            ):
                list(iter_detectrl_x_rows(path))

    def test_decoded_depth_backstop_is_wired_in(self):
        # The post-decode depth check is enforced: if the measured depth
        # exceeds the budget, the row is rejected even though the text
        # and the decoder both behaved.
        import tempfile
        from unittest import mock

        import textforensics.datasets as datasets_mod

        blob = b'[{"a": 1}]'
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "shallow", blob)
            with (
                mock.patch.object(datasets_mod, "_json_value_depth", return_value=10**9),
                self.assertRaises(DatasetFetchError),
            ):
                list(iter_detectrl_x_rows(path))


class TestCasefileReplayMalformedRobustness(unittest.TestCase):
    def test_present_but_malformed_robustness_is_a_replay_error(self):
        bundle = _bundle_dict()
        errors, _, _ = _replay_trust_map(bundle, None)
        self.assertEqual(errors, [])
        for broken_value in ("not-a-mapping", {"detectors": "not-a-list"}, [1, 2, 3]):
            with self.subTest(broken=repr(broken_value)):
                broken = copy.deepcopy(bundle)
                broken["robustness"] = broken_value
                errors, _, _ = _replay_trust_map(broken, None)
                self.assertEqual(errors, ["trust_map_state_mismatch"])


class TestObservatoryCallTimeRegistry(unittest.TestCase):
    def test_discover_detector_registry_resolved_at_call_time(self):
        import inspect

        import textforensics.observatory as observatory

        module_source = inspect.getsource(observatory)
        head = module_source.split("\ndef ")[0]
        self.assertNotIn("discover_detector_registry", head)


if __name__ == "__main__":
    unittest.main()
