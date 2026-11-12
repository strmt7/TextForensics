"""W3 Worker B cross-cutting regression tests (C02/C03/C11/C22/C23/CORE-10).

C02 signer binding across primary/combined paths; C03 whole-case
privacy beyond the forensic bundle (appeal, custody, validation
references, limitations, nested lists) plus the opt-in verdict pin
(opted-in cases STAY REFUSED — no non-portable verification mode);
C23 result-codec trust-map version reconciliation; CORE-10 registry
re-proof after the W3 schema/codec changes.
"""

import base64
import copy
import hashlib
import io
import json
import unittest
import warnings
import zipfile
from pathlib import Path

from textforensics.casefile import seal_case_file, verify_case_file
from textforensics.report import build_forensic_bundle
from textforensics.sealing import generate_sealing_key, verify_case_signature
from textforensics.verify import verify_case_file_combined

TEXT = (
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
CANARY_A = "CANARY-W3B-ALPHA-9d2f-synthetic-source-text"
CANARY_B = "CANARY-W3B-BETA-41ce-synthetic-source-text"
SEED = bytes(range(32))
SIGNER = {"identity": "strmt7", "role": "sealer"}


def _bundle_dict():
    return build_forensic_bundle(TEXT).to_dict()


def _sealed_case(**kwargs):
    return seal_case_file(
        _bundle_dict(),
        deterministic=True,
        fixed_timestamp="2026-11-07T00:00:00+00:00",
        **kwargs,
    )


def _rehash(case):
    stripped = copy.deepcopy(case)
    stripped.pop("case_sha256", None)
    stripped.pop("created_at_utc", None)
    canonical = json.dumps(
        stripped, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    case["case_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _signed_case():
    key = generate_sealing_key("auditor@example.test", "auditor")
    seed = base64.b64decode(key["seed_b64"])
    public_key = base64.b64decode(key["public_key_b64"])
    case = _sealed_case(
        signing_seed=seed, signer={"identity": "auditor@example.test", "role": "auditor"}
    )
    return case, public_key


def _v3_trust_map():
    from textforensics.conditions import conditions_from_dict
    from textforensics.validation import ValidationRegistry, derive_trust_map

    bundle = _bundle_dict()
    conditions = conditions_from_dict(bundle["input_conditions"])
    return derive_trust_map(
        conditions,
        ValidationRegistry(),
        detector_id="textforensics/builtin-heuristic",
        detector_version="0.1.0",
        now="2026-11-07T00:00:00Z",
    ).to_dict()


class C02CombinedPathsTests(unittest.TestCase):
    """C02: a signed case verifies across primary/combined paths, and
    each individual signer-record mutation fails on both."""

    def test_signed_case_verifies_across_primary_and_combined(self):
        case, public_key = _signed_case()
        self.assertTrue(verify_case_file(case, public_key=public_key)["valid"])
        self.assertTrue(verify_case_file_combined(case, public_key=public_key)["valid"])
        self.assertTrue(verify_case_signature(case, public_key)["valid"])

    def test_each_signer_record_mutation_fails_both_paths(self):
        case, public_key = _signed_case()

        def mutate_identity(c):
            c["seal"]["signature"]["signer"]["identity"] = "mallory@example.test"

        def mutate_role(c):
            c["seal"]["signature"]["signer"]["role"] = "admin"

        def mutate_fingerprint(c):
            c["seal"]["signature"]["key_fingerprint"] = "0" * 64

        def mutate_algorithm(c):
            c["seal"]["signature"]["algorithm"] = "rsa"

        for label, mutate in [
            ("identity", mutate_identity),
            ("role", mutate_role),
            ("fingerprint", mutate_fingerprint),
            ("algorithm", mutate_algorithm),
        ]:
            with self.subTest(mutation=label):
                mutated = copy.deepcopy(case)
                mutate(mutated)
                _rehash(mutated)
                self.assertFalse(
                    verify_case_signature(mutated, public_key)["valid"],
                    label,
                )
                self.assertFalse(
                    verify_case_file(mutated, public_key=public_key)["valid"],
                    label,
                )
                self.assertFalse(
                    verify_case_file_combined(mutated, public_key=public_key)["valid"],
                    label,
                )


class C03WholeCasePrivacyTests(unittest.TestCase):
    """C03: forbidden raw-text keys are refused in EVERY section of the
    completed case — appeal, retention, subject response, contrary
    evidence, custody, validation references, limitations and nested
    lists — not just the forensic bundle.  Free-text reasoning values
    are never content-guessed."""

    def test_sealer_refuses_smuggled_appeal(self):
        with self.assertRaises(ValueError):
            _sealed_case(
                process={
                    "appeal": {
                        "decider": "panel",
                        "route": "written",
                        "raw_text": CANARY_A,
                    }
                }
            )

    def test_sealer_refuses_smuggled_retention_and_subject_response(self):
        with self.assertRaises(ValueError):
            _sealed_case(process={"retention": {"period": "90d", "content": CANARY_A}})
        with self.assertRaises(ValueError):
            _sealed_case(
                process={
                    "subject_response": {
                        "opportunity_given": True,
                        "response": {"excerpt": CANARY_B},
                    }
                }
            )

    def test_sealer_refuses_smuggled_contrary_evidence_nested_lists(self):
        with self.assertRaises(ValueError):
            _sealed_case(
                process={
                    "contrary_evidence": [
                        {
                            "detector_id": "textforensics/builtin-heuristic",
                            "evidence": [{"snippet": CANARY_A}],
                        }
                    ]
                }
            )

    def test_sealer_refuses_smuggled_limitations_nested_lists(self):
        with self.assertRaises(ValueError):
            _sealed_case(
                limitations={
                    "counterfactuals": [
                        {"excerpt": CANARY_A},
                        "plain counterfactual without raw text",
                    ],
                    "bundle_limitations": ["short text"],
                }
            )
        with self.assertRaises(ValueError):
            _sealed_case(
                limitations={
                    "plain_language": {
                        "score_not_probability": "A score is not a probability.",
                        "authorship_warning": "Text-only detection cannot prove authorship.",
                        "human_fpr": "Human false positives are a release gate.",
                        "raw_text": CANARY_B,
                    },
                    "counterfactuals": [],
                }
            )

    def test_verification_refuses_smuggled_appeal_custody_refs_limitations(self):
        case = _sealed_case()
        smuggled = copy.deepcopy(case)
        smuggled["process"]["appeal"] = {
            "decider": "panel",
            "route": "written",
            "source_text": CANARY_A,
        }
        smuggled["custody"] = [
            {**entry, "document_text": CANARY_B} for entry in smuggled["custody"]
        ]
        smuggled["validation_refs"] = [
            {**ref, "quote": CANARY_A} for ref in smuggled["validation_refs"]
        ]
        smuggled["limitations"]["counterfactuals"] = [
            {"text": CANARY_B},
            *smuggled["limitations"]["counterfactuals"],
        ]
        smuggled["limitations"]["bundle_limitations"] = [
            {"content": CANARY_A},
            *smuggled["limitations"]["bundle_limitations"],
        ]
        _rehash(smuggled)
        primary = verify_case_file(smuggled)
        self.assertFalse(primary["valid"])
        self.assertIn("raw_text_present_in_case", primary["errors"])
        combined = verify_case_file_combined(smuggled)
        self.assertFalse(combined["valid"])
        self.assertIn("raw_text_present_in_case", combined["errors"])

    def test_legitimate_free_text_in_appeal_is_not_prohibited(self):
        # Key-based policy only: a canary as the VALUE of a legitimate
        # free-text field must seal fine.
        case = _sealed_case(
            process={
                "appeal": {
                    "decider": "panel",
                    "route": "written",
                    "reasoning": f"Appeal considered the finding: {CANARY_A}",
                }
            }
        )
        self.assertFalse(case["raw_text_included"])

    def test_opted_in_case_stays_refused_everywhere(self):
        # W3 verdict (C03): an opted-in case stays refused by every
        # portable verification entry point; there is no separate
        # non-portable verification mode.
        from textforensics.sealed_bundle import pack_sealed_bundle

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
        self.assertIs(case["raw_text_included"], True)
        self.assertIn("raw_text_policy_violation", verify_case_file(case)["errors"])
        self.assertFalse(verify_case_file_combined(case)["valid"])
        with self.assertRaises(Exception):
            pack_sealed_bundle(case)

    def test_no_canary_in_default_export_or_packed_archive(self):
        import tempfile

        from textforensics.casefile import write_case_file
        from textforensics.sealed_bundle import pack_sealed_bundle

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.json"
            write_case_file(
                path,
                _bundle_dict(),
                deterministic=True,
                fixed_timestamp="1970-01-01T00:00:00+00:00",
            )
            self.assertNotIn(CANARY_A, path.read_text(encoding="utf-8"))
            self.assertNotIn(CANARY_B, path.read_text(encoding="utf-8"))
            archive, _record = pack_sealed_bundle(_sealed_case())
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                for name in zf.namelist():
                    content = zf.read(name)
                    self.assertNotIn(CANARY_A.encode(), content, name)
                    self.assertNotIn(CANARY_B.encode(), content, name)

    def test_standalone_verifier_rejects_smuggled_appeal(self):
        import textforensics._standalone_verify as standalone
        from textforensics.sealed_bundle import pack_sealed_bundle

        case = _sealed_case()
        smuggled = copy.deepcopy(case)
        smuggled["process"]["appeal"] = {
            "decider": "panel",
            "route": "written",
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
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            for name, data in contents.items():
                zf.writestr(name, data)
        report = standalone.verify_bundle_bytes(buf.getvalue())
        self.assertNotEqual(report["exit_code"], 0)


class C23ResultCodecTests(unittest.TestCase):
    """C23: the result codec must accept every trust-map version the
    schema registry supports (v1/v2/v3), keep the found label, and
    refuse only genuinely unsupported versions under strict mode."""

    def test_strict_decode_accepts_v3_trust_map(self):
        from textforensics.result_codec import CodecConfig, ResultCodec

        decoded = ResultCodec(CodecConfig(strict_version=True)).decode(
            json.dumps(_v3_trust_map()), "trust-map", validate=True
        )
        self.assertEqual(decoded["schema"], "textforensics.trust-map/v3")

    def test_decode_keeps_supported_legacy_labels(self):
        from textforensics.result_codec import ResultCodec

        v2_map = _bundle_dict()["trust_map"]
        self.assertEqual(v2_map["schema"], "textforensics.trust-map/v2")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            decoded = ResultCodec().decode(json.dumps(v2_map), "trust-map", validate=True)
        self.assertEqual(decoded["schema"], "textforensics.trust-map/v2")
        self.assertFalse(
            [w for w in caught if "No migration path" in str(w.message)],
            [str(w.message) for w in caught],
        )

    def test_encode_without_label_stamps_current_v3(self):
        from textforensics.result_codec import ResultCodec

        v3_map = {k: v for k, v in _v3_trust_map().items() if k != "schema"}
        encoded = ResultCodec().encode(v3_map, "trust-map", validate=False)
        self.assertEqual(json.loads(encoded)["schema"], "textforensics.trust-map/v3")

    def test_encode_keeps_explicit_legacy_label(self):
        from textforensics.result_codec import ResultCodec

        v2_map = _bundle_dict()["trust_map"]
        encoded = ResultCodec().encode(dict(v2_map), "trust-map", validate=True)
        self.assertEqual(json.loads(encoded)["schema"], "textforensics.trust-map/v2")

    def test_strict_decode_refuses_unsupported_version(self):
        from textforensics.result_codec import CodecConfig, ResultCodec, VersionMigrationError

        v3_map = _v3_trust_map()
        v3_map["schema"] = "textforensics.trust-map/v9"
        with self.assertRaises(VersionMigrationError):
            ResultCodec(CodecConfig(strict_version=True)).decode(
                json.dumps(v3_map), "trust-map", validate=False
            )

    def test_non_strict_decode_of_v3_map_validates(self):
        from textforensics.result_codec import ResultCodec

        decoded = ResultCodec().decode(json.dumps(_v3_trust_map()), "trust-map", validate=True)
        self.assertEqual(decoded["schema"], "textforensics.trust-map/v3")


class Core10ReproofTests(unittest.TestCase):
    """CORE-10 (W3 side): after the C23 codec reconciliation and the
    case-file schema addition, the registry stays complete and
    consistent — every shipped schema listed and loadable, every
    listed name dispatching, unsupported versions refused."""

    def test_shipped_schemas_equal_listed_schemas(self):
        from textforensics.schema import list_schemas, load_schema

        shipped = sorted(
            p.name
            for p in (
                Path(__file__).resolve().parent.parent / "src" / "textforensics" / "schemas"
            ).glob("*.json")
        )
        listed = [f"{name}.schema.json" for name in list_schemas()]
        self.assertEqual(len(shipped), 13)
        self.assertEqual(sorted(listed), shipped)
        for name in list_schemas():
            self.assertIsInstance(load_schema(name), dict)

    def test_generic_validate_dispatches_every_listed_name(self):
        from textforensics.schema import list_schemas, validate

        for name in list_schemas():
            with self.subTest(name=name):
                # Dispatching means: no "unknown schema" raise; a list
                # of errors is returned for an empty payload.
                errors = validate({}, name)
                self.assertIsInstance(errors, list)

    def test_unsupported_versions_refused_through_generic_surface(self):
        from textforensics.schema import list_schemas, load_schema, supported_versions, validate

        for name in list_schemas():
            supported = supported_versions(name)
            if not supported:
                continue
            with self.subTest(name=name):
                payload = {"schema": "textforensics.unknown/v9"}
                errors = validate(payload, name)
                self.assertNotEqual(errors, [], name)
                with self.assertRaises(ValueError):
                    load_schema(name, version="textforensics.unknown/v9")

    def test_supported_versions_pinned(self):
        from textforensics.schema import supported_versions

        self.assertEqual(
            supported_versions("trust-map"),
            {
                "textforensics.trust-map/v1",
                "textforensics.trust-map/v2",
                "textforensics.trust-map/v3",
            },
        )
        self.assertEqual(
            supported_versions("forensic-bundle"),
            {
                "textforensics.forensic-bundle/v1",
                "textforensics.forensic-bundle/v2",
            },
        )
        self.assertEqual(
            supported_versions("case-file"),
            {
                "textforensics.case-file/v1",
                "textforensics.case-file/v2",
                "textforensics.case-file/v3",
                "textforensics.case-file/v4",
            },
        )


if __name__ == "__main__":
    unittest.main()
