"""Tests for scripts/build_human_fpr_run_artifact.py.

Pure functions plus the committed artifact file: no network, no dataset
cache, no detector run. The live re-measurement is covered by the
script's own run, which checks the fresh values reproduce
EV-20261108-human-fpr.json exactly before writing anything.
"""

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def builder():
    return _load_module(
        "build_human_fpr_run_artifact",
        SCRIPTS_DIR / "build_human_fpr_run_artifact.py",
    )


@pytest.fixture(scope="module")
def check_claims():
    return _load_module("check_claims", SCRIPTS_DIR / "check_claims.py")


@pytest.fixture(scope="module")
def committed_artifact():
    return json.loads(
        (REPO_ROOT / "docs" / "evidence" / "runs" / "EV-20261110-human-fpr.json").read_text(
            encoding="utf-8"
        )
    )


@pytest.fixture(scope="module")
def source_artifact():
    return json.loads(
        (REPO_ROOT / "docs" / "evidence" / "EV-20261108-human-fpr.json").read_text(encoding="utf-8")
    )


def _fixture_old_artifact():
    """Minimal old-shape FPR artifact (same field set as the real one)."""
    return {
        "schema": "textforensics.human-fpr-evidence/v1",
        "evidence_record_id": "EV-20261108-human-fpr",
        "run_date": "2026-11-08",
        "code_version": "8" * 40,
        "detector": "textforensics/builtin-heuristic",
        "detector_version": "0.1.0",
        "detector_family": "stylometric-heuristic",
        "command": "python scripts/measure_human_fpr.py",
        "environment": {"platform": "Linux", "python": "3.12.3"},
        "method": "Re-ran the detector over the cached rows.",
        "pooling_assessment": "Pooling is NOT legitimate as the gate statistic.",
        "slices": [
            {
                "record_id": "evr-20261106-opai-bench-builtin-heuristic",
                "dataset": "OpAI-Bench",
                "n_human": 56,
                "fpr_native_wilson": {
                    "k": 0,
                    "n": 56,
                    "value": 0.0,
                    "ci_lower": 0.0,
                    "ci_upper": 0.064196,
                    "method": "Wilson score interval, 95% (z=1.96)",
                },
                "registry_fpr_native": {
                    "value": 0.0,
                    "n": 56,
                    "ci_lower": 0.0,
                    "ci_upper": 0.0,
                    "method": "bootstrap, 1000 resamples, seed 20261106",
                },
                "registry_tpr_native": {
                    "value": 0.0,
                    "n": 55,
                    "ci_lower": 0.0,
                    "ci_upper": 0.0,
                    "method": "bootstrap, 1000 resamples, seed 20261106",
                },
            }
        ],
        "pooled_documents_only": {"k": 0, "n": 56, "value": 0.0},
        "pooled_all_slices_including_segments": {"k": 0, "n": 56, "value": 0.0},
        "worst_slice_wilson_ci_upper": 0.064196,
        "worst_document_slice_wilson_ci_upper": 0.064196,
        "still_unknown": ["Worst-slice human FPR as a supported claim: unknown."],
    }


def _validate(builder, check_claims, artifact):
    # The repo's own gate validator: the exact function
    # verify_registry_records uses for every pinned artifact.
    schema = check_claims._load_schema(REPO_ROOT, "run-artifact.schema.json")
    return check_claims._schema_errors(schema, artifact)


def test_reshape_conforms_to_run_artifact_schema(builder, check_claims):
    candidate = builder.reshape_fpr_to_run_artifact(
        _fixture_old_artifact(),
        evidence_record_id="EV-20261110-human-fpr",
        run_date="2026-11-10",
        code_version="a" * 40,
        command="python scripts/build_human_fpr_run_artifact.py",
        drops=[{"item": "x", "reason": "y"}],
    )
    assert _validate(builder, check_claims, candidate) == []
    assert candidate["schema"] == "textforensics.run-artifact/v1"
    assert candidate["kind"] == "command"
    assert candidate["badge"] == "available"
    assert candidate["drops"] == [{"item": "x", "reason": "y"}]
    assert set(candidate) <= {
        "schema",
        "evidence_record_id",
        "kind",
        "command",
        "environment",
        "code_version",
        "run_date",
        "results",
        "drops",
        "badge",
        "detector_version",
        "notes",
    }


def test_reshape_preserves_every_value(builder):
    old = _fixture_old_artifact()
    candidate = builder.reshape_fpr_to_run_artifact(
        old,
        evidence_record_id="EV-20261110-human-fpr",
        run_date="2026-11-10",
        code_version="a" * 40,
        command="python scripts/build_human_fpr_run_artifact.py",
        drops=[{"item": "x", "reason": "y"}],
    )
    assert builder.check_value_preservation(old, candidate) == []
    # Prose assessments survive verbatim in notes, not dropped.
    assert old["pooling_assessment"] in candidate["notes"]
    for item in old["still_unknown"]:
        assert item in candidate["notes"]


def test_reshape_never_introduces_lead_flipping_keys(builder):
    old = _fixture_old_artifact()
    candidate = builder.reshape_fpr_to_run_artifact(
        old,
        evidence_record_id="EV-20261110-human-fpr",
        run_date="2026-11-10",
        code_version="a" * 40,
        command="python scripts/build_human_fpr_run_artifact.py",
        drops=[{"item": "x", "reason": "y"}],
    )
    assert "worst_slice_human_fpr" not in candidate["results"]
    assert "human_fpr" not in candidate["results"]
    # The preserved key is the Wilson bound, under its own name.
    assert candidate["results"]["worst_slice_wilson_ci_upper"] == old["worst_slice_wilson_ci_upper"]


def test_preservation_checker_catches_tampering(builder):
    old = _fixture_old_artifact()
    candidate = builder.reshape_fpr_to_run_artifact(
        old,
        evidence_record_id="EV-20261110-human-fpr",
        run_date="2026-11-10",
        code_version="a" * 40,
        command="python scripts/build_human_fpr_run_artifact.py",
        drops=[{"item": "x", "reason": "y"}],
    )
    candidate["results"]["worst_slice_wilson_ci_upper"] = 0.05
    mismatches = builder.check_value_preservation(old, candidate)
    assert any("worst_slice_wilson_ci_upper" in m for m in mismatches)
    candidate["results"]["worst_slice_human_fpr"] = 0.064196
    mismatches = builder.check_value_preservation(old, candidate)
    assert any("worst_slice_human_fpr" in m for m in mismatches)


def test_reshape_refuses_lead_flipping_input(builder):
    old = _fixture_old_artifact()
    old["worst_slice_human_fpr"] = 0.064196
    with pytest.raises(ValueError, match="worst_slice_human_fpr"):
        builder.reshape_fpr_to_run_artifact(
            old,
            evidence_record_id="EV-20261110-human-fpr",
            run_date="2026-11-10",
            code_version="a" * 40,
            command="python scripts/build_human_fpr_run_artifact.py",
            drops=[{"item": "x", "reason": "y"}],
        )


def test_reshape_refuses_incomplete_input(builder):
    old = _fixture_old_artifact()
    del old["slices"]
    with pytest.raises(ValueError, match="slices"):
        builder.reshape_fpr_to_run_artifact(
            old,
            evidence_record_id="EV-20261110-human-fpr",
            run_date="2026-11-10",
            code_version="a" * 40,
            command="python scripts/build_human_fpr_run_artifact.py",
            drops=[{"item": "x", "reason": "y"}],
        )


def test_reproduction_checker_catches_changed_values(builder):
    old = _fixture_old_artifact()
    fresh = json.loads(json.dumps(old))
    fresh["worst_slice_wilson_ci_upper"] = 0.05
    result = builder.check_reproduction(fresh, old)
    assert any("worst_slice_wilson_ci_upper" in m for m in result["mismatches"])
    clean = builder.check_reproduction(old, old)
    assert clean == {"mismatches": [], "registry_echo_drift": []}


def test_reproduction_allows_documented_wilson_echo_drift(builder):
    # The parent applied the Wilson-CI replacement on 2026-11-08: the
    # fresh registry_fpr_native quotation carries the Wilson upper and
    # method where the committed artifact quoted bootstrap [0.0, 0.0].
    # Value and n are unchanged, and the upper equals the slice's own
    # Wilson fpr ci_upper. That exact pattern is allowed — and disclosed.
    old = _fixture_old_artifact()
    fresh = json.loads(json.dumps(old))
    fresh["slices"][0]["registry_fpr_native"] = {
        "value": 0.0,
        "n": 56,
        "ci_lower": 0.0,
        "ci_upper": 0.064196,
        "method": "Wilson score interval, 95% (z=1.96)",
    }
    result = builder.check_reproduction(fresh, old)
    assert result["mismatches"] == []
    assert len(result["registry_echo_drift"]) == 1
    assert "evr-20261106-opai-bench-builtin-heuristic" in result["registry_echo_drift"][0]


def test_reproduction_rejects_undocumented_echo_drift(builder):
    # A changed registry_tpr_native was never part of the Wilson
    # replacement: any drift there is a mismatch, not a disclosure.
    old = _fixture_old_artifact()
    fresh = json.loads(json.dumps(old))
    fresh["slices"][0]["registry_tpr_native"] = {
        "value": 0.0,
        "n": 55,
        "ci_lower": 0.0,
        "ci_upper": 0.065287,
        "method": "Wilson score interval, 95% (z=1.96)",
    }
    result = builder.check_reproduction(fresh, old)
    assert any("registry_tpr_native" in m for m in result["mismatches"])


def test_committed_artifact_validates_and_preserves_source(
    builder, check_claims, committed_artifact, source_artifact
):
    assert _validate(builder, check_claims, committed_artifact) == []
    assert committed_artifact["evidence_record_id"] == "EV-20261110-human-fpr"
    assert committed_artifact["run_date"] == "2026-11-10"
    assert committed_artifact["kind"] == "command"
    assert committed_artifact["badge"] == "available"
    assert committed_artifact["detector_version"] == "0.1.0"
    assert re.fullmatch(r"[0-9a-f]{40}", committed_artifact["code_version"])
    assert committed_artifact["drops"], "a run artifact must carry a drops manifest"
    assert committed_artifact["results"]["worst_slice_wilson_ci_upper"] == 0.064196
    assert "worst_slice_human_fpr" not in committed_artifact["results"]
    assert "human_fpr" not in committed_artifact["results"]
    # Measured values reproduce the source exactly; the only allowed
    # difference is the documented registry-echo drift (Wilson quotation
    # where the source quoted bootstrap [0.0, 0.0] — see
    # check_reproduction's contract, enforced here field by field).
    assert (
        committed_artifact["results"]["pooled_documents_only"]
        == source_artifact["pooled_documents_only"]
    )
    assert (
        committed_artifact["results"]["pooled_all_slices_including_segments"]
        == source_artifact["pooled_all_slices_including_segments"]
    )
    assert (
        committed_artifact["results"]["worst_document_slice_wilson_ci_upper"]
        == source_artifact["worst_document_slice_wilson_ci_upper"]
    )
    assert committed_artifact["results"]["method"] == source_artifact["method"]
    assert source_artifact["pooling_assessment"] in committed_artifact["notes"]
    for item in source_artifact["still_unknown"]:
        assert item in committed_artifact["notes"]
    assert "Registry-echo note" in committed_artifact["notes"]


def test_committed_artifact_does_not_flip_report_card_lead(check_claims, committed_artifact):
    worst, record = check_claims.worst_slice_fpr(
        {"EV-20261110-human-fpr": {"artifact": committed_artifact}}
    )
    assert worst is None and record is None


def test_committed_artifact_reproduces_source_slices(committed_artifact, source_artifact):
    # Measured slice values reproduce the source exactly (registry-echo
    # fields stripped: they quote the registry at run time, and the
    # registry moved under the Wilson replacement — see the test below).
    echo_fields = ("registry_fpr_native", "registry_tpr_native")
    committed_slices = [
        {k: v for k, v in s.items() if k not in echo_fields}
        for s in committed_artifact["results"]["slices"]
    ]
    source_slices = [
        {k: v for k, v in s.items() if k not in echo_fields} for s in source_artifact["slices"]
    ]
    assert committed_slices == source_slices


def test_committed_artifact_echo_drift_is_only_the_wilson_replacement(
    committed_artifact, source_artifact
):
    committed_by_id = {s["record_id"]: s for s in committed_artifact["results"]["slices"]}
    for source_slice in source_artifact["slices"]:
        committed_slice = committed_by_id[source_slice["record_id"]]
        # TPR echoes untouched by the replacement: identical.
        assert committed_slice["registry_tpr_native"] == source_slice["registry_tpr_native"]
        fresh_echo = committed_slice["registry_fpr_native"]
        old_echo = source_slice["registry_fpr_native"]
        if source_slice["record_id"] == "evr-20261106-raid-builtin-heuristic":
            # The old RAID record's fpr CI was NOT replaced: the parent's
            # apply step moved the replacement to the NEW n=171 record
            # (evr-20261108-raid-builtin-heuristic), so the old record
            # still quotes the degenerate bootstrap [0.0, 0.0] — and the
            # fresh echo matches the source exactly. No drift, no surprise.
            assert fresh_echo == old_echo
            continue
        # FPR echoes on the other six slices: value and n identical; the
        # fresh quotation carries the Wilson upper and method, equal to
        # the slice's own Wilson CI.
        assert fresh_echo["value"] == old_echo["value"]
        assert fresh_echo["n"] == old_echo["n"]
        assert old_echo["ci_upper"] == 0.0
        assert old_echo["method"].startswith("bootstrap")
        assert fresh_echo["method"].startswith("Wilson")
        assert fresh_echo["ci_upper"] == committed_slice["fpr_native_wilson"]["ci_upper"]
