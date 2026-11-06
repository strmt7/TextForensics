"""Tests for scripts/check_claims.py (U7 claim-to-evidence gate).

The gate is exercised against a minimal fake repo in tmp_path so the
linkage checks (a)–(e) and the report card (f) can be tested without
running the full suite. One integration test runs the real gate against
the real repo.
"""

import hashlib
import importlib.util
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
REPO_ROOT = Path(__file__).parent.parent
REAL_SCHEMAS = REPO_ROOT / "src" / "textforensics" / "schemas"


def _load_gate_module():
    spec = importlib.util.spec_from_file_location("check_claims", SCRIPTS_DIR / "check_claims.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_claims"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load_gate_module()


TODAY = date(2026, 11, 6)


def _make_artifact(
    record_id, results=None, run_date="2026-11-06", detector_version="0.1.0", drops=None
):
    artifact = {
        "schema": "textforensics.run-artifact/v1",
        "evidence_record_id": record_id,
        "kind": "test-suite",
        "command": "pytest tests/",
        "environment": {"python": "3.12.3", "platform": "linux", "extras": "none"},
        "code_version": "a" * 40,
        "run_date": run_date,
        "results": results or {},
        "drops": [] if drops is None else drops,
        "badge": "available",
    }
    if detector_version is not None:
        artifact["detector_version"] = detector_version
    return artifact


def _write_artifact(root: Path, artifact: dict) -> tuple[Path, str]:
    path = root / "docs" / "evidence" / "runs" / f"{artifact['evidence_record_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _write_registry(root: Path, entries: list[tuple[str, str, str]]) -> None:
    """entries: (record_id, artifact_rel_path, sha256)."""
    registry = {
        "schema": "textforensics.evidence-registry/v1",
        "records": [
            {
                "evidence_record_id": rid,
                "run_artifact": rel,
                "run_artifact_sha256": sha,
            }
            for rid, rel, sha in entries
        ],
    }
    path = root / "docs" / "evidence" / "registry.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _make_claim(record_id, sha, statement="Suite: 2336 passed, 0 failed", values=None, **overrides):
    claim = {
        "id": "test.claim",
        "statement": statement,
        "category": "maturity",
        "status": "verified",
        "evidence_type": "doc",
        "evidence_path": "docs/evidence/runs/EV-20261106-suite.json",
        "owner": "dev",
        "last_verified": "2026-11-06",
        "evidence_record_id": record_id,
        "run_artifact_sha256": sha,
    }
    if values is not None:
        claim["values"] = values
    claim.update(overrides)
    return claim


@pytest.fixture()
def fake_repo(tmp_path: Path):
    """A minimal repo with the real U7 schemas and a fake detectors.py."""
    schemas = tmp_path / "src" / "textforensics" / "schemas"
    schemas.mkdir(parents=True)
    for name in ("run-artifact.schema.json", "evidence-registry.schema.json"):
        (schemas / name).write_text(
            (REAL_SCHEMAS / name).read_text(encoding="utf-8"), encoding="utf-8"
        )
    detectors = tmp_path / "src" / "textforensics" / "detectors.py"
    detectors.write_text('detector_version = "0.1.0"\n', encoding="utf-8")
    return tmp_path


def _seed_fake_repo(root: Path, artifact: dict):
    _path, sha = _write_artifact(root, artifact)
    rel = f"docs/evidence/runs/{artifact['evidence_record_id']}.json"
    _write_registry(root, [(artifact["evidence_record_id"], rel, sha)])
    return sha


def test_linkage_passes(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336, "tests_failed": 0})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, failures = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    assert not failures
    claim = _make_claim("EV-20261106-suite", sha, values={"tests_passed": 2336, "tests_failed": 0})
    ok, _msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass"


def test_missing_record_id_fails_criterion_a(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim("EV-20261106-suite", sha)
    del claim["evidence_record_id"]
    ok, msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail" and "(U7 (a))" in msg


def test_tampered_artifact_fails_criterion_b(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    _seed_fake_repo(fake_repo, artifact)
    path = fake_repo / "docs" / "evidence" / "runs" / "EV-20261106-suite.json"
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["results"]["tests_passed"] = 9999
    path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _records, failures = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    assert failures and "hash mismatch" in failures[0][1]


def test_stale_old_record_fails_criterion_d(gate, fake_repo):
    old_date = (TODAY - timedelta(days=100)).isoformat()
    artifact = _make_artifact("EV-20260801-suite", {"tests_passed": 2336}, run_date=old_date)
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim("EV-20260801-suite", sha, last_verified=old_date)
    ok, msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "stale" and "100 days old" in msg


def test_stale_detector_version_fails_criterion_d(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336}, detector_version="0.0.9")
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim("EV-20261106-suite", sha)
    ok, msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "stale" and "detector version changed" in msg


def test_missing_drops_fails_criterion_e(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    del artifact["drops"]
    _path, sha = _write_artifact(fake_repo, artifact)
    rel = "docs/evidence/runs/EV-20261106-suite.json"
    _write_registry(fake_repo, [("EV-20261106-suite", rel, sha)])
    _records, failures = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    assert failures and "drops" in failures[0][1]
    # Direct linkage check on an entry without drops reports incomplete.
    entry = {"record": {"run_artifact_sha256": sha}, "artifact": artifact, "path": _path}
    claim = _make_claim("EV-20261106-suite", sha)
    ok, msg, verdict = gate.check_evidence_linkage(
        claim, {"EV-20261106-suite": entry}, fake_repo, TODAY, "0.1.0"
    )
    assert not ok and verdict == "incomplete" and "(U7 (e))" in msg


def test_values_mismatch_fails_criterion_c(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim("EV-20261106-suite", sha, values={"tests_passed": 9999})
    ok, msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail" and "value mismatch" in msg


def test_value_not_in_statement_fails_criterion_c(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim(
        "EV-20261106-suite",
        sha,
        statement="The suite passes (no numbers here)",
        values={"tests_passed": 2336},
    )
    ok, msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail" and "does not appear in the claim statement" in msg


def test_zero_matches_word_zero(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_failed": 0})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim(
        "EV-20261106-suite",
        sha,
        statement="The suite has zero failures",
        values={"tests_failed": 0},
    )
    ok, _msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass"


def test_values_dotted_path_and_tolerance(gate, fake_repo):
    artifact = _make_artifact(
        "EV-20261106-audit", {"packages": {"cryptography": 11}, "coverage_pct": 85}
    )
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim(
        "EV-20261106-audit",
        sha,
        statement="11 findings in cryptography; 86% coverage",
        values={"packages.cryptography": 11, "coverage_pct": 86},
        tolerance=1,
    )
    ok, _msg, verdict = gate.check_evidence_linkage(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass"


def test_report_card_leads_with_fpr_and_lists_failures(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim_results = [
        ("test.claim", "verified", "EV-20261106-suite", True, "pass", "evidence linkage OK"),
        ("test.broken", "verified", "EV-20261106-suite", False, "stale", "stale — 100 days old"),
    ]
    card = gate.write_report_card(fake_repo, claim_results, records_by_id, [])
    text = card.read_text(encoding="utf-8")
    assert text.index("Worst-slice human false-positive rate") < text.index("## Claims")
    assert "**unknown**" in text
    assert "test.broken" in text and "stale" in text
    assert "EV-20261106-suite" in text
    # Deterministic: writing twice yields identical bytes.
    card2 = gate.write_report_card(fake_repo, claim_results, records_by_id, [])
    assert card2.read_bytes() == card.read_bytes()


def test_worst_slice_fpr_found(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-bench", {"worst_slice_human_fpr": 0.05})
    _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    value, record_id = gate.worst_slice_fpr(records_by_id)
    assert value == 0.05 and record_id == "EV-20261106-bench"


def test_duplicate_yaml_keys_rejected(gate, fake_repo):
    claims_file = fake_repo / "docs" / "CLAIMS.yaml"
    claims_file.parent.mkdir(parents=True, exist_ok=True)
    claims_file.write_text("claims:\n  - id: a\n    id: a\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate YAML keys"):
        gate.load_claims(fake_repo)


def test_verify_claim_runs_doc_evidence(gate, fake_repo):
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    claim = _make_claim("EV-20261106-suite", sha, values={"tests_passed": 2336})
    ok, _msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass"
