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
    doc_rel = "docs/evidence/runs/EV-20261106-suite.json"
    head = _commit_doc_repo(
        fake_repo, doc_rel, (fake_repo / doc_rel).read_text(encoding="utf-8")
    )
    digest = hashlib.sha256((fake_repo / doc_rel).read_bytes()).hexdigest()
    claim = _make_claim(
        "EV-20261106-suite",
        sha,
        values={"tests_passed": 2336},
        doc_sha256=digest,
        doc_as_of_sha=head,
        doc_state="historical",
    )
    ok, _msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass"

# ---------------------------------------------------------------------------
# ENG-16: doc evidence must bind to content digest + source SHA, and the
# report card must be schema-aware about Wilson-upper-bound FPR evidence.
# ---------------------------------------------------------------------------

import subprocess


def _git(root: Path, *args: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    import os

    full_env = dict(os.environ, **env)
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        env=full_env,
        check=True,
    )
    return result.stdout.strip()


def _commit_doc_repo(root: Path, rel: str, content: str) -> str:
    """Init a git repo in root, commit the doc, return the HEAD SHA."""
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "doc commit")
    return _git(root, "rev-parse", "HEAD")


def _doc_claim(record_id, sha, doc_rel, doc_sha256, doc_as_of_sha, doc_state, **overrides):
    claim = _make_claim(record_id, sha, evidence_type="doc", evidence_path=doc_rel)
    claim.update(
        {
            "doc_sha256": doc_sha256,
            "doc_as_of_sha": doc_as_of_sha,
            "doc_state": doc_state,
        }
    )
    claim.update(overrides)
    return claim


def _seed_doc_repo(gate, fake_repo, doc_rel="docs/STATUS.md", content="status: ok\n"):
    """Seed registry + a git-committed doc; return (records_by_id, sha, head)."""
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    head = _commit_doc_repo(fake_repo, doc_rel, content)
    digest = hashlib.sha256((fake_repo / doc_rel).read_bytes()).hexdigest()
    return records_by_id, sha, head, digest


def test_doc_evidence_without_digest_fails(gate, fake_repo):
    """ENG-16: a doc claim with no recorded digest must fail, not pass."""
    records_by_id, sha, head, _digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim("EV-20261106-suite", sha, "docs/STATUS.md", None, head, "implemented")
    del claim["doc_sha256"]
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "doc_sha256" in msg


def test_doc_evidence_digest_mismatch_fails(gate, fake_repo):
    """ENG-16: a recorded digest that no longer matches the bytes fails."""
    records_by_id, sha, head, _digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", "0" * 64, head, "implemented"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "digest" in msg.lower()


def test_doc_evidence_content_change_after_digest_fails(gate, fake_repo):
    """ENG-16: mutating the doc after its digest was recorded must fail."""
    records_by_id, sha, head, digest = _seed_doc_repo(gate, fake_repo)
    (fake_repo / "docs/STATUS.md").write_text("status: changed\n", encoding="utf-8")
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", digest, head, "implemented"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "digest" in msg.lower()


def test_doc_evidence_matching_digest_and_as_of_passes(gate, fake_repo):
    """Clean control: matching digest + as-of SHA + implemented state passes."""
    records_by_id, sha, head, digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", digest, head, "implemented"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass", msg


def test_doc_evidence_changed_since_as_of_fails_for_implemented(gate, fake_repo):
    """ENG-16: implemented doc changed after its as-of SHA must re-verify."""
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    head_v1 = _commit_doc_repo(fake_repo, "docs/STATUS.md", "status: v1\n")
    # Second commit changes the doc; digest is recorded for v2 bytes.
    (fake_repo / "docs/STATUS.md").write_text("status: v2\n", encoding="utf-8")
    _git(fake_repo, "add", ".")
    _git(fake_repo, "commit", "-q", "-m", "doc v2")
    digest_v2 = hashlib.sha256((fake_repo / "docs/STATUS.md").read_bytes()).hexdigest()
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", digest_v2, head_v1, "implemented"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "as-of" in msg.lower() or "as_of" in msg.lower()


def test_doc_evidence_historical_state_allows_older_as_of(gate, fake_repo):
    """Historical records may cite an older as-of SHA when bytes still match."""
    artifact = _make_artifact("EV-20261106-suite", {"tests_passed": 2336})
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, _ = gate.verify_registry_records(fake_repo, gate.load_registry(fake_repo))
    head_v1 = _commit_doc_repo(fake_repo, "docs/STATUS.md", "status: v1\n")
    # Unrelated commit moves HEAD; the doc itself is untouched.
    (fake_repo / "other.txt").write_text("unrelated\n", encoding="utf-8")
    _git(fake_repo, "add", ".")
    _git(fake_repo, "commit", "-q", "-m", "unrelated")
    digest = hashlib.sha256((fake_repo / "docs/STATUS.md").read_bytes()).hexdigest()
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", digest, head_v1, "historical"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass", msg


def test_doc_evidence_unknown_as_of_sha_fails(gate, fake_repo):
    """An as-of SHA that does not resolve in the repo must fail."""
    records_by_id, sha, _head, digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", digest, "f" * 40, "implemented"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "as-of" in msg.lower() or "as_of" in msg.lower()


def test_doc_evidence_bad_state_fails(gate, fake_repo):
    """doc_state must be one of implemented/tested/historical/blocked."""
    records_by_id, sha, head, digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", digest, head, "current"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "doc_state" in msg


def test_doc_evidence_blocked_state_fails(gate, fake_repo):
    """A blocked doc assertion can never pass the gate."""
    records_by_id, sha, head, digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite", sha, "docs/STATUS.md", digest, head, "blocked"
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "blocked" in msg.lower()


def test_doc_evidence_executable_property_requires_check(gate, fake_repo):
    """ENG-16: an executable claim with no executable check must fail."""
    records_by_id, sha, head, digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite",
        sha,
        "docs/STATUS.md",
        digest,
        head,
        "implemented",
        executable_property=True,
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"
    assert "executable" in msg.lower()


def test_doc_evidence_executable_check_failure_fails(gate, fake_repo):
    """An executable check that exits nonzero fails the doc claim."""
    records_by_id, sha, head, digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite",
        sha,
        "docs/STATUS.md",
        digest,
        head,
        "tested",
        executable_property=True,
        executable_check="python -c 'import sys; sys.exit(3)'",
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert not ok and verdict == "fail"


def test_doc_evidence_executable_check_success_passes(gate, fake_repo):
    """Clean control: a passing executable check lets a tested claim pass."""
    records_by_id, sha, head, digest = _seed_doc_repo(gate, fake_repo)
    claim = _doc_claim(
        "EV-20261106-suite",
        sha,
        "docs/STATUS.md",
        digest,
        head,
        "tested",
        executable_property=True,
        executable_check="python -c 'print(\"checked\")'",
    )
    ok, msg, verdict = gate.verify_claim(claim, records_by_id, fake_repo, TODAY, "0.1.0")
    assert ok and verdict == "pass", msg


# ---------------------------------------------------------------------------
# ENG-16: schema-aware report-card FPR aggregation
# ---------------------------------------------------------------------------


def _fpr_artifact(record_id, results):
    return _make_artifact(record_id, results)


def _fpr_records(gate, fake_repo, artifact):
    sha = _seed_fake_repo(fake_repo, artifact)
    records_by_id, failures = gate.verify_registry_records(
        fake_repo, gate.load_registry(fake_repo)
    )
    assert not failures
    return records_by_id


def test_report_card_present_but_unqualified_wilson_evidence(gate, fake_repo):
    """ENG-16: a Wilson upper bound on an unqualified slice stays unknown,
    but the card must report it accurately instead of 'no FPR anywhere'."""
    artifact = _fpr_artifact(
        "EV-20261110-human-fpr",
        {
            "worst_slice_wilson_ci_upper": 0.064196,
            "worst_document_slice_wilson_ci_upper": 0.064196,
            "slices": [
                {
                    "record_id": "evr-20261106-opai-bench-builtin-heuristic",
                    "dataset": "OpAI-Bench",
                    "slice_kind": "document",
                    "n_human": 56,
                    "fpr_native_wilson": {
                        "k": 0,
                        "n": 56,
                        "value": 0.0,
                        "ci_lower": 0.0,
                        "ci_upper": 0.064196,
                        "method": "Wilson score interval, 95% (z=1.96)",
                    },
                    "assessment": {
                        "record_id": "evr-20261106-opai-bench-builtin-heuristic",
                        "can_support_fpr_claim": False,
                        "blockers": [
                            "n_human=56 is below the 100-row minimum for a supported slice",
                            "Wilson fpr_native ci_upper is 0.064196, which exceeds the ceiling 0.05",
                        ],
                    },
                }
            ],
        },
    )
    records_by_id = _fpr_records(gate, fake_repo, artifact)
    card = gate.write_report_card(fake_repo, [], records_by_id, [])
    text = card.read_text(encoding="utf-8")
    assert "**unknown**" in text
    assert "No FPR is claimed anywhere" not in text
    assert "0.064196" in text
    assert "EV-20261110-human-fpr" in text
    assert "unqualified" in text.lower()


def test_report_card_qualified_worst_slice_wilson_lead(gate, fake_repo):
    """A worst-slice Wilson upper whose worst slice meets the bar may lead,
    labelled as a Wilson 95% upper bound (not a point rate)."""
    artifact = _fpr_artifact(
        "EV-20990101-human-fpr",
        {
            "worst_slice_wilson_ci_upper": 0.018,
            "worst_document_slice_wilson_ci_upper": 0.018,
            "slices": [
                {
                    "record_id": "evr-20990101-example-builtin-heuristic",
                    "dataset": "Example",
                    "slice_kind": "document",
                    "n_human": 200,
                    "fpr_native_wilson": {
                        "k": 0,
                        "n": 200,
                        "value": 0.0,
                        "ci_lower": 0.0,
                        "ci_upper": 0.018,
                        "method": "Wilson score interval, 95% (z=1.96)",
                    },
                    "assessment": {
                        "record_id": "evr-20990101-example-builtin-heuristic",
                        "can_support_fpr_claim": True,
                        "blockers": [],
                    },
                }
            ],
        },
    )
    records_by_id = _fpr_records(gate, fake_repo, artifact)
    card = gate.write_report_card(fake_repo, [], records_by_id, [])
    text = card.read_text(encoding="utf-8")
    assert "**unknown**" not in text
    assert "0.018" in text
    assert "Wilson" in text
    assert "EV-20990101-human-fpr" in text


def test_report_card_single_slice_wilson_does_not_fill_lead(gate, fake_repo):
    """ENG-16: one slice's Wilson upper is present evidence, not a worst-slice lead."""
    artifact = _fpr_artifact(
        "EV-20261110-dataset-opai-bench",
        {
            "human_fpr_native": {
                "k_fp": 0,
                "n_human": 218,
                "value": 0.0,
                "wilson_95_ci_lower": 0.0,
                "wilson_95_ci_upper": 0.0173,
                "method": "wilson_ci (textforensics.probe_metrics), 95%",
            }
        },
    )
    records_by_id = _fpr_records(gate, fake_repo, artifact)
    card = gate.write_report_card(fake_repo, [], records_by_id, [])
    text = card.read_text(encoding="utf-8")
    assert "**unknown**" in text
    assert "0.0173" in text
    assert "single-slice" in text.lower()


def test_report_card_pooled_values_never_fill_lead(gate, fake_repo):
    """ENG-16: pooled Wilson uppers hide heterogeneity; never a worst-slice lead."""
    artifact = _fpr_artifact(
        "EV-20261110-human-fpr",
        {
            "pooled_documents_only": {
                "k": 0,
                "n": 1002,
                "value": 0.0,
                "ci_lower": 0.0,
                "ci_upper": 0.003819,
                "method": "Wilson score interval, 95% (z=1.96)",
            },
            "pooled_all_slices_including_segments": {
                "k": 0,
                "n": 5787,
                "value": 0.0,
                "ci_lower": 0.0,
                "ci_upper": 0.000663,
                "method": "Wilson score interval, 95% (z=1.96)",
            },
        },
    )
    records_by_id = _fpr_records(gate, fake_repo, artifact)
    card = gate.write_report_card(fake_repo, [], records_by_id, [])
    text = card.read_text(encoding="utf-8")
    assert "**unknown**" in text
    # The pooled numbers may be named inside the unknown reason as
    # ineligible evidence, but they must never be presented as the
    # lead value (the bold "**<value>**" lead format).
    assert "**0.003819**" not in text
    assert "**0.000663**" not in text
    assert "pooled" in text.lower()
    assert "never a worst-slice statistic" in text


def test_report_card_best_slice_never_fills_lead(gate, fake_repo):
    """ENG-16: an ineligible best-slice value must never fill the lead."""
    artifact = _fpr_artifact(
        "EV-20261110-human-fpr",
        {"best_slice_wilson_ci_upper": 0.001, "min_slice_wilson_ci_upper": 0.001},
    )
    records_by_id = _fpr_records(gate, fake_repo, artifact)
    card = gate.write_report_card(fake_repo, [], records_by_id, [])
    text = card.read_text(encoding="utf-8")
    assert "**unknown**" in text
    lead = text.split("## Claims")[0]
    assert "0.001" not in lead


def test_report_card_legacy_point_rate_still_fills_lead(gate, fake_repo):
    """Legacy worst_slice_human_fpr point rates keep working as the lead."""
    artifact = _fpr_artifact("EV-20261106-bench", {"worst_slice_human_fpr": 0.02})
    records_by_id = _fpr_records(gate, fake_repo, artifact)
    card = gate.write_report_card(fake_repo, [], records_by_id, [])
    text = card.read_text(encoding="utf-8")
    assert "**unknown**" not in text
    assert "0.02" in text
