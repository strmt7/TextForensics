"""Tests for scripts/rehearse_no_publication.py (W10-B).

Runs the rehearsal end to end as a subprocess and asserts its contract:
the control (valid candidate, upload --dry-run) exits 0, every one of
the 9 planted-defect demos fails closed with a non-zero exit code, and
no demo command was a remote write. The rehearsal itself performs zero
remote writes (fixture repo has no remote; only `upload --dry-run` and
the in-process promotion-gate driver are invoked).
"""

import json
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"

EXPECTED_DEMO_IDS = ["a", "b", "c", "d", "e", "f", "g", "h", "i"]


def test_rehearsal_passes_end_to_end(tmp_path):
    report_path = tmp_path / "rehearsal-report.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS_DIR / "rehearse_no_publication.py"),
            "--json",
            str(report_path),
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"rehearsal failed:\n{proc.stdout}\n{proc.stderr}"
    assert "overall: PASS" in proc.stdout
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["overall_pass"] is True

    control = report["control"]
    assert control["exit_code"] == 0
    assert control["passed"] is True
    assert control["signature_verification_reached"] is True

    demos = {d["id"]: d for d in report["demos"]}
    assert sorted(demos) == sorted(EXPECTED_DEMO_IDS)
    for demo_id, demo in demos.items():
        assert demo["exit_code"] != 0, f"demo {demo_id} did not fail closed"
        assert demo["passed"] is True
        assert demo["remote_writes_in_demo_commands"] == []

    assert report["remote_write_commands"] == []
    # No demo command may be a remote-writing invocation, by prefix.
    remote_prefixes = (
        ("gh", "release", "create"),
        ("gh", "release", "upload"),
        ("twine", "upload"),
        ("docker", "push"),
        ("git", "push"),
    )
    for cmd in report["demo_commands"]:
        assert tuple(cmd[:3]) not in remote_prefixes, f"remote write issued: {cmd}"
