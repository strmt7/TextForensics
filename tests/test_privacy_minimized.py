"""W7 Worker D regression tests: privacy-minimized evidence successors.

Guards the W7 half of the privacy disposition gate
(`docs/evidence/runs/privacy-minimized/README.md`):

- the minimized successors carry the same evidence values as the
  originals except for the host-neutral `command`, and contain no
  home-directory path at all;
- the originals are byte-identical to the registry digests (never
  edited in place — they are digest-bound claims evidence);
- the lineage README records both source digests, both successor
  digests and the source commit;
- the minimized operational log carries its lineage header and no
  home-directory path, with the 4 redacted traceback frames still
  pointing at the repo-relative test file;
- the two fixture occurrences are already host-neutral (no real home
  path recorded in them).

The tests never assert on, print, or otherwise reproduce the
personal path values themselves: comparisons use only the successor
values, digests, and the boolean "real home path absent" property.
Lineage values (source commit, source sha256) are read out of the
log's own header and cross-checked against the README — they are
never hardcoded here, so this file contains no high-entropy literals
for the secret scanner to flag.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
RUNS = REPO_ROOT / "docs" / "evidence" / "runs"
MINIMIZED = RUNS / "privacy-minimized"
LOG = REPO_ROOT / "docs" / "live-host-api" / "fullsuite2.log"
README = MINIMIZED / "README.md"

SUITE_NAMES = ("EV-20261106-suite.json", "EV-20261107-suite.json")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _log_header_lineage() -> tuple[str, str]:
    """Source commit + source sha256, as recorded in the log header."""
    header = LOG.read_text(encoding="utf-8", errors="replace").splitlines()[:12]
    text = "\n".join(header)
    commit = re.search(r"commit ([0-9a-f]{40})", text)
    digest = re.search(r"source sha256:\n# ([0-9a-f]{64})", text)
    assert commit and digest, "log lineage header is malformed"
    return commit.group(1), digest.group(1)


def test_successors_match_originals_except_command():
    for name in SUITE_NAMES:
        original = json.loads((RUNS / name).read_text(encoding="utf-8"))
        successor = json.loads((MINIMIZED / name).read_text(encoding="utf-8"))
        assert list(original.keys()) == list(successor.keys()), name
        for key in original:
            if key != "command":
                assert original[key] == successor[key], f"{name}:{key}"
        command = successor["command"]
        assert command.startswith("python -m pytest "), name
        assert "/home/" not in command, name


def test_successors_and_log_contain_no_home_path():
    for name in SUITE_NAMES:
        assert "/home/" not in (MINIMIZED / name).read_text(encoding="utf-8")
    assert "/home/" not in LOG.read_text(encoding="utf-8", errors="replace")


def test_originals_still_match_registry_digests():
    registry = json.loads(
        (REPO_ROOT / "docs" / "evidence" / "registry.json").read_text(encoding="utf-8")
    )
    by_id = {r["evidence_record_id"]: r for r in registry["records"]}
    for name in SUITE_NAMES:
        record_id = name[: -len(".json")]
        record = by_id[record_id]
        assert record["run_artifact"] == f"docs/evidence/runs/{name}"
        assert _sha256(RUNS / name) == record["run_artifact_sha256"], name


def test_readme_records_lineage():
    text = README.read_text(encoding="utf-8")
    source_commit, source_sha = _log_header_lineage()
    assert source_commit in text, "README must record the source commit"
    assert source_sha in text, "README must record the log source sha256"
    for name in SUITE_NAMES:
        assert name in text
        assert _sha256(RUNS / name) in text, f"missing source digest for {name}"
        assert _sha256(MINIMIZED / name) in text, f"missing successor digest for {name}"
    # The README legitimately names the "/home/" scan pattern as generic
    # text; what it must not contain is the real home directory.
    assert str(Path.home()) not in text, "lineage README must not reproduce the real home path"


def test_log_minimized_in_place_with_lineage():
    text = LOG.read_text(encoding="utf-8", errors="replace")
    assert text.startswith("# PRIVACY-MINIMIZED SUCCESSOR"), "lineage header missing"
    source_commit, source_sha = _log_header_lineage()
    assert source_commit in text
    assert source_sha in text
    # The file really was minimized: its current digest differs from the
    # source digest its own header records.
    assert _sha256(LOG) != source_sha
    # The 4 redacted traceback frames still name the repo-relative file.
    assert text.count('File "tests/test_datasets.py"') == 4


def test_fixtures_record_no_real_home_path():
    # The two fixture occurrences are generic placeholders / probes:
    # neither may contain the executing account's real home directory.
    home = str(Path.home())
    for path in (
        REPO_ROOT / "tests" / "fuzz" / "generate_corpus.py",
        REPO_ROOT / "tests" / "test_w1_web_console.py",
    ):
        assert home not in path.read_text(encoding="utf-8"), path
