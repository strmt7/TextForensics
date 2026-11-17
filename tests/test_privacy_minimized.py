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

W10 Worker D extends the same guards to the three W8 registry-bound
run artifacts (minimized `cache_file` / `detail` fields) and to the
five W8 reproduce scripts (minimized in place to `REPO_ROOT`-relative
paths; see the README's W10 section).

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

# W10: the three W8 registry-bound run artifacts, and the exact JSON
# paths whose values were minimized (field path -> minimized form).
W8_NAMES = (
    "EV-20261116-ood-short-refusal.json",
    "EV-20261116-reproduction-detectrl-x.json",
    "EV-20261116-reproduction-registry.json",
)

REPRODUCE_SCRIPTS = (
    "reproduce_w8a_mage.py",
    "reproduce_w8a_raid.py",
    "reproduce_w8b_beemo.py",
    "reproduce_w8c_ghostwriter.py",
    "reproduce_w8c_opai.py",
)


def _diff_paths(original, successor, path=""):
    """JSON paths whose values differ between the two documents."""
    if type(original) is not type(successor):
        return [path]
    if isinstance(original, dict):
        assert list(original.keys()) == list(successor.keys()), path
        out = []
        for key in original:
            out += _diff_paths(
                original[key],
                successor[key],
                f"{path}.{key}" if path else key,
            )
        return out
    if isinstance(original, list):
        assert len(original) == len(successor), path
        out = []
        for i, (a, b) in enumerate(zip(original, successor, strict=True)):
            out += _diff_paths(a, b, f"{path}[{i}]")
        return out
    return [path] if original != successor else []


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
    for name in SUITE_NAMES + W8_NAMES:
        record_id = name[: -len(".json")]
        record = by_id[record_id]
        assert record["run_artifact"] == f"docs/evidence/runs/{name}"
        assert _sha256(RUNS / name) == record["run_artifact_sha256"], name


def test_w8_successors_match_originals_except_path_fields():
    home = str(Path.home())
    for name in W8_NAMES:
        original = json.loads((RUNS / name).read_text(encoding="utf-8"))
        successor = json.loads((MINIMIZED / name).read_text(encoding="utf-8"))
        assert list(original.keys()) == list(successor.keys()), name
        differing = _diff_paths(original, successor)
        assert differing, f"{name}: successor is byte-identical, nothing minimized"
        for path in differing:
            assert path.endswith(("cache_file", "detail")), f"{name}:{path}"
        # Every differing value is the host-neutral form of the original:
        # cache_file keeps the `.cache/...` tail under `$HOME`; detail
        # keeps the `docs/evidence/...` tail repo-relative. The check
        # derives the expected value from the original at runtime, so
        # this file never records the personal path itself.
        for path in differing:
            keys = re.findall(r"[^.\[\]]+|\[\d+\]", path)
            orig_value = original
            succ_value = successor
            for key in keys:
                if key.startswith("["):
                    orig_value = orig_value[int(key[1:-1])]
                    succ_value = succ_value[int(key[1:-1])]
                else:
                    orig_value = orig_value[key]
                    succ_value = succ_value[key]
            if path.endswith("cache_file"):
                # Home-directory independent: the original records
                # some account's home (<home>/.cache/... — recorded
                # as /home/hatch, while CI runs as /home/runner), so
                # the expected minimized form must be derived from
                # the original value itself, not from the executing
                # account's home (Path.home()). The successor keeps
                # only the `$HOME/.cache/...` tail.
                assert "/.cache/" in orig_value, f"{name}:{path}"
                assert orig_value.startswith("/"), f"{name}:{path}"
                tail = orig_value.split("/.cache/", 1)[1]
                assert succ_value == f"$HOME/.cache/{tail}", f"{name}:{path}"
            else:  # detail: repo-relative tail of the original path
                tail = orig_value.split("docs/evidence/", 1)[1]
                assert succ_value == f"docs/evidence/{tail}", f"{name}:{path}"
            assert "/home/" not in succ_value, f"{name}:{path}"
            assert home not in succ_value, f"{name}:{path}"


def test_w8_successors_contain_no_home_path():
    for name in W8_NAMES:
        assert "/home/" not in (MINIMIZED / name).read_text(encoding="utf-8")


def test_reproduce_scripts_contain_no_home_path():
    # The five W8 reproduce scripts were minimized in place (W10):
    # their worker-checkout absolute paths are now REPO_ROOT-relative,
    # so no script records the executing account's home directory.
    for name in REPRODUCE_SCRIPTS:
        text = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
        assert "/home/" not in text, name
        assert "REPO_ROOT = Path(__file__).parent.parent" in text, name


def test_readme_records_lineage():
    text = README.read_text(encoding="utf-8")
    source_commit, source_sha = _log_header_lineage()
    assert source_commit in text, "README must record the source commit"
    assert source_sha in text, "README must record the log source sha256"
    for name in SUITE_NAMES:
        assert name in text
        assert _sha256(RUNS / name) in text, f"missing source digest for {name}"
        assert _sha256(MINIMIZED / name) in text, f"missing successor digest for {name}"
    # W10 successors: the README must record their digests too.
    for name in W8_NAMES:
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
