#!/usr/bin/env python3
"""No-publication rehearsal for the TextForensics release boundary (W10-B).

Runs the exact publishing-boundary code paths with publication disabled
and asserted, and proves each planted defect prevents promotion BEFORE
any remote write. Performs ZERO remote writes itself:

- the upload demos invoke ``publish_release.py upload --dry-run`` only
  (the W10 no-publication mode: confirmation -> typed manifest ->
  checksums -> SBOM structure -> cosign signature verification -> tag
  binding, then stop before ``gh release create``);
- the gate demos invoke ``promotion_gate.evaluate_gate`` in a subprocess
  with planted check-run records (no ``gh api`` call is made at all);
- all fixture work happens in a fresh temporary git repository with NO
  remote configured, so a push could not target anything even by accident.

Runs (control + 9 planted-defect demos):

  control  valid candidate, upload --dry-run            -> exit 0
  (a)      asset removed from the manifest              -> exit 1
  (b)      asset tampered (digest mismatch)             -> exit 1
  (c)      mismatched source SHA                        -> exit 1
  (d)      mismatched tag                               -> exit 1
  (e)      mismatched version                           -> exit 1
  (f)      missing confirmation                         -> exit 1
  (g)      a failed required check (promotion gate)     -> exit 1
  (h)      a skipped required check (promotion gate)    -> exit 1
  (i)      a stale check (promotion gate, wrong SHA)    -> exit 1

Exit code: 0 only when the control passes (exit 0), every demo fails
closed (non-zero exit), and no demo command was a remote write.

Honest limitation: the rehearsal runs with a stub ``cosign`` on PATH
that accepts every ``verify-blob`` call and logs it. The stub proves the
dry-run route reaches signature verification (the log is asserted to
contain ``verify-blob``); it does NOT prove a real Sigstore signature
verifies. Real cosign verification is a CI concern and is mock-verified
only (see the W9 report). The fixture assets are synthetic files with
correct names, checksums and SBOM markers, not a real built wheel.

Usage:
    python scripts/rehearse_no_publication.py [--json PATH] [--keep-workdir]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

VERSION = "9.9.9"
TAG = "v9.9.9"
IDENTITY = "https://github.com/strmt7/TextForensics/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"

REMOTE_WRITE_PREFIXES = (
    ("gh", "release", "create"),
    ("gh", "release", "upload"),
    ("twine", "upload"),
    ("docker", "push"),
    ("git", "push"),
)

# Driver for the promotion-gate demos: loads planted check-run records
# from a JSON file and evaluates the REAL promotion_gate.evaluate_gate in
# a subprocess, exiting 0 only when promotion is allowed.
GATE_DRIVER = (
    "import json, sys; sys.path.insert(0, sys.argv[3]); import promotion_gate; "
    "runs = json.load(open(sys.argv[1])); "
    "r = promotion_gate.evaluate_gate(runs, sys.argv[2]); "
    "[print(f\"{k}: {g['status']} ({g['reason']})\") for k, g in r['gates'].items()]; "
    "print('Promotion gate PASS' if r['overall_pass'] else 'Promotion gate BLOCKED'); "
    "sys.exit(0 if r['overall_pass'] else 1)"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def build_fixture(base: Path) -> dict:
    """Build a complete, correctly-named, correctly-checksummed synthetic
    release fixture under ``base`` (same layout as the unit-test fixture
    in tests/test_publish_release.py)."""
    dist = base / "dist"
    prov = base / "provenance"
    notes = base / "release-notes.md"
    _write(notes, b"# textforensics v9.9.9\n")
    wheel = _write(dist / f"textforensics-{VERSION}-py3-none-any.whl", b"wheel-bytes")
    sdist = _write(dist / f"textforensics-{VERSION}.tar.gz", b"sdist-bytes")
    source = _write(dist / f"textforensics-{VERSION}-source.tar.gz", b"source-bytes")
    _write(dist / f"textforensics-{VERSION}-py3-none-any.whl.sig", b"sig")
    _write(
        dist / f"textforensics-{VERSION}-py3-none-any.whl.bundle",
        b'{"verificationMaterial": {}, "dsseEnvelope": {}}',
    )
    _write(dist / f"textforensics-{VERSION}.tar.gz.sig", b"sig")
    _write(
        dist / f"textforensics-{VERSION}.tar.gz.bundle",
        b'{"verificationMaterial": {}, "dsseEnvelope": {}}',
    )
    _write(dist / f"textforensics-{VERSION}-source.tar.gz.sig", b"sig")
    _write(
        dist / f"textforensics-{VERSION}-source.tar.gz.bundle",
        b'{"verificationMaterial": {}, "dsseEnvelope": {}}',
    )
    cdx = _write(dist / "textforensics-sbom.cdx.json", b'{"bomFormat":"CycloneDX"}')
    spdx = _write(dist / "textforensics-sbom.spdx.json", b'{"spdxVersion":"SPDX-2.3"}')
    _write(dist / "textforensics-sbom.cdx.json.sig", b"sig")
    _write(
        dist / "textforensics-sbom.cdx.json.bundle",
        b'{"verificationMaterial": {}, "dsseEnvelope": {}}',
    )
    _write(dist / "textforensics-sbom.spdx.json.sig", b"sig")
    _write(
        dist / "textforensics-sbom.spdx.json.bundle",
        b'{"verificationMaterial": {}, "dsseEnvelope": {}}',
    )
    _write(base / "release-notes.md.sig", b"sig")
    _write(
        base / "release-notes.md.bundle",
        b'{"verificationMaterial": {}, "dsseEnvelope": {}}',
    )
    notes_sum = base / "release-notes.md.sha256"
    notes_sum.write_text(f"{_sha256(notes)}  release-notes.md\n", encoding="utf-8")
    _write(prov / "provenance-bundle-0.intoto.jsonl", b"provenance")
    payload_assets = [
        wheel,
        sdist,
        source,
        dist / f"textforensics-{VERSION}-py3-none-any.whl.sig",
        dist / f"textforensics-{VERSION}-py3-none-any.whl.bundle",
        dist / f"textforensics-{VERSION}.tar.gz.sig",
        dist / f"textforensics-{VERSION}.tar.gz.bundle",
        dist / f"textforensics-{VERSION}-source.tar.gz.sig",
        dist / f"textforensics-{VERSION}-source.tar.gz.bundle",
        cdx,
        spdx,
        dist / "textforensics-sbom.cdx.json.sig",
        dist / "textforensics-sbom.cdx.json.bundle",
        dist / "textforensics-sbom.spdx.json.sig",
        dist / "textforensics-sbom.spdx.json.bundle",
        notes,
        base / "release-notes.md.sig",
        base / "release-notes.md.bundle",
        prov / "provenance-bundle-0.intoto.jsonl",
    ]
    sums = dist / "SHA256SUMS"
    sums.write_text(
        "".join(f"{_sha256(a)}  {a.name}\n" for a in payload_assets),
        encoding="utf-8",
    )
    return {"dist": dist, "prov": prov, "notes": notes, "wheel": wheel}


def _all_pass_runs() -> list[dict]:
    """One passing check-run per required promotion-gate check (matrix
    jobs: two legs), at the candidate SHA."""
    sys.path.insert(0, str(SCRIPTS_DIR))
    import promotion_gate

    sha = "a" * 40
    runs = []
    for spec in promotion_gate.REQUIRED_CHECKS:
        runs.append(
            {"name": spec["check"], "status": "completed", "conclusion": "success", "head_sha": sha}
        )
        if spec.get("matrix"):
            runs.append(
                {
                    "name": spec["check"] + " 3.11",
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": sha,
                }
            )
    return runs


class Rehearsal:
    """Runs the control + demos and records every demo command."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.demo_commands: list[list[str]] = []
        self.results: list[dict] = []
        # Stub cosign: accepts every verify-blob and logs the invocation,
        # so the rehearsal can assert signature verification was reached.
        # It is a rehearsal test double, NOT a real signature check.
        self.bin_dir = workdir / "bin"
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.cosign_log = workdir / "cosign-calls.log"
        stub = self.bin_dir / "cosign"
        stub.write_text(
            "#!/bin/sh\n"
            "# REHEARSAL TEST DOUBLE: accepts every call, logs it.\n"
            f'echo "$@" >> "{self.cosign_log}"\n'
            "exit 0\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        self.env = dict(os.environ)
        self.env["PATH"] = str(self.bin_dir) + os.pathsep + self.env.get("PATH", "")

    def _run(self, argv: list[str], cwd: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
        env = dict(self.env)
        if env_extra is not None:
            env.update(env_extra)
        env.pop("RELEASE_CONFIRMATION", None)
        if env_extra and "RELEASE_CONFIRMATION" in env_extra:
            env["RELEASE_CONFIRMATION"] = env_extra["RELEASE_CONFIRMATION"]
        self.demo_commands.append([str(a) for a in argv])
        return subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, text=True)

    def upload_demo(
        self, demo_id: str, name: str, fixture: dict, source_sha: str, tag: str,
        version: str, confirmation: str | None, repo: Path,
    ) -> dict:
        argv = [
            sys.executable,
            str(SCRIPTS_DIR / "publish_release.py"),
            "upload",
            "--dry-run",
            "--notes",
            str(fixture["notes"]),
            "--dist-dir",
            str(fixture["dist"]),
            "--provenance-dir",
            str(fixture["prov"]),
            "--tag",
            tag,
            "--version",
            version,
            "--source-sha",
            source_sha,
            "--expected-identity",
            IDENTITY,
            "--expected-issuer",
            ISSUER,
        ]
        env_extra = {"RELEASE_CONFIRMATION": confirmation} if confirmation else {}
        proc = self._run(argv, cwd=repo, env_extra=env_extra)
        return self._record(demo_id, name, proc, expect_nonzero=True)

    def gate_demo(self, demo_id: str, name: str, runs: list[dict], workdir: Path) -> dict:
        runs_file = workdir / f"check-runs-{demo_id}.json"
        runs_file.write_text(json.dumps(runs), encoding="utf-8")
        argv = [
            sys.executable,
            "-c",
            GATE_DRIVER,
            str(runs_file),
            "a" * 40,
            str(SCRIPTS_DIR),
        ]
        proc = self._run(argv, cwd=workdir)
        return self._record(demo_id, name, proc, expect_nonzero=True)

    def _record(
        self, demo_id: str, name: str, proc: subprocess.CompletedProcess, expect_nonzero: bool
    ) -> dict:
        remote_writes = [
            c for c in self.demo_commands if tuple(c[:3]) in REMOTE_WRITE_PREFIXES
        ]
        passed = (proc.returncode != 0) if expect_nonzero else (proc.returncode == 0)
        result = {
            "id": demo_id,
            "name": name,
            "exit_code": proc.returncode,
            "expected": "non-zero (fail closed)" if expect_nonzero else "0",
            "passed": bool(passed),
            "remote_writes_in_demo_commands": remote_writes,
            "stdout_tail": (proc.stdout or "").strip().splitlines()[-1:]
            + (proc.stderr or "").strip().splitlines()[-1:],
        }
        self.results.append(result)
        return result


def run_rehearsal(workdir: Path) -> dict:
    """Build the fixture repo, run the control + 9 demos, return the report."""
    repo = workdir / "fixture-repo"
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.email", "rehearsal@example.invalid"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "W10 rehearsal"], cwd=str(repo), check=True)
    (repo / "README").write_text("rehearsal fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-qm", "rehearsal fixture"], cwd=str(repo), check=True)
    subprocess.run(["git", "tag", TAG, "HEAD"], cwd=str(repo), check=True)
    source_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(repo), capture_output=True, text=True, check=True
    ).stdout.strip()
    remotes = subprocess.run(
        ["git", "remote"], cwd=str(repo), capture_output=True, text=True, check=True
    ).stdout.strip()
    assert remotes == "", f"fixture repo unexpectedly has remotes: {remotes}"

    rh = Rehearsal(workdir)

    # Control: valid candidate, upload --dry-run must exit 0.
    control_fx = build_fixture(workdir / "control")
    argv = [
        sys.executable,
        str(SCRIPTS_DIR / "publish_release.py"),
        "upload",
        "--dry-run",
        "--notes",
        str(control_fx["notes"]),
        "--dist-dir",
        str(control_fx["dist"]),
        "--provenance-dir",
        str(control_fx["prov"]),
        "--tag",
        TAG,
        "--version",
        VERSION,
        "--source-sha",
        source_sha,
        "--expected-identity",
        IDENTITY,
        "--expected-issuer",
        ISSUER,
    ]
    proc = rh._run(argv, cwd=repo, env_extra={"RELEASE_CONFIRMATION": "RELEASE"})
    control = {
        "id": "control",
        "name": "valid candidate, upload --dry-run",
        "exit_code": proc.returncode,
        "expected": "0",
        "passed": proc.returncode == 0,
        "stdout_tail": (proc.stdout or "").strip().splitlines()[-2:],
    }
    rh.results.append(control)
    # The control must have reached cosign signature verification: the
    # stub log must contain verify-blob calls (the dry run routes through
    # the same signature checks as a real upload).
    cosign_calls = rh.cosign_log.read_text(encoding="utf-8") if rh.cosign_log.exists() else ""
    control["signature_verification_reached"] = "verify-blob" in cosign_calls
    if not control["signature_verification_reached"]:
        control["passed"] = False

    # (a) asset removed from the manifest.
    fx_a = build_fixture(workdir / "demo-a")
    fx_a["wheel"].unlink()
    rh.upload_demo("a", "asset removed from manifest", fx_a, source_sha, TAG, VERSION, "RELEASE", repo)

    # (b) asset tampered (digest mismatch).
    fx_b = build_fixture(workdir / "demo-b")
    fx_b["wheel"].write_bytes(b"tampered-wheel-bytes")
    rh.upload_demo("b", "asset tampered (digest mismatch)", fx_b, source_sha, TAG, VERSION, "RELEASE", repo)

    # (c) mismatched source SHA.
    fx_c = build_fixture(workdir / "demo-c")
    rh.upload_demo("c", "mismatched source SHA", fx_c, "d" * 40, TAG, VERSION, "RELEASE", repo)

    # (d) mismatched tag.
    fx_d = build_fixture(workdir / "demo-d")
    rh.upload_demo("d", "mismatched tag", fx_d, source_sha, "v0.0.0", VERSION, "RELEASE", repo)

    # (e) mismatched version.
    fx_e = build_fixture(workdir / "demo-e")
    rh.upload_demo("e", "mismatched version", fx_e, source_sha, TAG, "9.9.8", "RELEASE", repo)

    # (f) missing confirmation.
    fx_f = build_fixture(workdir / "demo-f")
    rh.upload_demo("f", "missing confirmation", fx_f, source_sha, TAG, VERSION, None, repo)

    # (g) a failed required check (promotion gate).
    runs_g = _all_pass_runs()
    for r in runs_g:
        if "Claims" in r["name"]:
            r["conclusion"] = "failure"
    rh.gate_demo("g", "failed required check (promotion gate)", runs_g, workdir)

    # (h) a skipped required check (promotion gate).
    runs_h = _all_pass_runs()
    for r in runs_h:
        if "Claims" in r["name"]:
            r["conclusion"] = "skipped"
    rh.gate_demo("h", "skipped required check (promotion gate)", runs_h, workdir)

    # (i) a stale check (promotion gate: check-run recorded at another SHA).
    runs_i = _all_pass_runs()
    for r in runs_i:
        if "Reproducibility" in r["name"]:
            r["head_sha"] = "b" * 40
    rh.gate_demo("i", "stale check (promotion gate, wrong SHA)", runs_i, workdir)

    remote_writes = [c for c in rh.demo_commands if tuple(c[:3]) in REMOTE_WRITE_PREFIXES]
    overall = (
        all(r["passed"] for r in rh.results)
        and control["passed"]
        and not remote_writes
    )
    return {
        "control": control,
        "demos": [r for r in rh.results if r["id"] != "control"],
        "results": rh.results,
        "demo_commands": rh.demo_commands,
        "remote_write_commands": remote_writes,
        "overall_pass": bool(overall),
        "fixture_source_sha": source_sha,
        "note": (
            "Stub cosign used: verify-blob calls were accepted by a rehearsal "
            "test double (see module docstring). No remote write was made: "
            "fixture repo has no remote; no demo command matches a remote-write prefix."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", default=None, help="Write the JSON report to PATH.")
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="Keep the temporary work directory and print its path.",
    )
    args = parser.parse_args(argv)
    tmp = tempfile.mkdtemp(prefix="w10-no-publication-")
    workdir = Path(tmp)
    try:
        report = run_rehearsal(workdir)
    finally:
        if not args.keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)
    if args.keep_workdir:
        print(f"workdir kept at: {workdir}")
    for r in report["results"]:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"[{status}] {r['id']}: {r['name']} -> exit {r['exit_code']} (expected {r['expected']})")
    print(f"remote-write commands issued by demos: {len(report['remote_write_commands'])}")
    print(f"overall: {'PASS' if report['overall_pass'] else 'FAIL'}")
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"report written to {args.json}")
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
