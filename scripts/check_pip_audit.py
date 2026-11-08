#!/usr/bin/env python3
"""pip-audit gate for TextForensics.

Runs pip-audit against the installed environment AND
``requirements-pinned.txt``, and compares every finding against the
checked-in baseline (``pip-audit-baseline.toml``). The gate is the
pip-audit analogue of the mutation gate in ``scripts/run_mutation.py``:
a finding is either matched by a per-finding baseline entry, or the
run fails. There are no blanket ignores, no ``--ignore`` flags, and
no severity downgrades.

The bar (documented in the baseline file): zero NEW findings. A
finding is new when its package, vulnerability id, or affected
version is not covered by a baseline entry. pip-audit may report the
same vulnerability more than once (two advisory sources); findings
are deduplicated on (package, version, vulnerability id) before
matching, and the raw count is still reported.

Exit codes (mirroring the mutation gate):

- 0: pass. Every finding is baselined; dormant baseline entries
  (findings already fixed) are reported, not failed.
- 1: configuration / execution error, or a still-present finding
  whose baseline entry is past its ``review_by`` date (expired
  baseline entry — a human must re-check it).
- 2: one or more NEW findings (fail loudly, never pass silently).

Usage::

    python scripts/check_pip_audit.py [--baseline PATH]
        [--requirements PATH | --no-requirements] [--report PATH]

``--report`` writes a JSON summary (sources, raw/unique/baselined/
new counts, per-finding classification) for CI artifacts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_BASELINE = REPO_ROOT / "pip-audit-baseline.toml"
DEFAULT_REQUIREMENTS = REPO_ROOT / "requirements-pinned.txt"

EXIT_PASS = 0
EXIT_ERROR = 1
EXIT_NEW_FINDINGS = 2

_REQUIRED_ENTRY_FIELDS = (
    "package",
    "vuln_id",
    "aliases",
    "affected_versions",
    "fixed_in",
    "reason",
    "review_by",
)


class GateError(Exception):
    """Baseline, configuration, or pip-audit execution error (exit 1)."""


@dataclass(frozen=True)
class Finding:
    """One deduplicated pip-audit vulnerability finding."""

    package: str
    version: str
    vuln_id: str
    aliases: tuple[str, ...] = ()
    fix_versions: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.package.lower(), self.version, self.vuln_id)

    @property
    def all_ids(self) -> set[str]:
        return {self.vuln_id, *self.aliases}


@dataclass
class BaselineEntry:
    """One accepted finding from pip-audit-baseline.toml."""

    package: str
    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    fixed_in: str = ""
    reason: str = ""
    review_by: date | None = None

    @property
    def all_ids(self) -> set[str]:
        return {self.vuln_id, *self.aliases}

    def matches(self, finding: Finding) -> bool:
        """Exact match: same package, same vulnerability (id or alias),
        same affected version. A different version is a new finding."""
        return (
            finding.package.lower() == self.package.lower()
            and bool(finding.all_ids & self.all_ids)
            and finding.version in self.affected_versions
        )


@dataclass
class AuditResult:
    """One pip-audit run (installed env or pinned requirements)."""

    source: str
    findings: list[Finding]
    raw_findings: int


@dataclass
class Classification:
    """A finding set classified against the baseline."""

    baselined: list[tuple[Finding, BaselineEntry]]
    new: list[Finding]
    dormant: list[BaselineEntry]
    expired: list[tuple[Finding, BaselineEntry]]


def load_baseline(path: Path) -> list[BaselineEntry]:
    """Load and strictly validate the baseline file.

    Raises GateError on a missing file, malformed TOML, a missing or
    mistyped field, a bad review date, or a duplicate
    (package, vuln_id) entry. A malformed baseline fails loudly
    (exit 1) instead of passing silently.
    """
    if not path.is_file():
        raise GateError(f"baseline file not found: {path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"baseline file is not valid TOML: {exc}") from exc
    raw_entries = data.get("finding")
    if not isinstance(raw_entries, list):
        raise GateError("baseline file has no [[finding]] entries")
    entries: list[BaselineEntry] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_entries):
        where = f"baseline entry #{index + 1}"
        if not isinstance(raw, dict):
            raise GateError(f"{where}: not a table")
        for field_name in _REQUIRED_ENTRY_FIELDS:
            if field_name not in raw:
                raise GateError(f"{where}: missing required field {field_name!r}")
        try:
            review_by = date.fromisoformat(str(raw["review_by"]))
        except ValueError as exc:
            raise GateError(
                f"{where}: review_by {raw['review_by']!r} is not a YYYY-MM-DD date"
            ) from exc
        if not isinstance(raw["aliases"], list) or not all(
            isinstance(a, str) for a in raw["aliases"]
        ):
            raise GateError(f"{where}: aliases must be a list of strings")
        if not isinstance(raw["affected_versions"], list) or not raw["affected_versions"]:
            raise GateError(f"{where}: affected_versions must be a non-empty list of strings")
        if not all(isinstance(v, str) for v in raw["affected_versions"]):
            raise GateError(f"{where}: affected_versions must be a list of strings")
        key = (str(raw["package"]).lower(), str(raw["vuln_id"]))
        if key in seen:
            raise GateError(f"{where}: duplicate entry for {key[0]} {key[1]}")
        seen.add(key)
        entries.append(
            BaselineEntry(
                package=str(raw["package"]),
                vuln_id=str(raw["vuln_id"]),
                aliases=list(raw["aliases"]),
                affected_versions=list(raw["affected_versions"]),
                fixed_in=str(raw["fixed_in"]),
                reason=str(raw["reason"]),
                review_by=review_by,
            )
        )
    return entries


def parse_pip_audit_json(data: dict) -> tuple[list[Finding], int]:
    """Parse pip-audit ``--format json`` output.

    Returns (deduplicated findings, raw finding count). pip-audit
    reports the same vulnerability more than once when two advisory
    sources carry it, so duplicates on (package, version, vuln id)
    collapse to one finding; the raw count is kept for the report.
    """
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, list):
        raise GateError("pip-audit output has no 'dependencies' list")
    raw = 0
    by_key: dict[tuple[str, str, str], Finding] = {}
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name", ""))
        version = str(dep.get("version", ""))
        vulns = dep.get("vulns") or []
        for vuln in vulns:
            if not isinstance(vuln, dict) or "id" not in vuln:
                continue
            raw += 1
            finding = Finding(
                package=name,
                version=version,
                vuln_id=str(vuln["id"]),
                aliases=tuple(str(a) for a in (vuln.get("aliases") or [])),
                fix_versions=tuple(str(f) for f in (vuln.get("fix_versions") or [])),
            )
            # First report wins; duplicates carry the same id/version
            # (one case differs only in fix-version spelling, 26.2 vs
            # 26.2.0, which is not a distinguishing fact).
            by_key.setdefault(finding.key, finding)
    return list(by_key.values()), raw


def run_pip_audit(requirements: Path | None, source: str) -> AuditResult:
    """Run pip-audit once and return its findings.

    pip-audit exits 1 when findings are present — that is a normal
    result, not an error. Any other non-zero exit, missing module, or
    unparsable output is a GateError (exit 1).
    """
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json", "--desc=on"]
    if requirements is not None:
        cmd += ["-r", str(requirements)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise GateError(f"could not run pip-audit: {exc}") from exc
    if result.returncode not in (0, 1):
        raise GateError(
            f"pip-audit ({source}) failed with exit {result.returncode}: "
            f"{result.stderr.strip()[:500]}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(
            f"pip-audit ({source}) produced unparsable JSON: {exc}; "
            f"stderr: {result.stderr.strip()[:500]}"
        ) from exc
    findings, raw = parse_pip_audit_json(data)
    return AuditResult(source=source, findings=findings, raw_findings=raw)


def classify(findings: list[Finding], baseline: list[BaselineEntry], today: date) -> Classification:
    """Classify findings against the baseline.

    A finding is baselined when some entry matches it exactly. An
    entry that matched no finding is dormant (the finding is fixed;
    reported, not failed — a human removes the entry). A baselined
    finding whose entry is past ``review_by`` is expired.
    """
    baselined: list[tuple[Finding, BaselineEntry]] = []
    new: list[Finding] = []
    matched_entries: set[int] = set()
    for finding in findings:
        match_index = next((i for i, e in enumerate(baseline) if e.matches(finding)), None)
        if match_index is None:
            new.append(finding)
        else:
            matched_entries.add(match_index)
            baselined.append((finding, baseline[match_index]))
    dormant = [e for i, e in enumerate(baseline) if i not in matched_entries]
    expired = [(f, e) for f, e in baselined if e.review_by is not None and e.review_by < today]
    return Classification(baselined=baselined, new=new, dormant=dormant, expired=expired)


def _finding_line(finding: Finding) -> str:
    fix = f" (fixed in {', '.join(finding.fix_versions)})" if finding.fix_versions else ""
    return f"  - {finding.package} {finding.version}: {finding.vuln_id}{fix}"


def build_report(audits: list[AuditResult], classification: Classification, today: date) -> dict:
    """Machine-readable summary for CI artifacts."""
    return {
        "schema": "textforensics.pip-audit-gate/v1",
        "run_date": today.isoformat(),
        "sources": [
            {
                "source": a.source,
                "findings_raw": a.raw_findings,
                "findings_unique": len(a.findings),
            }
            for a in audits
        ],
        "findings_raw_total": sum(a.raw_findings for a in audits),
        "findings_unique_total": sum(len(a.findings) for a in audits),
        "baselined": len(classification.baselined),
        "new": len(classification.new),
        "dormant_baseline_entries": len(classification.dormant),
        "expired_baseline_entries": len(classification.expired),
        "new_findings": [
            {
                "package": f.package,
                "version": f.version,
                "vuln_id": f.vuln_id,
                "aliases": list(f.aliases),
                "fix_versions": list(f.fix_versions),
            }
            for f in classification.new
        ],
        "expired_findings": [
            {
                "package": f.package,
                "version": f.version,
                "vuln_id": f.vuln_id,
                "review_by": e.review_by.isoformat() if e.review_by else None,
            }
            for f, e in classification.expired
        ],
        "dormant_entries": [
            {"package": e.package, "vuln_id": e.vuln_id} for e in classification.dormant
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help="baseline TOML (default: pip-audit-baseline.toml)",
    )
    parser.add_argument(
        "--requirements",
        type=Path,
        default=DEFAULT_REQUIREMENTS,
        help="requirements file for the pinned audit (default: requirements-pinned.txt)",
    )
    parser.add_argument(
        "--no-requirements",
        action="store_true",
        help="skip the pinned-requirements audit (installed env only)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="write a JSON summary to this path (CI artifact)",
    )
    args = parser.parse_args(argv)
    today = date.today()

    try:
        baseline = load_baseline(args.baseline)
        audits = [run_pip_audit(None, "installed environment")]
        if not args.no_requirements:
            if not args.requirements.is_file():
                raise GateError(f"requirements file not found: {args.requirements}")
            audits.append(
                run_pip_audit(args.requirements, f"pinned requirements ({args.requirements})")
            )
    except GateError as exc:
        print(f"pip-audit gate ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = [f for audit in audits for f in audit.findings]
    classification = classify(findings, baseline, today)

    for audit in audits:
        print(f"{audit.source}: {audit.raw_findings} raw findings, {len(audit.findings)} unique")
    print(f"baseline entries: {len(baseline)}")
    print(f"baselined findings: {len(classification.baselined)}")
    if classification.dormant:
        print("dormant baseline entries (finding fixed, entry awaits removal):")
        for entry in classification.dormant:
            print(f"  - {entry.package}: {entry.vuln_id}")
    if classification.expired:
        print("EXPIRED baseline entries (finding still present past review_by):")
        for finding, entry in classification.expired:
            print(
                f"  - {finding.package} {finding.version}: {finding.vuln_id} "
                f"(review_by {entry.review_by})"
            )
    if classification.new:
        print(f"NEW findings ({len(classification.new)}):")
        for finding in classification.new:
            print(_finding_line(finding))

    if args.report is not None:
        args.report.write_text(
            json.dumps(build_report(audits, classification, today), indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"report written to {args.report}")

    if classification.expired:
        print(
            "pip-audit gate FAILED: expired baseline entries — "
            "re-check them and update review_by or fix the dependency.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if classification.new:
        print(
            "pip-audit gate FAILED: new findings — add a baseline entry "
            "with reason and review date, or fix the dependency.",
            file=sys.stderr,
        )
        return EXIT_NEW_FINDINGS
    print("pip-audit gate PASSED: no new findings.")
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
