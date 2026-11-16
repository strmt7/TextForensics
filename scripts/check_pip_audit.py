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
  baseline entry — a human must re-check it). Also exit 1: any
  package pip-audit did not actually audit — a skipped package with
  no recorded ``[[skip]]`` entry, an unresolved package, an expired
  recorded skip, malformed audit output, or an audit result with no
  coverage data at all (ENG-11: a skip is an explicit, recorded
  state, never silently zero vulnerabilities).
- 2: one or more NEW findings (fail loudly, never pass silently).

Coverage (ENG-11)
-----------------
Every dependency pip-audit reports is classified into exactly one
coverage state — ``audited`` (a vulns list was returned, possibly
empty), ``skipped`` (a ``skip_reason`` was returned: private,
editable, or unresolvable packages, e.g. the project itself, which
is not on PyPI), or ``unresolved`` (a named entry with neither a
vulns list nor a skip reason). The counts reconcile per source:
``total == audited + skipped + unresolved``, and the report lists
every package with its state. A skipped package passes only when a
``[[skip]]`` entry in the baseline records it (package, reason,
review date); an unrecorded skip fails the gate. A recorded skip
whose package is no longer skipped is dormant (reported, not
failed); a recorded skip still present past its review date fails.

Usage::

    python scripts/check_pip_audit.py [--baseline PATH]
        [--requirements PATH | --no-requirements] [--report PATH]
    python scripts/check_pip_audit.py --from-json audit.json
        [--baseline PATH] [--report PATH]
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

_REQUIRED_SKIP_FIELDS = (
    "package",
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
    # ENG-11: per-package coverage of this run. None only for
    # hand-built results (tests); a real run always populates it, and
    # main() fails closed when it is missing.
    coverage: CoverageSummary | None = None


@dataclass(frozen=True)
class PackageCoverage:
    """The audit coverage state of one reported dependency (ENG-11)."""

    name: str
    version: str
    state: str  # "audited" | "skipped" | "unresolved"
    skip_reason: str = ""
    vuln_count: int = 0


@dataclass
class CoverageSummary:
    """Per-source coverage: every reported dependency in exactly one
    state. Counts reconcile: total == audited + skipped + unresolved."""

    packages: list[PackageCoverage]

    @property
    def total(self) -> int:
        return len(self.packages)

    @property
    def audited(self) -> int:
        return sum(1 for p in self.packages if p.state == "audited")

    @property
    def skipped(self) -> int:
        return sum(1 for p in self.packages if p.state == "skipped")

    @property
    def unresolved(self) -> int:
        return sum(1 for p in self.packages if p.state == "unresolved")

    def assert_reconciles(self) -> None:
        """Internal consistency: the states partition the packages."""
        assert self.total == self.audited + self.skipped + self.unresolved, (
            f"coverage does not reconcile: total {self.total} != "
            f"audited {self.audited} + skipped {self.skipped} + "
            f"unresolved {self.unresolved}"
        )


@dataclass(frozen=True)
class SkipEntry:
    """One explicitly recorded expected skip from the baseline (ENG-11).

    A package pip-audit cannot audit (private, editable, not on PyPI)
    passes only when an entry records it, with a reason and a review
    date — the same discipline as an accepted finding.
    """

    package: str
    reason: str
    review_by: date | None = None


@dataclass
class CoverageGate:
    """Skipped/unresolved packages checked against recorded skips."""

    expected: list[PackageCoverage]
    unexpected: list[PackageCoverage]
    unresolved: list[PackageCoverage]
    dormant: list[SkipEntry]
    expired: list[tuple[PackageCoverage, SkipEntry]]


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


def load_skip_entries(path: Path) -> list[SkipEntry]:
    """Load and strictly validate the ``[[skip]]`` entries of the
    baseline file (ENG-11).

    Raises GateError on a missing file, malformed TOML, a missing or
    mistyped field, a bad review date, or a duplicate package entry.
    A baseline with no ``[[skip]]`` section yields no entries.
    """
    if not path.is_file():
        raise GateError(f"baseline file not found: {path}")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"baseline file is not valid TOML: {exc}") from exc
    raw_entries = data.get("skip", [])
    if not isinstance(raw_entries, list):
        raise GateError("baseline file [[skip]] section is not a list")
    entries: list[SkipEntry] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries):
        where = f"baseline skip entry #{index + 1}"
        if not isinstance(raw, dict):
            raise GateError(f"{where}: not a table")
        for field_name in _REQUIRED_SKIP_FIELDS:
            if field_name not in raw:
                raise GateError(f"{where}: missing required field {field_name!r}")
        try:
            review_by = date.fromisoformat(str(raw["review_by"]))
        except ValueError as exc:
            raise GateError(
                f"{where}: review_by {raw['review_by']!r} is not a YYYY-MM-DD date"
            ) from exc
        key = str(raw["package"]).lower()
        if not key:
            raise GateError(f"{where}: package must not be empty")
        if key in seen:
            raise GateError(f"{where}: duplicate skip entry for {key}")
        seen.add(key)
        entries.append(
            SkipEntry(
                package=str(raw["package"]),
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

    ENG-11: malformed entries fail closed (GateError) instead of
    being silently skipped — a non-dict dependency, a missing/empty
    name, a non-list vulns value, a vuln entry without an id, or an
    audited dependency without a version means the audit output
    cannot be trusted, so the gate errors rather than reporting
    zero findings for that package.
    """
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, list):
        raise GateError("pip-audit output has no 'dependencies' list")
    raw = 0
    by_key: dict[tuple[str, str, str], Finding] = {}
    for index, dep in enumerate(dependencies):
        where = f"pip-audit dependency #{index + 1}"
        if not isinstance(dep, dict):
            raise GateError(f"{where}: not an object")
        name = str(dep.get("name", ""))
        if not name:
            raise GateError(f"{where}: missing package name")
        version = str(dep.get("version", ""))
        vulns = dep.get("vulns") or []
        if not isinstance(vulns, list):
            raise GateError(f"{where} ({name}): 'vulns' is not a list")
        if vulns and not version:
            raise GateError(f"{where} ({name}): audited dependency has no version")
        for vuln in vulns:
            if not isinstance(vuln, dict) or "id" not in vuln:
                raise GateError(f"{where} ({name}): malformed vulnerability entry")
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


def parse_pip_audit_coverage(data: dict) -> CoverageSummary:
    """Classify every reported dependency into a coverage state
    (ENG-11): ``audited`` (a vulns list was returned, possibly
    empty), ``skipped`` (a ``skip_reason`` was returned), or
    ``unresolved`` (a named entry with neither a vulns list nor a
    skip reason). Raises GateError on malformed output — a
    dependency pip-audit reports without a usable audit state must
    never silently count as zero vulnerabilities.
    """
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, list):
        raise GateError("pip-audit output has no 'dependencies' list")
    packages: list[PackageCoverage] = []
    for index, dep in enumerate(dependencies):
        where = f"pip-audit dependency #{index + 1}"
        if not isinstance(dep, dict):
            raise GateError(f"{where}: not an object")
        name = str(dep.get("name", ""))
        if not name:
            raise GateError(f"{where}: missing package name")
        version = str(dep.get("version", ""))
        if "skip_reason" in dep:
            vulns = dep.get("vulns")
            if vulns is not None and not isinstance(vulns, list):
                raise GateError(f"{where} ({name}): 'vulns' is not a list")
            packages.append(
                PackageCoverage(
                    name=name,
                    version=version,
                    state="skipped",
                    skip_reason=str(dep.get("skip_reason") or ""),
                    vuln_count=len(vulns) if isinstance(vulns, list) else 0,
                )
            )
        elif "vulns" in dep:
            vulns = dep.get("vulns")
            if not isinstance(vulns, list):
                raise GateError(f"{where} ({name}): 'vulns' is not a list")
            if not version:
                raise GateError(f"{where} ({name}): audited dependency has no version")
            for vuln in vulns:
                if not isinstance(vuln, dict) or "id" not in vuln:
                    raise GateError(f"{where} ({name}): malformed vulnerability entry")
            packages.append(
                PackageCoverage(
                    name=name,
                    version=version,
                    state="audited",
                    vuln_count=len(vulns),
                )
            )
        else:
            packages.append(
                PackageCoverage(name=name, version=version, state="unresolved")
            )
    summary = CoverageSummary(packages=packages)
    summary.assert_reconciles()
    return summary


def check_coverage(
    packages: list[PackageCoverage], skip_entries: list[SkipEntry], today: date
) -> CoverageGate:
    """Check skipped/unresolved packages against recorded skips.

    A skipped package passes only when a ``[[skip]]`` entry records
    it. A recorded entry whose package is not skipped in this run is
    dormant (reported, not failed — the package became auditable). A
    recorded skip still present past its ``review_by`` is expired.
    """
    by_package = {e.package.lower(): e for e in skip_entries}
    expected: list[PackageCoverage] = []
    unexpected: list[PackageCoverage] = []
    unresolved: list[PackageCoverage] = []
    matched: set[str] = set()
    for package in packages:
        if package.state == "unresolved":
            unresolved.append(package)
        elif package.state == "skipped":
            entry = by_package.get(package.name.lower())
            if entry is None:
                unexpected.append(package)
            else:
                matched.add(package.name.lower())
                expected.append(package)
    dormant = [e for e in skip_entries if e.package.lower() not in matched]
    expired = [
        (p, by_package[p.name.lower()])
        for p in expected
        if by_package[p.name.lower()].review_by is not None
        and by_package[p.name.lower()].review_by < today
    ]
    return CoverageGate(
        expected=expected,
        unexpected=unexpected,
        unresolved=unresolved,
        dormant=dormant,
        expired=expired,
    )


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
    coverage = parse_pip_audit_coverage(data)
    return AuditResult(source=source, findings=findings, raw_findings=raw, coverage=coverage)


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


def build_report(
    audits: list[AuditResult],
    classification: Classification,
    coverage_gate: CoverageGate,
    today: date,
) -> dict:
    """Machine-readable summary for CI artifacts (schema v2: adds
    per-source coverage — every package's audit state — and the
    recorded/unexpected skip lists)."""
    return {
        "schema": "textforensics.pip-audit-gate/v2",
        "run_date": today.isoformat(),
        "sources": [
            {
                "source": a.source,
                "findings_raw": a.raw_findings,
                "findings_unique": len(a.findings),
                "packages_total": a.coverage.total if a.coverage else 0,
                "packages_audited": a.coverage.audited if a.coverage else 0,
                "packages_skipped": a.coverage.skipped if a.coverage else 0,
                "packages_unresolved": a.coverage.unresolved if a.coverage else 0,
                "packages": [
                    {
                        "package": p.name,
                        "version": p.version,
                        "state": p.state,
                        "skip_reason": p.skip_reason,
                        "vuln_count": p.vuln_count,
                    }
                    for p in (a.coverage.packages if a.coverage else [])
                ],
            }
            for a in audits
        ],
        "findings_raw_total": sum(a.raw_findings for a in audits),
        "findings_unique_total": sum(len(a.findings) for a in audits),
        "baselined": len(classification.baselined),
        "new": len(classification.new),
        "dormant_baseline_entries": len(classification.dormant),
        "expired_baseline_entries": len(classification.expired),
        "expected_skips": sorted({p.name for p in coverage_gate.expected}),
        "unexpected_skips": sorted({p.name for p in coverage_gate.unexpected}),
        "unresolved_packages": sorted({p.name for p in coverage_gate.unresolved}),
        "dormant_skips": sorted({e.package for e in coverage_gate.dormant}),
        "expired_skips": sorted({p.name for p, _ in coverage_gate.expired}),
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


def evaluate(
    audits: list[AuditResult],
    baseline: list[BaselineEntry],
    skip_entries: list[SkipEntry],
    today: date,
    report_path: Path | None,
) -> int:
    """Classify findings + coverage for completed audits and report.

    Shared by the live-run and ``--from-json`` paths. Exit 1 on any
    coverage failure (unexpected skip, unresolved package, expired
    skip, missing coverage data) or expired baseline entry; exit 2
    on new findings; exit 0 only when every finding is baselined AND
    every package's coverage state is accounted for.
    """
    for audit in audits:
        if audit.coverage is None:
            print(
                f"pip-audit gate ERROR: {audit.source} produced no coverage data — "
                "coverage must be measured, not assumed.",
                file=sys.stderr,
            )
            return EXIT_ERROR
        audit.coverage.assert_reconciles()

    findings = [f for audit in audits for f in audit.findings]
    classification = classify(findings, baseline, today)
    packages = [p for audit in audits for p in audit.coverage.packages]
    coverage_gate = check_coverage(packages, skip_entries, today)

    for audit in audits:
        coverage = audit.coverage
        assert coverage is not None
        print(
            f"{audit.source}: {audit.raw_findings} raw findings, "
            f"{len(audit.findings)} unique; coverage: {coverage.total} packages "
            f"({coverage.audited} audited, {coverage.skipped} skipped, "
            f"{coverage.unresolved} unresolved)"
        )
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
    if coverage_gate.expected:
        print("skipped packages (expected, recorded in baseline):")
        for package in coverage_gate.expected:
            print(f"  - {package.name} {package.version}: {package.skip_reason}")
    if coverage_gate.dormant:
        print("dormant skip entries (package is audited now, entry awaits removal):")
        for entry in coverage_gate.dormant:
            print(f"  - {entry.package}")
    if coverage_gate.unexpected:
        print("UNEXPECTED skipped packages (no recorded [[skip]] entry):")
        for package in coverage_gate.unexpected:
            print(f"  - {package.name} {package.version}: {package.skip_reason}")
    if coverage_gate.unresolved:
        print("UNRESOLVED packages (named but neither audited nor skipped):")
        for package in coverage_gate.unresolved:
            print(f"  - {package.name}")
    if coverage_gate.expired:
        print("EXPIRED skip entries (skip still present past review_by):")
        for package, entry in coverage_gate.expired:
            print(
                f"  - {package.name} {package.version} (review_by {entry.review_by})"
            )
    if classification.new:
        print(f"NEW findings ({len(classification.new)}):")
        for finding in classification.new:
            print(_finding_line(finding))

    if report_path is not None:
        report_path.write_text(
            json.dumps(
                build_report(audits, classification, coverage_gate, today), indent=2
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"report written to {report_path}")

    if classification.expired:
        print(
            "pip-audit gate FAILED: expired baseline entries — "
            "re-check them and update review_by or fix the dependency.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if coverage_gate.unexpected or coverage_gate.unresolved or coverage_gate.expired:
        print(
            "pip-audit gate FAILED: incomplete audit coverage — every "
            "skipped/unresolved package must be an explicit, recorded "
            "state; add a [[skip]] entry with reason and review date, "
            "or fix the dependency.",
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
    print("pip-audit gate PASSED: no new findings; audit coverage complete.")
    return EXIT_PASS


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
        "--from-json",
        type=Path,
        default=None,
        help="validate an existing pip-audit --format json file instead "
        "of running pip-audit (used by jobs that run pip-audit directly)",
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
        skip_entries = load_skip_entries(args.baseline)
        if args.from_json is not None:
            if not args.from_json.is_file():
                raise GateError(f"pip-audit JSON file not found: {args.from_json}")
            try:
                data = json.loads(args.from_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise GateError(
                    f"could not read pip-audit JSON {args.from_json}: {exc}"
                ) from exc
            if not isinstance(data, dict):
                raise GateError(f"pip-audit JSON {args.from_json} is not an object")
            findings, raw = parse_pip_audit_json(data)
            coverage = parse_pip_audit_coverage(data)
            audits = [
                AuditResult(
                    source=f"pip-audit JSON ({args.from_json})",
                    findings=findings,
                    raw_findings=raw,
                    coverage=coverage,
                )
            ]
        else:
            audits = [run_pip_audit(None, "installed environment")]
            if not args.no_requirements:
                if not args.requirements.is_file():
                    raise GateError(f"requirements file not found: {args.requirements}")
                audits.append(
                    run_pip_audit(
                        args.requirements, f"pinned requirements ({args.requirements})"
                    )
                )
    except GateError as exc:
        print(f"pip-audit gate ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return evaluate(audits, baseline, skip_entries, today, args.report)


if __name__ == "__main__":
    sys.exit(main())
