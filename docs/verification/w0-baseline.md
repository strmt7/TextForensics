# W0 baseline record

Wave W0 starting point, recorded 2026-11-10 20:17 CET (19:17:39 UTC).
Machine-readable form: `docs/evidence/runs/EV-20261110-w0-baseline.json`
(schema `textforensics.w0-baseline/v1`). That JSON is authoritative; this
page is the human-readable summary.

## Commits

| Role | SHA | Subject |
| --- | --- | --- |
| Audit baseline | `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` | docs: record proven mechanism behind the 82% core-coverage artifact (2026-11-10 10:51 CET) |
| Audit commit / wave head | `3ff365031faf48bc0d14212d81d147ac11c7b232` | docs: audit repository and plan stable release hardening (2026-11-10 19:34 CET) |

Relationship, verified with git (not assumed):

- `5ea804c` is an ancestor of `3ff3650`.
- The audit commit is docs-only: 14 files changed, +18,208 lines, 0
  deletions. The diff `5ea804c..3ff3650` touches only `AGENTS.md`,
  `CHANGELOG.md`, `docs/HANDOVER.md`, `docs/RELEASE_READINESS_PLAN.md` and
  `docs/audits/2026-11-10/*`. The diff is **empty** for `src/`,
  `scripts/`, `.github/`, `tests/`, `pyproject.toml` and `setup.py`.
  Code is therefore identical to the audited baseline.
- `5ea804c` is preserved as history. Nothing in W0 re-writes it.

Dirty status at wave start: **clean** — `git status --porcelain=v1`
returned no entries on branch `audit-w0-a`.

## Environment

- OS: Linux, kernel 7.0.0-44-generic, x86_64, glibc 2.39
  (`Linux-7.0.0-44-generic-x86_64-with-glibc2.39`).
- Interpreter: Python 3.12.3 (`/usr/bin/python3.12`).
- Canonical venv: the canonical TextForensics-rewrite venv
  interpreter, Python 3.12.3, pip 24.0. Its absolute path is omitted
  here because the same string occurs among the classified privacy
  occurrences (see `docs/audits/2026-11-10/privacy-disposition-w0.md`).
- Exact dependency closure: `requirements-pinned.txt`, SHA-256
  `3d34ffc35e1b0e9942f18d2e3d1e755221ae8222900655d5a326b69a156793c0`,
  git blob `6c444f6691b25d9fa6405fe6edaf3df2e5ff072a`
  (120 packages, Python 3.12 / Ubuntu — see the supported-profiles doc).
- Checked-in SBOM: `sbom/textforensics.cdx.json`, SHA-256
  `a00906a70e46d75ceec9705891bf425d87f30fadace8d95c5617deb831b0d8a5`,
  git blob `08602a4c50933e959485da978cf563346a6e156b` (120 components).
- All digests are computed over persisted file bytes (UTF-8, LF).

A full `pip freeze` is not embedded in the record: the lockfile above is
the exact identity of the resolved closure.

## Gate commands

The complete gate inventory (workflows, jobs, exact commands, triggers,
and the audit-stated defects in several of them) is enumerated in the JSON
record's `gates` array. Headline facts:

- CI (`ci.yml`) runs: pre-commit, compileall, ruff, core pytest on
  Python 3.11–3.15, golden-file verification, `pip check`, CLI smoke,
  75% coverage gate, claims gate, pinned-install, SBOM `--check`,
  OS smoke (Ubuntu/Windows/macOS x Python 3.11/3.15), wheel build +
  install, API surface, MCP surface.
- Supply chain (`supply-chain.yml`, `semver.yml`): baseline-aware
  pip-audit gate, gitleaks secret scan, SBOM generation, semver check.
- Deep verification (`enterprise-deep-verification.yml`, weekly):
  extras pytest, coverage, docs build, strict pip-audit + bandit,
  schema validation, CLI/API smoke, performance harness,
  cross-platform version prints.
- Mutation (`mutation.yml`): diff mode on push/PR, full +
  safety-critical on schedule/dispatch.
- Fuzz (`fuzz.yml`), observatory (`observatory.yml`), benchmark
  (`benchmark.yml`), reproducibility (`reproducibility.yml`),
  container (`container.yml`), release (`release.yml`),
  CodeQL / Scorecard / dependency-review / workflow-lint,
  download-prefix-probe.

Known-broken gates, as stated by the audit (not re-measured by W0) —
recorded here so no one reads a green overview as proof:

- Reproducibility wheel comparison is explicitly non-gating (ENG-03);
  the downloaded exact-SHA wheels differ.
- Integrity "verify signatures / attestations" steps are echo-only
  placeholders (ENG-07).
- Deep-verification pytest requests `--forked` without declaring
  pytest-forked (ENG-07); unquoted `pip-audit>=2,<3` /
  `bandit>=1.7,<2` / `httpx>=0.27,<1` ranges are shell redirections
  (ENG-07); Sphinx failures are ignored with `|| true` (ENG-07);
  fuzz steps end in `|| true` and a nonzero fuzz child can report
  `error=null` (ENG-07).
- Benchmark comparison uses an invalid download-artifact pin and is
  off by default on push/schedule (ENG-13).
- OS smoke is two shallow CLI operations, not workflow qualification
  (ENG-09); the real Windows extras suite is red at the audit
  baseline (21 failed, 4 errors, exit 1).
- Release and container publication have no dependency on the
  acceptance gates (ENG-04/14); the publish helper is not fail-closed
  (ENG-05/06).

## What this record is not

- It does **not** re-run any gate and does **not** claim any gate
  passes. Gate verdicts belong to the evidence manifest
  (`textforensics.evidence-manifest/v1`) once
  `scripts/verify_release.py` exists (Worker B).
- The repository currently has **no** canonical local verification
  command mirroring the complete CI surface. This record enumerates
  the gates that command must mirror; it does not invent one.

## Open owner decisions touching this record

- Signing/TSA trust identity (needed before any signed release
  material can be verified, W10).
- Public-snapshot/container policy (the container path currently
  publishes on main push without gates; see ENG-14).
- Final release authorization (owner only; no release/tag is created
  by this wave).
