# Canonical local verification

`python scripts/verify_release.py [--json PATH] [--gate NAME ...] [--candidate-sha SHA]`

This is the single local command that mirrors the complete CI surface.
It exists because the repository previously had no trustworthy single
command proving all the release criteria (see the W0 section of
`docs/RELEASE_READINESS_PLAN.md` and ENG-07/ENG-13/ENG-16 in the
2026-11-10 external audit). It verifies a candidate tree: the exact HEAD
commit, with a clean working tree. It never requires network access, the
GitHub API, or any remote service, and it never dispatches a release,
creates a tag, contacts an upload endpoint, or pushes an image.

Run it with the repository's canonical virtual environment and
`PYTHONPATH` pointing at this checkout's `src` first, e.g. from the
repository root:

```console
PYTHONPATH=$PWD/src PYTHONDONTWRITEBYTECODE=1 \
  /path/to/venv/bin/python scripts/verify_release.py --json /tmp/verify.json
```

## Exit codes and verdict

| Exit | Verdict | Meaning |
| --- | --- | --- |
| 0 | `pass` | Every required gate passed. |
| 1 | `fail` | A required gate failed (and no exit-2 condition applies). |
| 2 | `incomplete` | A required gate is `skipped`, `unavailable`, `zero_work`, or `not_applicable`; the candidate SHA is stale; the working tree is dirty; or a required tool, artifact, or baseline is missing. |

Rules that are easy to get wrong:

- A child process exit 2 is a FAILURE of its gate (status `fail`, detail
  records "child exit 2"), never a pass and never silently swallowed.
- Required gates accept ONLY `pass`. That is why a required gate that is
  `not_applicable` also yields exit 2: the contract enumerates
  `skipped` / `unavailable` / `zero_work` for exit 2, and the
  "required gates accept ONLY pass" sentence forces the same treatment
  for a required `not_applicable` gate. Optional gates in any status do
  not change the verdict or exit code; an optional gate that fails is
  still shown as `fail`, never hidden.
- A dirty working tree is not a verifiable candidate: gates are not
  executed at all, every gate is reported `not_applicable` with detail
  "working tree dirty; candidate not verifiable", and the exit code is 2.
  There is no `--allow-dirty` bypass in v1.
- A stale `--candidate-sha` (HEAD != the given SHA) is treated the same
  way: gates are not executed, every gate is `not_applicable` with detail
  "stale candidate SHA; gates not executed", top-level `stale_sha: true`,
  exit 2. This is the documented choice: a stale candidate is not
  verified, not failed gate by gate.
- `--gate NAME` runs only the named gates. Every other gate is reported
  `skipped`, so a filtered run is always exit 2 (`incomplete`): a partial
  run cannot yield `pass`.

## Status vocabulary

Exactly six strings, no others: `pass`, `fail`, `skipped`,
`unavailable`, `not_applicable`, `zero_work`. A gate that runs but
executes zero work (pytest collects 0 tests, a checker finds 0 files, a
comparison compares 0 benchmarks) reports `zero_work`, never `pass`.
Zero-work detection is implemented per gate by parsing the child output
and asserting `executed_work > 0` (see "What executed_work counts").
A gate whose required tool binary or module is absent reports
`unavailable` with a detail naming the missing tool; overall exit 2.

## Output

- Human-readable summary to stdout, always: one line per gate (name,
  status, `executed_work`, duration) plus a final verdict line, and the
  retained work-directory path.
- `--json PATH` writes the full machine-readable report: `{command,
  version, candidate_sha, head_sha, dirty, stale_sha, interpreter, os,
  repo_root, work_dir, started, finished, duration_s, gates, verdict,
  exit_code}`. Each gate record is `{name, ci_workflow, ci_job, required,
  status, executed_work, command, duration_s, detail, artifacts}`,
  where `artifacts` lists `{path, sha256}` for files the gate produced
  (pip-audit report, built distributions, determinism evidence, …).
  Gate records use the same six status strings as the evidence-manifest
  gate references, and artifacts are referenced by path + SHA-256 where
  produced.
- Per-gate working files (coverage data, pip-audit report, generated
  report card, build snapshots, determinism evidence, throwaway install
  venv) live in a retained temporary work directory
  (`/tmp/verify-release-…`), whose path is recorded in the report. The
  command writes nothing inside the repository (except the `--json`
  file itself, if the caller points it inside the repo — prefer
  `/tmp`). `__pycache__` creation is suppressed with
  `PYTHONDONTWRITEBYTECODE=1`; the `compile` gate is the one exception
  (compiling is its purpose; its `__pycache__` output is git-ignored).

## Required vs optional

`required=true` exactly when the mirrored CI job runs on push (or PR)
to `main` — i.e. it gates what lands on `main`. Schedule/dispatch-only
jobs, PR-only checks, and advisory jobs are `required=false`. The full
classification is in the inventory below; the coordinator may promote
a gate when a local equivalent lands (for example `bandit`, which is
currently schedule-only in CI via enterprise-deep-verification).

## What executed_work counts

`executed_work` is the count of positive work the gate executed, never
a number it did not measure. Definitions per gate:

- pytest gates (`pytest-core`, `observatory-tests`, `fuzz-regression`,
  `pytest-performance`, `pytest-benchmarks`): tests in the pytest
  summary line (passed + failed + skipped + deselected + errors).
- `claims`: claims evaluated (`passed + failed` from the
  "Results: N passed, M failed" line).
- `schemas` / `ent-deep-schema`: schemas validated (lines starting
  `OK: `; 12).
- `sbom-check`: components in the checked-in
  `sbom/textforensics.cdx.json` (120).
- `golden`: golden files verified (1).
- `ruff`, `bandit`, `compile`: `.py` files under the scanned
  directories (`src` + `tests`, or `src`).
- `pip-check`, `pip-audit`: installed distributions in the environment.
- `coverage`: statements measured (the `TOTAL` row of the coverage
  report).
- `api-unittest`: tests run (`Ran N tests`).
- `package-build`: distributions built (wheel + sdist = 2).
- `package-twine`: distributions twine checked (`PASSED` lines).
- `package-wheel-contents`: content assertions (4).
- `wheel-install-smoke`: smoke checks (2: `--version`, schema load).
- `cli-scan-smoke`, `cli-smoke`, `semver`, `api-create-app`,
  `mcp-smoke`, `drift-status-smoke`, `report-card-fresh`: one check each.
- `mutation-diff`: mutants in the validated summary (`total`).
- `wheel-reproducibility`, `case-file-determinism`: builds / exports (2).
- `cli-determinism`, `detector-determinism`: runs compared (5).
- `benchmark-script`: benchmarks in the results JSON.

Where a child output cannot be parsed reliably, the count used is the
one that can be established (files present, distributions installed),
and the limitation is stated here, not hidden.

## Deviations from the CI commands (deliberate, recorded)

The command invokes the same underlying entry points as CI wherever
possible. Where it cannot, the difference is a documented deviation,
not a silent adaptation:

- `claims` runs `scripts/check_claims.py --no-report-card`. CI runs it
  without the flag and then diffs the rewritten card. The local command
  must not mutate the repo, so the rewrite is reproduced by the
  separate `report-card-fresh` gate, which regenerates the card into
  the work directory and byte-compares it with the committed card.
- `check_pip_audit.py --report` writes to the work directory, not to
  `pip-audit-gate.json` in the repo root (that file is not git-ignored
  and would dirty the tree).
- `coverage run` writes its data file to the work directory via
  `COVERAGE_FILE`; the `coverage` gate reads it with `--data-file`.
  The CI `coverage xml` step is not run (its output file is not
  git-ignored and would dirty the tree); the gate is the
  `--fail-under=75` report.
- `package-build` builds from a `git archive HEAD` snapshot in the
  work directory, with `--no-isolation` (local verification has no
  network; CI uses an isolated build). The snapshot is byte-identical
  to the verified candidate because the tree is clean.
- `wheel-reproducibility` builds twice from independent snapshots with
  fixed `SOURCE_DATE_EPOCH`/`PYTHONHASHSEED` and compares bytes
  fatally (ENG-03). It does NOT use the workflow's
  `setuptools==79.0.1`: that version is rejected by the repo's own
  security evidence (ENG-10). The local gate uses the ambient build
  backend instead; the workflow pin is a gate defect for the
  coordinator (see below).
- `cli-determinism`, `case-file-determinism`, `detector-determinism`
  run their inputs from the work directory instead of `testdata/` /
  `evidence/` in the repo.
- CLI gates invoke `python -m textforensics.cli …` (the same entry
  point as the `textforensics` console script, resolved via
  `PYTHONPATH` to this checkout) instead of the console script, so the
  verified code is always this worktree's.
- The install smoke test installs the built wheel `--no-deps` into a
  throwaway venv with system site packages, so no network is needed,
  and runs its checks with `PYTHONPATH` removed so the wheel — not the
  worktree — is imported.
- Children inherit a `PATH` with the canonical venv's bin directory
  prepended (the directory of the interpreter running this command).
  Pre-commit's local hooks invoke bare `python` and the test suite
  invokes the bare `textforensics` console script; without this, both
  fail with `FileNotFoundError` whenever the caller's `PATH` lacks the
  venv bin dir. This was the single root cause of the pre-commit gate
  failure and of the 5 `test_schema.py` CLI failures in the first
  end-to-end run (see the part-report).

## Known gate defects (recorded, not silently adapted)

These are findings about CI entry points / local executability that the
coordinator must reconcile with the owners of the other W0 items.
None of them was worked around by weakening a gate:

1. The enterprise-deep-verification test-suite and coverage jobs are
   schedule/dispatch-only and no longer use `pytest --forked` (the flag
   was removed in W0, ENG-07, because the `pytest-forked` plugin is not
   installed and not a declared dev dependency). `ent-deep-suite` and
   `ent-deep-coverage` are `unavailable`; the same suite without
   `--forked` is covered by `pytest-core`, and core coverage by
   `coverage`.
2. `actionlint` is not installed: `workflow-lint` is `unavailable`
   (required).
3. `gitleaks` is not installed: `secrets-scan` is `unavailable`
   (required).
4. `cosign` is not installed and there are no signed release artifacts
   for any HEAD: `sigstore-verification` is `unavailable` (required).
   The CI job itself now performs real cosign/attestation verification
   (the echo placeholder was replaced in W0, ENG-07); the gate is
   unavailable for lack of artifacts to verify, not for lack of a check.
5. No Syft binary: the three Syft-based SBOM jobs
   (`supply-chain-sbom`, `repo-provenance-sbom`,
   `ent-deep-provenance`) are `unavailable`; the checked-in SBOM
   freshness is covered by `sbom-check`.
6. The reproducibility workflow pins `setuptools==79.0.1`, a version
   the repo's own security evidence rejected (ENG-10); the local
   reproducibility gates use the ambient build backend (see above).
7. The `mutation-diff` summary (`mutation-results/summary.json`)
   carries no source-SHA binding, so the gate cannot establish that a
   present artifact is for the exact HEAD; it records that limitation
   in its detail. Note also that the test suite itself writes this
   file: `tests/test_mutation.py` writes the `no-relevant-changes`
   marker summary into the repo-root `mutation-results/` directory
   while the `pytest-core` gate runs, so a full verification run
   always finds a zero-mutant summary and the gate reports
   `zero_work` for it (per the frozen contract). That file is
   git-ignored, so the tree stays clean, but it is test debris, not
   independent evidence of a mutation campaign; a future wave may
   want SHA-bound artifacts or a suite that stops writing
   repo-relative mutation artifacts.
8. The enterprise-deep documentation job requires `sphinx` and the
   `markdown` package, neither installed: `ent-deep-docs` is
   `unavailable`. (Its `|| true` failure swallowing was removed in W0,
   ENG-07.)
9. The fuzz direct-atheris steps no longer swallow exit codes (the
   `|| true` on the `run_fuzz.py` invocations was removed in W0,
   ENG-07), but `atheris` is not installed: `fuzz-direct-atheris` is
   `unavailable`. The pytest-mode regression is covered by
   `fuzz-regression`.
10. `benchmark-compare` has no resolved baseline artifact for any
    HEAD, so it is `not_applicable` (ENG-13): a success label must not
    claim a matched baseline was evaluated.
11. Worker A's evidence-manifest schema was not attached to the W0
    brief for this command, so no field-by-field conformance check
    against it could be performed at build time. The coordinator
    reconciled the boundary at integration: the manifest's `gates` map
    is derived from this command's gate list by gate `name`, with
    `status` copied verbatim (see
    `docs/verification/evidence-manifest-spec.md`), and the
    required-gates binding is enforced by the exact-SHA promotion gate
    and the W10 manifest verifier, not by this command. The report uses
    the frozen contract's status vocabulary and path + SHA-256 artifact
    references.
12. `sbom-check` (`generate_sbom.py --check`) regenerates the SBOM
    from the *installed* environment. The canonical venv's closure
    differs from the checked-in lockfile closure (for example
    `anybadge` 1.16.0 installed vs 1.18.0 locked; `atheris` and
    `wheel` not installed), so the gate fails in this environment
    even though the checked-in SBOM is consistent with its lockfile.
    That is an environment mismatch, not a repo defect; a future wave
    may run this gate in a fresh venv built from
    `requirements-pinned.txt`.
13. The `wheel` package is not installed in the canonical venv, so
    `python -m build --no-isolation` fails with "Unmet dependencies:
    wheel>=0.45, found: not installed". `package-build` and
    `wheel-reproducibility` therefore report `unavailable` naming the
    missing `wheel` module (missing-tool handling), instead of
    failing the build. A future wave may provide a build venv with
    the locked build backend.
14. The benchmark workflow's legacy step is broken as written:
    `pytest tests/test_benchmarks.py --benchmark-only
    --benchmark-json=…` deselects all 9 tests ("Skipping
    non-benchmark (--benchmark-only active)"), so pytest-benchmark
    runs zero benchmarks and warns "Not saving anything, no
    benchmarks have been run!", which the repo's
    `filterwarnings = ["error", …]` turns into an error (exit 1).
    The `pytest-benchmarks` gate mirrors the CI command exactly and
    reports `fail`; fixing the workflow step belongs to a later wave.
15. The first end-to-end run's `pre-commit` gate and 5
    `test_schema.py` CLI failures shared one root cause: bare
    `python` / `textforensics` were not resolvable for child
    processes because the caller's `PATH` lacked the venv bin dir.
    The command now prepends the interpreter's bin dir to the child
    `PATH` (see "Deviations"); the failures were environmental, not
    repo defects.

## Gate inventory

CI job → local gate → required → how it runs locally.

| CI workflow / job | Local gate | Req | Local behaviour |
| --- | --- | --- | --- |
| ci.yml / core | `pre-commit` | yes | `pre-commit run --all-files` |
| ci.yml / core | `ruff` | yes | `ruff check src tests` |
| ci.yml / core | `compile` | yes | `python -m compileall -q src tests` |
| ci.yml / core | `pytest-core` | yes | `coverage run --source=textforensics -m pytest tests -q --tb=short` (data to work dir) |
| ci.yml / core | `coverage` | yes | `coverage report --data-file=… --fail-under=75` on pytest-core data |
| ci.yml / core | `golden` | yes | `python scripts/verify_golden.py` |
| ci.yml / core | `pip-check` | yes | `python -m pip check` |
| ci.yml / core | `cli-smoke` | yes | `python -m textforensics.cli --version` |
| ci.yml / os-smoke | `cli-scan-smoke` | yes | `textforensics.cli scan --json`, sample stdin, JSON parsed |
| ci.yml / claims-gate | `claims` | yes | `python scripts/check_claims.py --no-report-card` |
| ci.yml / claims-gate | `report-card-fresh` | yes | regenerate card to work dir, byte-compare with committed card |
| ci.yml / sbom | `sbom-check` | yes | `python scripts/generate_sbom.py --check` |
| semver.yml / semver-check | `semver` | yes | `python scripts/check_semver.py` |
| supply-chain.yml / pip-audit-gate | `pip-audit` | yes | `python scripts/check_pip_audit.py --report <workdir>/…` |
| supply-chain.yml / secrets | `secrets-scan` | yes | `unavailable`: gitleaks not installed |
| supply-chain.yml / sbom | `supply-chain-sbom` | no | `unavailable`: requires Syft action |
| ci.yml core (pre-commit hook) + ent-deep schema-validation | `schemas` | yes | `python scripts/validate_schemas.py` |
| enterprise-deep-verification.yml / vulnerability-audit | `bandit` | no | `bandit -r src -ll -ii` |
| ci.yml / api | `api-unittest` | yes | `python -m unittest tests.test_api -v` |
| ci.yml / api | `api-create-app` | yes | `create_app()` is not None |
| ci.yml / mcp | `mcp-smoke` | yes | `mcp_server._server()` is not None |
| ci.yml / package | `package-build` | yes | `python -m build --no-isolation` in HEAD snapshot |
| ci.yml / package | `package-twine` | yes | `twine check` on built distributions |
| ci.yml / package | `package-wheel-contents` | yes | 3 schemas + LICENSE in wheel |
| ci.yml / package | `wheel-install-smoke` | yes | install wheel in throwaway venv, `--version` + schema load |
| observatory.yml / machinery-smoke | `observatory-tests` | yes | pytest on the 6 U3/validation files |
| observatory.yml / machinery-smoke | `drift-status-smoke` | yes | `drift status` with an empty runs dir |
| observatory.yml / scheduled-probe-run | `observatory-probe-run` | no | `unavailable`: corpus host only; no user-cache access |
| fuzz.yml / fuzz-regression | `fuzz-regression` | yes | `pytest tests/fuzz/test_fuzz_pytest.py -v` |
| fuzz.yml / fuzz-regression | `fuzz-direct-atheris` | no | `unavailable`: atheris absent; pytest-mode covered by `fuzz-regression` |
| fuzz.yml / fuzz-weekly | `fuzz-weekly` | no | `not_applicable`: schedule-only extended campaign |
| fuzz.yml / fuzz-summary | `fuzz-summary` | no | `not_applicable`: aggregation only |
| mutation.yml / mutation-diff | `mutation-diff` | yes | `--check-results` on existing summary only; never launches a campaign |
| mutation.yml / mutation-full | `mutation-full` | no | `unavailable`: scheduled campaign; no artifact for HEAD |
| mutation.yml / mutation-report | `mutation-report` | no | `not_applicable`: aggregation only |
| workflow-lint.yml / actionlint | `workflow-lint` | yes | `unavailable`: actionlint not installed |
| codeql.yml / analyze | `codeql` | yes | `unavailable`: requires GitHub CodeQL action |
| container.yml / build-and-push | `container` | yes | `unavailable`: must not push images |
| repository-integrity.yml / sigstore | `sigstore-verification` | yes | `unavailable`: real verification in CI now; no signed artifacts |
| repository-integrity.yml / provenance | `repo-provenance-sbom` | yes | `unavailable`: requires Syft action |
| reproducibility.yml / build-reproducibility | `wheel-reproducibility` | yes | two snapshot builds, fatal byte compare |
| reproducibility.yml / cli-determinism | `cli-determinism` | yes | scan ×5, jq-filtered, hash-compared |
| reproducibility.yml / case-file-determinism | `case-file-determinism` | yes | export ×2 `--deterministic`, `case_sha256` compared |
| reproducibility.yml / detector-determinism | `detector-determinism` | yes | report ×5, jq-filtered, hash-compared |
| benchmark.yml / benchmark | `benchmark-script` | no | `scripts/benchmark.py --iterations 5` |
| benchmark.yml / benchmark | `pytest-performance` | no | pytest-benchmark on `test_performance.py` |
| benchmark.yml / benchmark | `pytest-benchmarks` | no | pytest-benchmark on `test_benchmarks.py` |
| benchmark.yml / benchmark | `benchmark-compare` | no | `not_applicable`: no baseline artifact (ENG-13) |
| enterprise-deep-verification.yml / test-suite-all-features | `ent-deep-suite` | no | `unavailable`: schedule/dispatch-only; `--forked` removed in W0 |
| enterprise-deep-verification.yml / coverage-verification | `ent-deep-coverage` | no | `unavailable`: schedule/dispatch-only; `--forked` removed in W0 |
| enterprise-deep-verification.yml / documentation-verification | `ent-deep-docs` | no | `unavailable`: sphinx/markdown absent (`|| true` removed in W0) |
| enterprise-deep-verification.yml / vulnerability-audit | `ent-deep-vuln-audit` | no | `unavailable`: needs isolated audit venv + network |
| enterprise-deep-verification.yml / schema-validation | `ent-deep-schema` | no | jsonschema check + `load_schema` asserts |
| enterprise-deep-verification.yml / release-provenance | `ent-deep-provenance` | no | `unavailable`: requires Syft action |
| scorecard.yml / scorecard | `scorecard` | no | `unavailable`: advisory; requires GitHub Action |
| dependency-review.yml / dependency-review | `dependency-review` | no | `not_applicable`: PR-only |
| download-prefix-probe.yml / prefix-probe | `download-prefix-probe` | no | `unavailable`: requires network |
| download-prefix-probe.yml / full-download | `download-full` | no | `not_applicable`: dispatch-only dataset download |
| release.yml / release | `release-dispatch` | no | `not_applicable`: manual publication; never dispatched |

## Expected runtime

The full run is long, and that is expected: the core pytest suite
alone takes on the order of ten minutes in the canonical venv, plus
pre-commit, the claims gate (~30 s), pip-audit (~2 min), the benchmark
gates, the determinism gates, and two wheel builds. Do NOT truncate
the suite to make it fast. A filtered run (`--gate …`) is faster but
always exits 2 (`incomplete`).

## Tests

`tests/test_verify_release.py` covers the contract with synthetic
gates (passing / failing / skipped / zero-work / child exit 2 / stale
SHA / dirty tree / missing tool / JSON shape / real subprocess with
positive work), plus gate-definition well-formedness and the
mutation-diff no-artifact case. It runs in a few seconds and never
runs the full suite.

## Human-only decisions

The following are flagged, not decided, by this command: signing/TSA
trust identity; public-snapshot/container policy; branch-protection
governance; history-rewrite privacy cleanup; final release
authorization. The command records `unavailable` where a gate would
need one of those decisions (for example signature verification), and
never invents consent or credentials.
