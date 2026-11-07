# Verification record — Phase 1 (2026-11-06)

Every number in this file was measured on 2026-11-06 by running the
stated command in the stated environment. Nothing here is copied from
an earlier run. `docs/CLAIMS.yaml` cites this file where a claim's
evidence is a measured run rather than a single test.

## Environment

- Machine: Linux VM, Python **3.12.3** (`python3` only; no bare `python` binary).
- Bare verification venv: `python3 -m venv` + `pip install -e ".[dev]"`,
  then `pip install -e ".[security]"` for the audit tools. `/tmp` is a
  512 MB tmpfs, so installs used `TMPDIR=<repo>/.tmp PIP_NO_CACHE_DIR=1`.
- Repo HEAD at measurement time: `efc198c` (rewritten history, canonical
  identity `Stratos <28989754+strmt7@users.noreply.github.com>`).
- The `textforensics` console script is only resolvable when the venv's
  `bin/` is on `PATH`; invoking pytest via the venv python without that
  `PATH` makes the 5 `SchemaCLITests` fail with `FileNotFoundError:
  'textforensics'` — a harness artifact, not a repo defect.

## Full test suite

Command (venv `bin/` on `PATH`):

```bash
python -m pytest tests/ -q -p no:cacheprovider \
  --cov=src/textforensics --cov-report=term -o addopts=''
```

Result: **2325 passed, 0 failed, 0 skipped in 128.78 s.**
Coverage: **86%** (11,551 statements, 1,304 missed, 3,894 branches,
557 partial).

This is the extras-installed venv (`.venv`, `pip install -e
".[dev]"` + extras), so nothing skips: 2325 tests were collected in
total. (The earlier 2210 passed / 147 skipped / 78% figure was the
bare venv without the optional extras installed.)

Lowest-coverage core modules at this commit (from the same run):
`ollama.py` 62%, `casefile.py` 70%, `_build_info.py` 71%,
`workspace_integrity.py` 73%, `cli.py` 76%, `model_card.py` 79%,
`web_ui/main.py` 82%, `bundle.py` 84%.

## Lint / format

```bash
ruff check src/ tests/ scripts/   # All checks passed (0 errors)
ruff format --check src/ tests/ scripts/  # 168 files already formatted
```

## Static security scan

```bash
python -m bandit -r src/        # 16 Low, 0 Medium, 0 High
python -m bandit -r src/ -lll   # exit 0 (no medium/high findings)
```

## Dependency audit

```bash
python -m pip_audit --format json --desc=on   # exit 1: findings present
```

**25 findings in 3 packages** (all have a fixed version available):

| Package | Installed | Findings | Fixed in |
|---------|-----------|---------:|----------|
| cryptography | 42.0.8 | 11 | 43.0.1 – 49.0.0 depending on advisory |
| pip | 24.0 | 12 | 25.3 – 26.2 |
| pytest | 8.4.2 | 2 | 9.0.3 |

Notes:

- `cryptography` is pinned `<43` by the `enterprise` extra, which
  forces the vulnerable 42.x line. Dependabot PR #27 widens the cap;
  it is merged in Phase 4, after the history rewrite lands and CI is
  green — it is not silently upgraded here.
- `pip` 24.0 is the virtualenv's own installer, not a shipped project
  dependency.
- `pytest` 8.4.2 is a dev-only dependency.

## Schema validation

```bash
python scripts/validate_schemas.py   # 5 OK
```

The top-level `schemas/` duplicate was deleted in Phase 1; the packaged
`src/textforensics/schemas/` is the single source of truth, asserted by
`tests/test_precommit.py`.

## Claims gate

```bash
python scripts/check_claims.py   # All claims verified (exit 0)
```

The gate runs each claim's evidence (pytest for `test` claims, the
command for `command` claims) and fails on any `unverified`/`false`/
`stale` claim or missing evidence.

## Phase 1 security fixes verified by tests

- Web UI: `tests/test_web_ui.py` — `GET /` renders 200 with the session
  id (Starlette 1.10 `TemplateResponse` signature).
- Emergency stop: `tests/test_workspace_integrity.py` — identity lookup
  never fails headless (`getpass.getuser()` fallback).
- Ollama SSRF guard: `tests/test_ollama.py` — non-loopback `base_url`
  rejected without `allow_remote_host=True`; 10 MB response cap.
- Archive bombs: `tests/test_bundle.py::DecompressionCapTests` — real
  11 MB zero-filled zip/tar.gz bombs (compressed to ~10 KB) rejected.
- Cache bombs: `tests/test_detection_cache.py::TestDeserializeCaps` —
  oversized zlib expansion rejected.

## What is NOT verified here

- RAID / DetectRL / M4 benchmark integration: only placeholder READMEs
  exist under `benchmarks/`; no loader or run artifact. The old
  `partially_verified` claims were deleted, not restated. Real
  integration is Phase 3 work.
- Python 3.11 / 3.13 / 3.14 / 3.15: only 3.12.3 was run locally. Those
  versions are in the CI matrix (`.github/workflows/ci.yml`); local
  verification on them is not claimed.
- Human false-positive rate: no human-FPR evidence exists yet. It is a
  Phase 5 release gate (AGENTS.md rule 10), not a claim made here.
- Live-host Docker/API/web verification: not run in Phase 1. Phase 5.

---

## Verification record — Phase 2 (2026-11-06)

Local verification only (same caveat as Phase 1: GitHub CI on the pushed
head was red and never ran the tests; see the Phase 2 consolidation
report). Environment: same extras-installed venv (`.venv`), Python
3.12.3, `PATH="$PWD/.venv/bin:$PATH"`. Full-suite command as in Phase 1.

### Wave (a) — ledger/policy merge (`6cc0ae1`)

- Suite: **2357 passed / 0 failed / 84% coverage** (12,376 stmts).
- Ruff 0 errors, 179 files formatted; claims gate 31/31; schemas 5 OK.

### CI-greening fixes (`d8fd3f0` whitespace strip, `6b877d9` determinism fix)

- `TRUST_STATES` frozenset → ordered tuple: `trust_map.coverage` key
  order is now deterministic across processes. Verified with the
  CI-style check: 5 `scan` runs under 5 `PYTHONHASHSEED` values
  produced identical output.
- Trailing whitespace stripped in `docs/REVAMP_RESEARCH_2026.md`
  (lines 3, 51, 123) and `docs/REVAMP_SPEC.md` (lines 3, 4) — the only
  trailing whitespace in the repo; these failed the pre-commit
  trailing-whitespace hook in CI run 42219479007.
- Still open (CI config, not code): atheris 1.0.11 wheel fails to build
  on Python 3.12; the Mutation workflow ran 0 mutations. For the
  release gate.

### Wave (b) — one CLI (commit titled "refactor: one CLI — port
Typer-only commands into cli.py, delete typer_cli.py"; exact SHA in
the Phase 2 consolidation report)

- Suite: **2335 passed / 0 failed / 0 skipped / 86% coverage**
  (11,844 stmts, 1,320 missed, 3,962 branches, 565 partial) in
  124.82 s. (2335 vs 2357: −48 deleted Typer tests + 26 new tests.)
- Ruff 0 errors, 178 files formatted; claims gate 31/31; schemas 5 OK.
- `typer_cli.py` (1,251 lines) deleted; `capability policy` and
  `bundle check` ported into `cli.py` with their Typer bugs fixed
  (`--json` NameError; missing `read_bundle` import); `--text` added
  to `scan`/`audit`/`report`/`case export`.
- `bundle_consistency.py`: `trust_map.overall` now validated against
  {strong, mixed, insufficient} (was: dimension states) — every real
  bundle was spuriously warned.

### Wave (c) — one web UI (`f1dcc62`)

- Suite: **2313 passed / 0 failed / 0 skipped / 86% coverage**
  (11,796 stmts, 1,325 missed) in 125.46 s. (2313 vs 2335: −34
  deleted webapp tests + 12 new tests.)
- Ruff 0 errors, 176 files formatted; claims gate 31/31; schemas 5 OK.
- `webapp.py` (217 lines) deleted; its surface ported into `web_ui/`
  (FastAPI): `textforensics web` serves the FastAPI UI, `POST
  /api/report` kept as a raw-bundle alias (now emergency-stop gated,
  411/413 for chunked/oversize), CSP added, Chart.js 4.4.1 vendored
  locally (no CDN fetch). Live smoke on real uvicorn: GET / 200, GET
  /index.html 200, POST /api/report 200.
- The legacy grade panel is gone (it rendered nothing; its diagnostic
  is deprecated upstream).

### Wave (d) — one verifier entry point + one bundle format (`69091e0`)

- Suite: **2332 passed / 0 failed / 0 skipped / 86% coverage**
  (11,809 stmts, 1,320 missed) in 125.38 s. (2332 vs 2313: +19 new
  tests.)
- Ruff 0 errors, 177 files formatted; claims gate 31/31; schemas 5 OK.
- New `verify.verify_case_file_combined` runs both the N-version
  replay and the primary-path seal check and requires both; `case
  verify`, `verify`, and the MCP `verify_case_file` tool all use it.
  `case verify` on a seal-valid but trust-tampered file now exits
  EXIT_INCOMPLETE (was EXIT_OK); malformed JSON exits
  EXIT_INCOMPLETE instead of crashing.
- Result codec now speaks the current v2 format; legacy v1 artifacts
  decode keeping their v1 label (with a warning) instead of being
  silently relabelled. `verify.py` coverage 98%, `result_codec.py`
  96%.

### Wave (e) — consensus / calibration / benchmark / observatory / tiny-module merges

- (e1) `9c9aa87`: agreement → consensus. Suite 2332 passed.
- (e2) `3784d86`: benchmark_fingerprint → benchmark. Suite 2332
  passed.
- (e3) `181729f`: threshold_selection → calibration. Suite **2334
  passed** (+2 new tests). Includes a real bug fix:
  `validate_no_contamination` never detected partial overlap (it
  hashed `(label, score)` rows on one side vs raw text on the
  other); both sides now use `benchmark._compute_sample_hashes`.
  Also: `select_threshold` default detector version corrected to
  the live `"0.1.0"` (was `"1.0.0"`); `create_calibration_artifact`
  renamed `create_threshold_selection_artifact`.
- (e4) `997f8f1`: drift + detector_health → new `observatory.py`.
  Suite 2334 passed.
- (e5) `c195356`: tiny modules folded (robustness/naturalness →
  features; compare → engine; server → api; version →
  `_build_info`). Suite 2334 passed. `models.py` and `constants.py`
  deliberately kept (import-cycle / product-contract reasons — see
  the Phase 2 consolidation report).
- All five: ruff 0 errors, claims gate 31/31, schemas 5 OK.
  Modules 56 → 47; src LOC 28,531 → 28,543 (moves + docstrings).

### Wave (f) — telemetry deleted (`a1ce23c`)

- Suite: **2318 passed** (2334 − 20 deleted telemetry tests + 4 new
  guard tests), claims gate 31/31, schemas 5 OK.
- `telemetry.py` (375 lines) deleted outright — it was load-bearing
  (engine.py, cli.py, `__init__.py`), not an optional extra.
  `--metrics` flag and the `[telemetry]` extra are gone; no
  OpenTelemetry import remains in src/, guarded by
  `tests/test_no_telemetry.py`. `docs/CLAIMS.yaml`
  `core.no_telemetry` restated accordingly.
- Modules 47 → 46; src LOC 28,543 → 28,101.

### Wave (g) — adversarial bright-line test (`4f7f25b`)

- Suite: **2323 passed / 0 failed / 0 skipped / 86% coverage** in
  126.47 s; ruff 0 errors, claims gate 31/31, schemas 5 OK.
- New `tests/test_adversarial_bright_line.py` (5 tests) proves
  `adversarial.py` never emits rewrite suggestions: no public entry
  point returns text, no rewrite/evasion vocabulary in outputs, no
  long output string is a rewritten copy of the input
  (SequenceMatcher < 0.9 unless a verbatim quote), no evasion verb
  in any public API name. No source change in this wave.

### Wave (h) — model_card + compliance → transparency notes

- Suite: **2325 passed / 0 failed / 0 skipped / 86% coverage**
  (11,551 stmts, 1,304 missed, 3,894 branches, 557 partial) in
  128.78 s; ruff 0 errors, 168 files formatted; claims gate 31/31;
  schemas 5 OK. (2325 vs 2323: +2 new tests.)
- `ModelCard.eu_ai_act_compliance` → `eu_ai_act_transparency_notes`
  (field, `to_dict` key, Markdown heading); the builder no longer
  asserts a risk class (`"not_assessed"`), a conformity assessment
  (`"not_assessed"`), or a CE marking (`"not_claimed"`); it no longer
  claims "Performance metrics published" (the generator leaves
  `metrics=[]`) and the data-governance flags now reflect whether
  documentation was actually supplied. The license default is now
  the project's actual `AGPL-3.0-or-later` (was the wrong
  `Apache-2.0`).
- `ComplianceReport.to_dict()` gains `"report_type":
  "transparency_note"` + a self-assessment disclaimer; `summary()`'s
  `"compliance_score"` → `"transparency_score"` (same values).
  Class names and per-check status values are unchanged — they
  describe self-assessed statuses inside a labelled transparency
  note, not a certification.
- Modules 46 (unchanged); src LOC 28,101 → 28,150 (docstrings +
  the disclaimer/note text). No docs references to the old outputs
  needed updating (none existed outside the coverage figure, which
  is unchanged: `model_card.py` 79%).

## Verification record — Phase 3, U7 claim-to-evidence gate (2026-11-06)

U7 extends `scripts/check_claims.py` into a claim-to-evidence CI gate
and migrates every claim in `docs/CLAIMS.yaml` to a measured run
artifact in `docs/evidence/runs/` (registry `docs/evidence/registry.json`).
Records are produced by `scripts/seed_evidence.py`, which runs the
measurements; nothing is hand-written. Repo HEAD at measurement time:
`d759bd8` (U7 gate + tests), canonical identity
`Stratos <28989754+strmt7@users.noreply.github.com>`.

### Commands

```bash
# Produce/refresh all records (extras venv, bin/ on PATH):
python scripts/seed_evidence.py --force
# Core-only suite record (bare core venv, its bin/ on PATH):
/tmp/tfc-core-venv/bin/python scripts/seed_evidence.py --force --suffix core --only suite
# Run the gate (writes docs/evidence/report-card.md):
python scripts/check_claims.py
# Full suite (extras venv, bin/ on PATH):
python -m pytest tests/ -q -p no:cacheprovider --cov=src/textforensics --cov-report=term -o addopts=''
```

### Measured numbers (2026-11-06, Python 3.12.3)

- Full suite, extras venv: **2354 passed, 1 failed, 0 skipped,
  86% coverage** (11,582 stmts, 1,311 missed, 3,904 branches,
  557 partial) in 128.28 s. The 1 failure is
  `tests/test_diagnostics.py::TestDiagnosticsEngine::test_memory_check`,
  the known host-memory flake (fails when this VM sits above 95%
  memory use; passes in isolation and in CI). Record
  `EV-20261106-suite`.
- Full suite, bare core-only venv: **2243 passed, 0 failed,
  112 skipped, 82% coverage** (11,582 stmts, 1,874 missed,
  3,904 branches, 537 partial) in 114.52 s. The 112 skips are tests
  for optional extras not installed (fastapi/typer-gated). The
  memory flake did not fire in this run; an earlier core run the
  same day gave 2242 passed / 1 failed (the flake) / 112 skipped.
  Record `EV-20261106-suite-core`.
- ruff: **0 errors**, 171 files formatted. Record `EV-20261106-ruff`.
- bandit: **16 Low, 0 Medium, 0 High** (`-lll` exit 0). Record
  `EV-20261106-bandit`.
- pip-audit: **25 findings in 3 packages** (cryptography 11, pip 12,
  pytest 2). Record `EV-20261106-pip-audit`.
- Schemas: **7 OK** (5 original + run-artifact + evidence-registry).
  Record `EV-20261106-schemas`.
- Determinism: **1 unique hash per 5 scan + 5 report runs**
  (reproducibility workflow's exact jq filter), Trust Map coverage
  keys in declared order. Record `EV-20261106-determinism`.
- Code audit (AST scan of `src/`): the only network-client import
  is `src/textforensics/ollama.py`. Record `EV-20261106-code-audit`.
- Doc records: license `AGPL-3.0-or-later`, CI matrix
  Python 3.11–3.15, `SOURCE_DATE_EPOCH=1704067200` — each cited
  line hashed. Records `EV-20261106-doc-license`,
  `EV-20261106-doc-ci-matrix`, `EV-20261106-doc-repro`.

### Claims gate

```bash
python scripts/check_claims.py   # exit 0
```

Result: **33 passed, 0 failed** (31 original claims + 2 new:
`test_suite_measured_core`, `detector.deterministic_output`).
The gate re-hashes all 11 registry artifacts, checks every claim's
`values` map against its record, enforces the 90-day / detector-version
staleness rule, requires a drops manifest, and writes the deterministic
report card `docs/evidence/report-card.md` (CI diffs it). The CI
`claims-gate` job runs the gate on every push (Python 3.12,
`.[dev,api,mcp,security]` — the `security` extra was added after the
first CI run failed on a missing `bandit`; see below).

### Gate failure demonstrations (scratch worktree, 2026-11-06)

- **Tampered artifact:** `tests_passed` in
  `EV-20261106-suite.json` changed to 9999. Gate exit 1; registry
  failure "run artifact hash mismatch (U7 (b)): registry says
  bfb3faa38a46..., file hashes to 8a292c60bd14..."; 10 passed,
  23 failed (every claim citing the suite record).
- **Stale claim:** suite artifact `run_date` set to 2026-07-29 with
  registry/claim hashes and `last_verified` realigned. Gate exit 1;
  10 passed, 23 failed, every failure "stale — evidence record is
  100 days old (> 90 days) (U7 (d))".

### CI fixes after the U7 push (2026-11-06)

CI run 42254886415 on head `2bc6e03` was RED, with two root causes
(neither a U7 design failure) plus the known atheris pinned-install
failure (release gate, untouched). Both were fixed in commits
`46f2ade` (baseline) and `0766524` (claims-gate job); the parent
re-verifies CI on the fixed head.

- **Failure 1 — all five Core jobs (Python 3.11–3.15): pre-commit
  `detect-secrets` failed.** It flagged 36 "Hex High Entropy String"
  values U7 added: 11 `run_artifact_sha256` lines in
  `docs/CLAIMS.yaml`, 11 in `docs/evidence/registry.json`, and 14 in
  `docs/evidence/runs/EV-20261106-*.json` (`code_version` +
  `document_sha256`). Because pre-commit aborts (`bash -e`), pytest
  never ran in Core — the run finished in ~2 minutes with no test
  results. Every flagged value was audited by recomputation: each
  `run_artifact_sha256` equals the SHA-256 of its artifact file, each
  `code_version` is commit `d759bd8` (an ancestor of HEAD), each
  `document_sha256` equals the SHA-256 of the cited document at that
  commit. No credentials, tokens, or keys. The 36 entries were added
  to `.secrets.baseline` (44 pre-existing entries preserved, 80 total);
  the hook is unchanged and no evidence file is excluded, so future
  real secrets in these files are still caught. Trap found while
  doing this: a naive `detect-secrets scan --baseline` silently
  drops baseline entries whose keys use Windows backslashes (40
  testdata/tests/golden entries) and adds unaudited findings — the
  baseline was instead updated by a script that grafted only the 36
  audited entries, verifying `sha1(raw value) == hashed_secret` for
  each. Verified locally: `pre-commit run --all-files` — all 13 hooks
  pass (detect-secrets included; the hook fails while the baseline is
  unstaged, by design, and passes once staged).
- **Failure 2 — claims-gate job: 32 passed, 1 failed.** Only
  `security.bandit_no_medium_high` failed: `No module named bandit`.
  The job installed `.[dev,api,mcp]`; bandit lives in the separate
  `[security]` extra (`bandit>=1.7.0,<2`, `pip-audit>=2.10.1,<3`).
  The pip-audit claim passed because its evidence is a doc, not a
  command. Fix: the job now installs `.[dev,api,mcp,security]`
  (one-line change in `.github/workflows/ci.yml`; no pyproject.toml
  change, and the gate still fails hard on a missing tool). Verified
  locally: `python scripts/check_claims.py` — **33 passed, 0 failed**;
  fresh gate run leaves `docs/evidence/report-card.md` unchanged
  (`git diff --exit-code` clean), which is the job's second step.
- **Failure 3 — Supply-chain security: gitleaks found 36 leaks.**
  After the two fixes above were pushed, CI on head `ec543ba` was
  green where it matters (Core 3.11–3.15, claims-gate, Reproducibility
  all SUCCESS; only the atheris pinned-install job and Mutation
  failed, both release-gate items) — except Supply-chain security,
  whose "Full-history secret scan" job failed. Gitleaks 8.24.3
  scanned the pushed range `46f2ade^..ec543ba` and reported 36
  `generic-api-key` findings, all in `.secrets.baseline`, all in
  commit `46f2ade`: the baseline's `hashed_secret` values (SHA-1
  hashes of the audited values) trip gitleaks' generic rule. The
  detect-secrets fix broke gitleaks — the two scanners disagree
  about hash-looking strings. Fix: `.gitleaks.toml` at the repo root
  with `[extend] useDefault = true` (without it a custom config
  REPLACES the default rules) and a global `[allowlist]` for the
  `.secrets.baseline` path only. This hides no secrets: the file
  holds hashes only, never raw secrets, and the detect-secrets hook
  still guards new additions to it. The allowlist is path-based, so
  future baseline updates need no per-entry maintenance (no
  fingerprint allowlists, which are commit-bound). Verified locally
  with gitleaks 8.24.3 (the CI version): the CI range scans clean
  (**0 leaks**, exit 0), and a planted fake GitHub PAT in a scratch
  commit is still caught (`github-pat`, exit 2), proving the default
  rules survive the extension. A stronger full-history scan (261
  commits) finds exactly one pre-existing `generic-api-key` finding
  outside the CI range — `tests/test_watermarking.py:535`, commit
  `882b405` (2026-11-03): an assertion comparing a reloaded keypair
  against the one generated in the test, where both sides are
  runtime-generated objects and no key material appears in the line
  at all. It is a false positive, predates U7, and is left untouched here for the release
  gate (a line-targeted allowlist or `gitleaks:allow` comment); it
  does not affect CI, which scans only pushed commits.

### Measured numbers after the CI fixes (HEAD `0766524`, 2026-11-06, Python 3.12.3)

- Full suite, extras venv: **2355 passed, 0 failed, 86% coverage**
  (11,582 stmts, 1,310 missed, 3,904 branches, 558 partial) in
  128.16 s. The `test_memory_check` host flake did not fire in this
  run.
- The 5 serve/web tests that failed CI on `e99c474` all pass in the
  bare core-only venv (fastapi absent):
  `test_remote_bind_guard_surfaces_clean_error`,
  `test_serve_command_with_mocked_api`,
  `test_remote_bind_guard_serve`, `test_web_remote_bind_guard`,
  `test_serve_api_with_uvicorn` — **5 passed**.
- pre-commit `--all-files`: **13 hooks pass, 0 fail**.
- Claims gate: **33 passed, 0 failed**; report-card diff clean.
- The seeded U7 evidence records are unchanged by these fixes (no
  re-seeding; their measured numbers above still stand).

### Measured numbers after the gitleaks fix (HEAD `547797b`, 2026-11-06, Python 3.12.3)

- Full suite, extras venv: **2355 passed, 0 failed, 86% coverage**
  (11,582 stmts, 1,310 missed, 3,904 branches, 558 partial) in
  127.98 s. The `test_memory_check` host flake did not fire in this
  run.
- Gitleaks 8.24.3 (CI version), CI range `46f2ade^..ec543ba`:
  **0 leaks**, exit 0. Planted fake GitHub PAT control: still caught
  (`github-pat`, exit 2). Full-history scan (261 commits): 1
  pre-existing false positive (`tests/test_watermarking.py:535`,
  see Failure 3 above) — outside the CI scan range.
- pre-commit `--all-files`: **13 hooks pass, 0 fail**.
- Claims gate: **33 passed, 0 failed**; report-card diff clean.

### What is NOT verified here

- **Worst-slice human FPR: unknown.** No human-FPR evidence is
  recorded in the registry yet; the report card says so honestly.
  Human-FPR measurement arrives with U1/datasets (Phase 3) and is a
  Phase 5 release gate. No FPR is claimed anywhere.
- The seeded records are dated 2026-11-06 and go stale after 90 days
  (2027-02-04) or if the detector version changes; re-run
  `scripts/seed_evidence.py` and update the citing claims.
- CI on the fixed head (`0766524`) has not been observed yet — the
  parent verifies the run (Core on all five Pythons, claims-gate,
  Reproducibility) after pushing. The atheris pinned-install failure
  and the Mutation workflow (0 mutations) remain open for the Phase 5
  release gate.

## Verification record — Phase 3, datasets wave 1 (2026-11-06)

Loaders for RAID, MAGE, Beemo and OpAI-Bench (MixSet deferred — see
below) plus first preliminary measurements of the built-in detector on
documented samples. Full report:
`~/workspace/goals/textforensics-complete-revamp/hidden_files/phase3-datasets-wave1.md`.

### Where the data lives

- Local cache only, never committed:
  `~/.cache/textforensics/datasets/<dataset>/<config>/<split>.jsonl`
  plus `<split>.manifest.json` (source URL, fetch date, row count,
  file SHA-256). Override with `TEXTFORENSICS_DATASETS_DIR`.
- No dataset text is in the repo, in tests, or in any run artifact.
  Artifacts (`docs/evidence/runs/EV-20261106-dataset-*.json`) carry
  counts, hashes and metrics only. Test fixtures are synthetic.
- Transport: standard library only (`urllib` against
  `https://datasets-server.huggingface.co`); the core still has zero
  third-party dependencies. Full-corpus parquet evaluation is U1/U3
  future work and would use `datasets` as an optional extra then.

### Licences (resolved 2026-11-06 from live sources, before any download)

- RAID (`liamdugan/raid`): **MIT** — HF API tag `license:mit`,
  GitHub repo metadata MIT, LICENSE file MIT (Copyright (c) 2024-
  Liam Dugan). Caveat: the MIT text covers the distribution; the
  underlying human source texts carry their own upstream licences.
- MAGE (`yaful/MAGE`): **Apache-2.0** (LICENSE file, repo metadata,
  HF tag); the README licence badge asserts **CC BY 4.0**. Both
  strings are recorded in the loader spec and the artifact; both are
  permissive, attribute the authors either way.
- Beemo (`toloka/beemo`): card says **MIT**, but prompts +
  `human_output` (from No Robots) are **CC-BY-NC-4.0** — the human
  half is non-commercial use only. `model_output` and LLM-edited
  versions follow the underlying LLM licences. Never cite "MIT" alone.
- OpAI-Bench (`OpAI-Bench1/OpAI-Bench`): **Apache-2.0** — HF card
  "Licensing and Reuse" section, HF tag, README badge and LICENSE
  file agree. (GitHub's "Other (NOASSERTION)" is a detection
  artefact of the abbreviated 37-line LICENSE file, not a competing
  licence. The LICENSE closes with "Copyright 2026 Anonymous".)
- MixSet (`ONE-Lab/MixSet`): **NO LICENCE FOUND** on any source
  (HF card, GitHub repo, READMEs; the paper's CC BY 4.0 covers the
  paper, not the dataset). Loader is code-complete and tested with
  mocks, but the licence gate refuses every live fetch and the
  mapper refuses on unverified label polarity. No MixSet rows, no
  MixSet artifact, until the authors clarify.

### Verified row counts (datasets-server `/size`, 2026-11-06 — not paper figures)

- RAID: **4,981,100 rows loaded** (config `raid` 4,309,100: train
  2,270,000 + extra 2,039,100; config `raid_test` 672,000 test).
  Endpoint reports `partial:true` (viewer exposes the first 5 GB).
- MAGE: **436,606 rows** (train 319,071 / validation 56,792 / test
  60,743). The GitHub README claims 447,674 — use the endpoint figure.
- Beemo: **2,187 rows**, single train split. (The paper's ~19.6k is
  text variants: 2,187 rows x multiple text fields per row.)
- OpAI-Bench: **318,249 rows** (default 281,178: train 196,029 / dev
  42,363 / test 42,786; ablations 37,071). (The README claims 279,794
  versioned samples — use the endpoint figure.)
- MixSet: **3,600 rows** (train 3,000 / test 600) — metadata only,
  no rows fetched.

### Sampling (all strided — every split is ordered by testbed/model)

First-*n* sampling was measured and rejected: RAID first-200 rows are
all human, MAGE train is blocked by `src`. Samples are *n* evenly
spaced rows across the split (`scripts/measure_datasets.py`,
`fetch_strided_sample` — deterministic, no randomness). The script
refuses to run if the server's split total differs from the plan.

```bash
python scripts/measure_datasets.py --only raid        # n=3000 strided (U1 growth; was 600)
python scripts/measure_datasets.py --only mage        # n=400 strided (U1 growth; was 200)
python scripts/measure_datasets.py --only beemo       # n=100 records strided (unchanged)
python scripts/measure_datasets.py --only opai_bench  # n=500 strided (U1 growth; was 100)
python scripts/measure_datasets.py --list             # print the plan, no network
```

U1 (2026-11-06) grew the plan so the thin slices strengthen: RAID
3000 strided for ~100 humans (its train human fraction is only
~3.3%), MAGE 400, OpAI-Bench 500. Beemo is unchanged (200 humans
already). The wave-1 preliminary numbers below are superseded by
the larger samples.

### Measured numbers (BuiltinHeuristicDetector 0.1.0, Python 3.12.3, all preliminary)

Re-measured with the grown U1 samples on 2026-11-06 (artifacts
`EV-20261106-dataset-{raid,mage,opai-bench}`, `code_version`
`5cfd6a6e`); Beemo unchanged from wave 1. The wave-1 numbers
(RAID n=600 AUROC 0.6414, MAGE n=200 AUROC 0.5417, OpAI-Bench n=100
AUROC 0.4697) are superseded by the table below. Wave-1 verification
at HEAD `2e2d81a` (2026-11-06) stands as history:

- Full suite, extras venv: **2396 passed, 0 failed, 86% coverage**
  (11,840 stmts, 1,325 missed, 3,988 branches, 570 partial).
- Full suite, bare core-only venv (`/tmp/tfc-core-venv`, fastapi
  confirmed absent): **2283 passed, 1 failed, 112 skipped**. The one
  failure is `test_memory_check`, the known host flake: it asserts on
  the host's available memory, and the VM was at 7,451/7,934 MB used
  (482 MB available) during the run — it fails in isolation too
  under that pressure and passes in CI. Not a code regression.
- Claims gate: **33/33**; ruff check + format clean.

| Dataset | Sample | Labels (0 / 1 / None) | AUROC | TPR@1% FPR | TPR@5% FPR | Abstentions |
| --- | --- | --- | --- | --- | --- | --- |
| RAID | 3000 strided train | 92 / 2908 / 0 | 0.5937 | 0.0454 | 0.1348 | 1490/3000 |
| MAGE | 400 strided train | 117 / 283 / 0 | 0.5567 | 0.1060 | 0.1661 | 217/400 |
| Beemo | 100 records -> 900 rows | 200 / 700 / 0 | 0.3976 | 0.0129 | 0.0586 | 487/900 |
| OpAI-Bench | 500 strided train | 56 / 55 / 389 | 0.3961 | 0.0 | 0.0 | 55/111 |

- RAID: human mean score 0.2841 vs machine 0.3298. Train human
  fraction is only ~3.3%, so 3000 rows yield 92 humans — just short
  of the 100-human minimum for a `supported` slice, so the U1 RAID
  seed record stays `partial` on sample size alone. Disjointness
  vs `raid_test`/test (n=50): **disjoint, verified, 0 shared**.
- MAGE: human mean 0.2533 vs machine 0.2926. The native polarity
  flip held on all 400 rows (every `src` cross-check passed:
  `_human` <-> native 1, `_machine_` <-> native 0). The strided
  sample covers 11 testbeds. Disjointness vs validation (n=50):
  **disjoint, verified, 0 shared**.
- Beemo: AUROC **below chance (0.3976)** — the heuristic scores
  expert human text higher than machine text (human mean 0.2859 vs
  machine 0.2505; per-kind, plain human 0.2987 is the highest mean,
  llama-3.1-70b P2 0.202 the lowest). The expert-edited regime
  inverts the baseline. Disjointness not checkable (single split);
  recorded in the artifact drops.
- OpAI-Bench: only 111 of 500 rows carry a binary label (v0 pure
  human, v8 fully machine, 56 vs 55); the 389 partial rows take no
  binary label and are reported by `ai_sentence_ratio`. AUROC
  **below chance (0.3961)** on n=111 — the heuristic scores pure
  human text higher than fully machine text here (human mean 0.3334
  vs machine 0.2951), so TPR@1% and TPR@5% are both 0.0. Recorded,
  not claimed. Disjointness vs dev (n=50): **disjoint, verified,
  0 shared**.
- AUROC/TPR@FPR are threshold-free (no threshold was fitted on any
  sample). Scores are the detector's uncalibrated heuristic scores,
  never presented as probabilities.

### What is NOT verified here

- **No new claims.** The claims gate stays **33/33**; dataset
  numbers are preliminary evidence records only (registry now 15
  records). The report card still honestly leads with worst-slice
  human FPR = unknown: the grown samples are still preliminary
  slices, not release-gate human-FPR evidence, and the RAID human
  slice (n=92) is still below the 100-human minimum. Whether the
  U1 seed records promote the report-card lead is a claims
  decision for the Phase 5 release gate, not U1.
- **MixSet**: no live rows, no measurement (licence unresolved).
- **Full-corpus runs**: every measurement is a small documented
  sample (see the table). Full-corpus evaluation is U1/U3 work.
- **Other Python versions**: measured on 3.12.3 only; CI covers the
  matrix.
- **PAN 2025**: untouched in wave 1 (wave 2, gated on Greg's TIRA
  registration). RealDet / CrisisFake: no loader (no verified
  route). MultiSocial: dropped by Greg's decision.

### CI fixes after the wave-1 push (2026-11-06)

CI run 42291714530 on head `5919a8a` was RED: all five Core jobs
failed at pre-commit hooks; the claims-gate job passed, as did
Reproducibility, Supply-chain, Scorecard, Semver and Repository
Integrity. No test ran in Core (pre-commit aborts first).

- Failure 1 — `end-of-file-fixer`: wave 1 left a trailing blank
  line at the end of this file. Fixed by committing the hook's own
  change (commit `f545c52`).
- Failure 2 — `detect-secrets`: the hook flagged 12 hex values wave
  1 added as "Hex High Entropy String": the 4 dataset `code_version`
  commit SHAs, the 4 `cache_file_sha256` values and the 4 registry
  `run_artifact_sha256` values. Every value was audited by
  recomputation (44/44 checks): each `code_version` is a real commit
  and an ancestor of HEAD; each cache hash equals the manifest
  `file_sha256` and the recomputed SHA-256 of the local cache file;
  each registry hash equals the recomputed SHA-256 of its artifact
  file. No credentials, tokens or keys. Only the 12 audited entries
  were grafted into `.secrets.baseline` (80 -> 92 entries, 0 dropped;
  commit `e142bbd`).
- The hook itself then normalised the 40 legacy backslash-keyed
  baseline entries to forward slashes and refreshed stale registry
  line numbers on its first run (exit 3, by design); that rewrite was
  verified entry-by-entry (same 92 hashed secrets,
  plugins/filters/version unchanged) and staged. This permanently
  removes the backslash-key trap documented after the U7 fix: future
  baseline updates can no longer silently drop those entries. Four
  legacy entries for hook-excluded test files still carry stale line
  numbers from the 2026-11-02 Windows baseline; they are untouched
  (pre-existing, excluded from the scan) and are not a regression.
- Gitleaks 8.24.3 (CI version): range `5919a8a^..HEAD` and wider
  range `1cf9716^..HEAD`: **0 leaks**, exit 0. The `.gitleaks.toml`
  path allowlist for `.secrets.baseline` covers the new entries.

### Measured numbers after the wave-1 CI fixes (HEAD `e142bbd`, 2026-11-06, Python 3.12.3)

- Full suite, extras venv: **2395 passed, 1 failed, 86%** coverage
  (11,840 stmts, 1,328 missed, 3,988 branches, 571 partial) in
  134.28 s. The 1 failure is the known `test_memory_check`
  host-memory flake (VM at ~94% memory; passes in isolation — 1
  passed in 0.48 s immediately afterwards).
- pre-commit `--all-files`: **13 hooks pass, 0 fail**.
- Claims gate: **33 passed, 0 failed**; report-card diff clean.
- ruff: 0 errors. Schemas: 7 OK.
- Seeded wave-1 evidence records: unchanged — no re-seeding was
  needed or done; the wave-1 measured numbers above still stand.

## Verification record — Phase 3, U1 validation-evidence registry (2026-11-06)

U1 builds the validation-evidence registry (`textforensics.evidence-record/v1`)
and the regime-conditioned Trust Map derivation engine (Trust Map v3). Design:
`hidden_files/phase3-u1-design.md`; full report:
`hidden_files/phase3-u1.md`. Seven commits, `dc2e1f1`…`596d10a`.

### What was built

- Schema `textforensics.evidence-record/v1` + `textforensics.validation-registry/v1`
  (packaged schemas; `scripts/validate_schemas.py` now reports 9 OK, was 7).
  The registry schema types records as generic objects — a relative `$ref`
  to the record schema fails offline under `Draft202012Validator`
  (`Unresolvable`); the Python loader enforces record shape.
- `src/textforensics/validation.py` (stdlib-only): `ValidationRecord`
  dataclasses, `validate_record()` with the validator-enforced partial cap
  (missing mandatory-for-supported field caps effective status at `partial`),
  licence/contamination missing = hard rejection, `compute_signature()` /
  `verify_signature()` (SHA-256 hash-seal over canonical JSON), computed
  staleness (`effective_status`: stale on detector-version change,
  `next_revalidation_due` expiry, or `demoted_by`), contamination labels,
  `ValidationRegistry` (registry-id verification, regime lookup).
- Trust Map v3 (`textforensics.trust-map/v3`, `TRUST_STATES_V3` adds
  `stale`): `derive_trust_map` in `validation.py` derives the 8 evidence
  dimensions from U1 records only, citing matching record ids; live
  dimensions reuse the v2 helpers when observations are supplied, else
  `unknown`. V2 behaviour and the v2 schema contract are unchanged
  (verified: a v2 map with a `stale` dimension or a `stale` coverage key
  is rejected; v3 accepts it; v1 rejects it).
- Seeded registry `docs/validation/registry.json` (4 records, all
  `partial`): RAID (92/2908), MAGE (117/283), Beemo (200/700),
  OpAI-Bench (56/55 binary). Every record carries licence/consent,
  contamination flag `no`, per-slice AUROC + TPR@1%/5% FPR + native
  FPR/TPR with bootstrap 95% CIs (1000 resamples, seed 20261106), and a
  drops manifest. Native FPR is 0.0000 on all four (the categorical
  verdict fires only at score ≥ 0.68; highest human score in any seed
  sample is 0.625) — a quiet verdict, not separation: AUROC is
  below chance on Beemo (0.3976) and OpAI-Bench (0.3961). MixSet has
  no record (no licence — the schema forbids a record without one).
- Follow-up commit `596d10a`: `tpr_native` (paired with `fpr_native`)
  is now an optional `evidence-record/v1` metric; the seed script
  wires in the already-computed native TPR and the registry was
  re-seeded (registry_id `85822eabb900…`).

### Measured numbers (HEAD `596d10a`, 2026-11-06, Python 3.12.3)

- Full suite, extras venv: **2531 passed, 0 failed, 86%** coverage
  (12,977 stmts, 1,493 missed, 4,482 branches, 707 partial) in
  144.35 s. The `test_memory_check` host flake did not fire.
- pre-commit `--all-files`: **13 hooks pass, 0 fail** (verified
  independently by the coordinator, twice — after Package B and after
  the `tpr_native` follow-up).
- Claims gate: **33 passed, 0 failed**; report-card diff clean.
- Schemas: **9 OK**. Ruff: 0 errors, format clean.
- Gitleaks 8.24.3 (CI version): **0 leaks** on `75e9c30..HEAD`
  (follow-up) and on `dc2e1f1^..HEAD` (all of U1, 7 commits).
- Engine smoke test on the real seeded registry (en, 229 words,
  news, raw machine output): v3 map, overall `mixed`, coverage
  0 supported / 6 partial / 4 unknown / 0 out_of_scope / 0 stale,
  record ids cited on every matched dimension.

### What is NOT verified / NOT done here

- **No new claims.** The claims gate stays **33/33** and the report
  card still leads with worst-slice human FPR = unknown. Promoting
  it on the native-verdict zeros is a claims decision for the Phase 5
  release gate, not U1.
- **RAID at 92 humans** is 8 short of the 100-human minimum for a
  `supported` slice; a future re-measurement (wave 2 / release gate)
  can grow it. All four seeds are `partial` (unreviewed, preliminary
  samples; OpAI-Bench's binary slice is 111 rows).
- **`verify.py` still carries its own 4-state `_TRUST_STATES`** for
  case-file verification, so a v3 Trust Map embedded in a case file
  would be rejected there. Nothing embeds v3 maps in case files yet;
  this is a U2/release-gate decision, not a U1 fix.
- **A v3 map from U1 records alone is at most `mixed`**: temporal
  stability caps at `partial` from a single snapshot, so `strong`
  is unreachable until U3 supplies longitudinal evidence. By design.
- **`tpr_native` is optional in v1**, not mandatory-for-supported;
  a future schema revision may make it mandatory. Records predating
  it load with `tpr_native=None`.

## Verification record — Phase 3, datasets wave 2, worker A: GhostWriter (2026-11-07)

GhostWriter loader + first preliminary measurement, plus the shared
resumable large-file downloader (stdlib-only) that worker B needs
for DetectRL-X. Work is in `main` only, canonical identity
`Stratos <28989754+strmt7@users.noreply.github.com>`; no push, no
release, no tag. Commits `ddab1f2`…`563c212` (4 commits) on top of
`530c56b` (U1 head). DetectRL-X and the three licence-blocked loaders
belong to later workers and are deliberately NOT done here.

### What was built

- `download_large_file` in `src/textforensics/datasets.py`
  (wave-2 shared infrastructure): HTTP Range resume (`.part` file +
  atomic rename, so a partial file is never left as valid), retries
  with exponential back-off on `RemoteDisconnected` /
  `HTTPException` / `ConnectionError` / `URLError` / timeouts and
  5xx (4xx fail immediately — the wave-1 client retry discipline),
  SHA-256 and byte-count verification against a manifest, and no
  re-download of an already-verified destination. 8 mocked unit
  tests (fresh, hash mismatch, resume, range-ignored restart, retry,
  404, already-downloaded, byte-count). Live smoke test against a
  small real file over the datasets-server endpoint: fresh download
  and resume both hash-verified (SHA-256
  `51dbcc80…`, 1,081 bytes).
- GhostWriter spec + mapper: per-domain licence table (8 domains,
  see below); `DatasetSpec` gains an optional `domain_licences`
  field (default `None`; wave-1 specs untouched); the mapper refuses
  any row whose domain has no recorded licence (fail closed), any
  unexpected label value, and missing text or id. Fusion (label 2)
  → `label=None`, regime `mixed-origin` (U4 spine, like the
  OpAI-Bench partials); human/ai rows are regime `raw`;
  `source_id` is the row `id`; meta carries domain, lang, agent,
  type, date (raw string, never parsed) and source.
- Measurement: `scripts/measure_datasets.py` SAMPLE_PLAN gains
  ghostwriter (train n=500 strided, total 332,224; disjointness vs
  validation n=50 strided, total 47,548). Artifact
  `docs/evidence/runs/EV-20261107-dataset-ghostwriter.json`
  (badge `available`, `preliminary: true`, drops manifest); U7
  registry rebuilt (16 records); report card regenerated.
- U1 seed: `evr-20261107-ghostwriter-builtin-heuristic` appended to
  `docs/validation/registry.json` (4 → 5 records; the existing 4
  records are byte-identical, `created_at_utc` preserved,
  registry_id `85822eabb90096ba` → `2d2a1651498da998`).
  `scripts/seed_validation.py` now takes `--run-date` (the U7
  artifact lookup is no longer hardcoded to `EV-20261106`; it
  defaults to the latest matching artifact) and `--append` (merge
  into the existing registry, duplicate record ids refused).
- Baseline grafts: 3 measurement hashes + 4 seed-record hashes,
  each audited by recomputation (cache/artifact SHA-256s, record
  signature via `compute_signature`, code_version checked as a real
  commit); 106 → 109 → 113 entries, 0 unexpected drops (multiset
  check). No full rescan was ever run.

### Licence (verified 2026-11-07 from the live HF card, lines 340–468)

GhostWriter has **no single licence** — the licence is the
per-domain table, recorded verbatim in the spec and the artifact.
There is no `license:` tag in the HF API record; the card text is
the only licence source. Two domains are NC and the blog corpus is
non-commercial-research-only; use is non-commercial research
evaluation, local cache only, no redistribution, no commercial use.

- cnn_news **Apache-2.0**; arxiv_papers **arXiv.org non-exclusive
  licence to distribute**; blog_authorship_corpus **CC0 / free for
  non-commercial research**; bundestag **DL-DE-BY-2.0**;
  house_of_commons **Open Parliament Licence**; euro_court_cases
  **CC-BY-NC-SA 4.0**; student_essays **CC-BY-NC-SA 4.0**; gutenberg
  **CC0**. (The card says "seven domains" in one place, but the
  licence table and the viewer show 8 — trust 8.)

### Verified row counts (datasets-server `/size`, 2026-11-07 — not paper figures)

- GhostWriter (`TheItCrOw/GhostWriter`): **474,904 rows total**
  (single config `default`, 9 columns, `partial:false`): train
  332,224 / test 95,132 / validation 47,548.
- Live `/rows` probe confirms the 9 columns (`id`, `text`,
  `domain`, `date`, `source`, `lang`, `label`, `agent`, `type`),
  labels 0/1/2, and agents `human` / `gpt-4o-mini` / `gemma2:9b` /
  … . `date` formats are inconsistent across rows (`2025`, `-`,
  `01,July,2004`, `2022-09-23T00:00:00`, `2007-2015`) — never
  parsed. `lang` has 2 values in this sample (en-EN, de-DE); the
  card's third value did not appear — do not assume it.

### Sampling (strided, as in wave 1)

Train n=500 strided across 332,224 rows; disjointness vs validation
n=50 strided across 47,548 rows. Cache + manifest under
`~/.cache/textforensics/datasets/ghostwriter/default/` (local only,
never committed): `train.jsonl` (500 rows, SHA-256
`12d2ab69…`) and `validation.jsonl` (50 rows, SHA-256
`1af9f67e…`).

### Measured numbers (BuiltinHeuristicDetector 0.1.0, Python 3.12.3, preliminary)

| Dataset | Sample | Labels (0 / 1 / None) | AUROC | TPR@1% FPR | TPR@5% FPR | Abstentions |
| --- | --- | --- | --- | --- | --- | --- |
| GhostWriter | 500 strided train | 137 / 210 / 153 | 0.436 | 0.0 | 0.0048 | 162/347 |

- GhostWriter: AUROC **below chance (0.436)** — the heuristic
  scores human text higher than machine text (human mean 0.3199 vs
  machine 0.2880; human max 0.674, machine max 0.5744), so TPR@1%
  is 0.0 and TPR@5% is 0.0048. The highest human score (0.674) sits
  just under the detector's 0.68 `ai_like` bar, so the native
  verdict never fires on this slice. All 8 domains are present in
  the sample (student_essays 135, bundestag 85,
  blog_authorship_corpus 71, cnn_news 61, house_of_commons 56,
  euro_court_cases 47, arxiv_papers 25, gutenberg 20). The 153
  fusion rows take no binary label (mixed-origin, U4 spine).
  Disjointness vs validation (n=50): **disjoint, verified,
  0 shared**.
- The sample is bilingual: 288 English + 59 German labelled rows.
  The U1 record's regime language is `mul` (BCP 47) with the split
  in `language_variety`; per-language metrics are not reported
  separately. Fusion rows are all `chunk` and labelled rows are all
  `fulltext`, so chunk behaviour is unmeasured — recorded as a
  limitation.
- U1 seed record `evr-20261107-ghostwriter-builtin-heuristic`
  (partial / partial, next revalidation 2027-02-05): AUROC 0.4360
  [0.3647, 0.5036], TPR@1% FPR 0.0000 [0.0000, 0.0044], TPR@5% FPR
  0.0048 [0.0000, 0.0332], native FPR 0.0000 [0.0000, 0.0000],
  native TPR 0.0000 [0.0000, 0.0000], abstention 0.4669 [0.4121,
  0.5187] (bootstrap 95% CIs, 1000 resamples, seed 20261106).
  Length (labelled rows): min 8 / median 447 / max 20084 words.
  Generators are the `agent` values (gemma2:9b, gpt-4o-mini,
  phi3:3.8b, nemotron, deepseek-r1:32b, deepseek-r1:1.5b).

### Measured verification numbers (HEAD `563c212`, 2026-11-07, Python 3.12.3)

- Full suite, extras venv: **2553 passed, 0 failed, 86%** coverage
  (13,059 stmts, 1,495 missed, 4,522 branches, 709 partial).
- `ruff check` + `ruff format --check` clean (180 files).
- Claims gate: **33/33**; report-card diff clean (regenerated).
- Schemas: **9 OK**.
- `pre-commit run --all-files`: **13 hooks pass, 0 fail**.
- Gitleaks 8.24.3 (official release, re-downloaded after the
  sandbox wiped `/tmp`): **0 leaks** on `530c56b..HEAD` (4 commits).

### Incidents found during this wave

- **Sandbox service restarts mid-run** (several, as in wave 1).
  `/tmp` is wiped on restart — the smoke-test script and the
  gitleaks binary were both lost and re-created in the persistent
  workspace scratch dir. Caches survived (they live in `~/.cache`,
  not `/tmp`).
- **urllib reads time out on `raw.githubusercontent.com` while
  curl works** (4 attempts, `The read operation timed out`), but
  urllib to `datasets-server.huggingface.co` works fine (live
  `/size` + `/rows` probes succeed). The downloader is sound — the
  raw host is the outlier, not the code — so the live smoke test
  was switched to a datasets-server file (fresh + resume,
  hash-verified). Same transient-egress shape as the wave-1
  incident; the downloader's retry discipline covers it.
- **detect-secrets flags the new artifact/record hashes**, as
  designed: the hook failed on the new U7 registry entry and on
  the 4 new seed-record values. Grafted entry-by-entry after
  recomputation (see above); the hook is green on the committed
  tree. The baseline entries are per (filename, value), so the
  cache/artifact/code-version hashes needed one entry under each
  filename that carries them.

### What is NOT verified / NOT done here

- **No new claims.** The claims gate stays **33/33** and the report
  card still leads with worst-slice human FPR = unknown. The
  GhostWriter native-verdict zeros are the same quiet-verdict
  pattern as the U1 seeds, not release-gate FPR evidence.
- **DetectRL-X, M4, M4GT-Bench, DetectRL, PAN 2025**: not this
  worker (later wave-2 workers; PAN is gated on Greg's TIRA
  access). No loader code for them was touched.
- **Full-corpus evaluation**: the measurement is a 500-row strided
  sample, not the 332,224-row split.
- **Per-domain / per-language metrics**: the cache carries domain,
  lang and agent on every row; sliced metrics are U1/wave-2 work.
- **Other Python versions**: measured on 3.12.3 only; CI covers the
  matrix.
- **No push, no release, no tag.** Pushing is the parent's step.
