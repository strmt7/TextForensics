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

## Verification record — Phase 3, datasets wave 2, worker B: DetectRL-X (2026-11-07)

DetectRL-X loader + first preliminary measurement + U1 seed record.
Work is in `main` only, canonical identity
`Stratos <28989754+strmt7@users.noreply.github.com>`; no push, no
release, no tag. Commits `b80097a`…`ff662d1` (3 commits) on top of
`6e57340` (worker A head). M4, M4GT-Bench, DetectRL and PAN 2025
belong to later workers and are deliberately NOT done here.

### What was built

- DetectRL-X spec + mapper in `src/textforensics/datasets.py`:
  licence is the three-way conflict recorded verbatim (see below);
  `DatasetSpec` gains no new fields. The mapper emits one
  normalised row per text field — `human_written_text` → label 0,
  `llm_generated_text` → label 1, both regime `raw` — and, when a
  row carries `llm_refined_text` (Ternary files), a third row with
  `label=None`, regime `mixed-origin` (U4 spine, like the
  OpAI-Bench partials). `source_id` is file + row index (the file
  has no id field); the mapper fails closed without a row index,
  on missing/empty text fields, on unknown lang/model/domain
  values, and on a row whose own `split` field disagrees with the
  split being mapped. Meta carries lang, model, split, domain,
  file.
- Streaming whole-file reader: `iter_detectrl_x_rows` decodes one
  object at a time with `json.JSONDecoder.raw_decode` over a 1 MiB
  rolling buffer (the file is ~879 MB; loading it whole would need
  several GB of RAM) and refuses anything that is not a JSON array
  of objects; `sample_detectrl_x_rows` counts rows per split and
  collects strided samples in a single streaming pass, failing
  closed on an unexpected split value or a short sample.
  `download_detectrl_x` fetches via worker A's shared resumable
  downloader (`download_large_file`, Range resume + retries +
  SHA-256/size verification); `verify_detectrl_x_file` re-checks
  size and SHA-256 before any row is read.
- Measurement: `scripts/measure_datasets.py` SAMPLE_PLAN gains
  detectrl_x (train n=400 strided source rows, total 76,800;
  disjointness vs test n=50 strided, total 48,000). Artifact
  `docs/evidence/runs/EV-20261107-dataset-detectrl-x.json`
  (badge `available`, `preliminary: true`, drops manifest); U7
  registry rebuilt (17 records); report card regenerated.
- U1 seed: `evr-20261107-detectrl-x-builtin-heuristic` appended to
  `docs/validation/registry.json` (5 → 6 records; the existing 5
  records are byte-identical, `created_at_utc` preserved,
  registry_id recomputed). `scripts/seed_validation.py` gains the
  detectrl_x config (language `mul`, script `mul`) and an
  `aggregate_scope` branch (domains from `domain`, generators from
  `model`); `record_from_triples` now takes the script from the
  per-dataset config (default `Latn`, so wave-1/U1 records are
  untouched).
- Baseline grafts: 4 measurement hashes + 4 seed-record hashes,
  each audited by recomputation (raw-file SHA-256 against the HF
  LFS oid, cache/artifact SHA-256s recomputed, record signature
  via `verify_signature`, code_version checked as a real commit,
  registry_id recomputed by `ValidationRegistry`); 113 → 117 →
  121 entries, 0 unexpected drops (multiset check). No full rescan
  was ever run. The public file hash constant
  (`DETECTRL_X_SHA256`) carries a `pragma: allowlist secret`
  comment — it is the HF-published content hash, not a credential.

### Licence (three-way conflict, verified live 2026-11-07)

- GitHub README §License (ATH-MaaS/Marco-LLM, formerly
  AIDC-AI/Marco-LLM): "licensed under the Apache License 2.0.
  Usage is strictly restricted to non-commercial academic research
  purposes." (README badge also says Apache 2.0; repo record
  `license:null`, no LICENSE file.)
- HF card + HF API record: MIT (`license:mit` tag; record last
  modified 2026-07-27).
- ACL 2026 paper, Ethical Considerations: use "strictly restricted
  to noncommercial academic research purposes."
- Reasoning (Beemo precedent): the strictest reading
  (non-commercial academic research only) is satisfiable, and
  under ALL THREE readings TextForensics' intended use —
  non-commercial academic research evaluation, local cache only, no
  redistribution, no commercial use — is permitted. The conflict
  blocks commercial use and redistribution, neither of which we do.
  All three strings are recorded verbatim in the spec; the
  NC-academic-only restriction governs. No redistribution of raw
  text, ever.

### Route + verified row counts (HF tree API + downloaded file, 2026-11-07 — not paper figures)

- HF dataset `WUJUNCHAO/DetectRL-X`, `gated:false`. GitHub mirror
  exists but HF is the route (the repo route would be a ~28 GB
  clone). HF viewer / default load is BROKEN
  (`DatasetGenerationCastError` — perturbation files add a
  `perturbation_info` column; datasets-server `/size` confirms
  `num_rows: 0`); load per-file only, never the dataset default.
- Scope: ONE Binary file, `Binary/binary_general_open.json`
  (878,631,989 bytes; SHA-256 `815be166…`, the HF LFS oid,
  verified from the HF tree API before download
  and re-verified after). The README states the train split is
  identical across all strategy files, so the general file is the
  representative preliminary slice; downloading all 16 Binary
  files (~14.67 GB) for a preliminary slice is not proportionate.
  Ternary files are out of scope for the measurement (the mapper
  supports them if cheap — see above).
- Verified from the downloaded file (single streaming pass):
  **124,800 rows (76,800 train + 48,000 test)**, exactly matching
  the README "Open vs. Heldout" table (2:1 train-test split, 192
  language × model × domain cells). The headline 3,456,000 counts
  overlapping categories — never quoted as a downloadable row
  count. The file is a JSON array of objects with exactly 6 keys
  (`domain`, `human_written_text`, `lang`, `llm_generated_text`,
  `model`, `split`); no id field, no `perturbation_info` column in
  this file. The strided sample landed exactly 100 rows per
  language, so the file is ordered/blocked by language (same shape
  as RAID's blocked train split).

### Sampling (strided, as in wave 1)

Train n=400 strided source rows across 76,800 train rows (→ 800
normalised rows, one per text field); disjointness vs test n=50
strided across 48,000 test rows (→ 100 normalised rows). The
measurement verifies the file's per-split counts against the plan
totals BEFORE any row is mapped or cached and refuses on a
mismatch. Raw file + caches under
`~/.cache/textforensics/datasets/detectrl_x/` (local only, never
committed): `Binary/binary_general_open.json` (878,631,989 bytes,
SHA-256 `815be166…`) and `binary/train.jsonl` (800 rows, SHA-256
`08f23dc3…`) / `binary/test.jsonl` (100 rows).

### Measured numbers (BuiltinHeuristicDetector 0.1.0, Python 3.12.3, preliminary)

| Dataset | Sample | Labels (0 / 1 / None) | AUROC | TPR@1% FPR | TPR@5% FPR | Abstentions |
| --- | --- | --- | --- | --- | --- | --- |
| DetectRL-X | 400 strided train source rows | 400 / 400 / 0 | 0.5972 | 0.005 | 0.0825 | 100/800 |

- DetectRL-X: AUROC 0.5972 — the heuristic separates weakly on
  this multilingual slice (human mean 0.1805 vs machine 0.2078;
  human max 0.4964, machine max 0.4560). TPR@1% FPR is 0.005 and
  TPR@5% FPR is 0.0825. Disjointness vs test (n=50):
  **disjoint, verified, 0 shared**.
- Per language: exactly 100 labelled rows each (50 human + 50
  machine per language: arabic, chinese, english, french, german,
  portuguese, russian, spanish). Abstentions are uneven across
  languages — chinese 28/100, english 22/100, spanish 22/100,
  portuguese 15/100, french 8/100, german 3/100, arabic 2/100,
  russian 0/100 — so the "English-focused detector abstains on
  non-English text" expectation was only partly borne out: English
  itself abstains at 22%. Per-language AUROC/TPR are not reported
  (pooled slice only); per-language counts and abstentions are in
  the artifact. The shortest texts in both classes are 1 word.
- U1 seed record `evr-20261107-detectrl-x-builtin-heuristic`
  (partial / partial, next revalidation 2027-02-05): AUROC 0.5972
  [0.5567, 0.6384], TPR@1% FPR 0.0050 [0.0000, 0.0158], TPR@5% FPR
  0.0825 [0.0215, 0.1469], native FPR 0.0000 [0.0000, 0.0000],
  native TPR 0.0000 [0.0000, 0.0000], abstention 0.1250 [0.1037,
  0.1500] (bootstrap 95% CIs, 1000 resamples, seed 20261106).
  Length (labelled rows): min 1 / median 385 / max 3242 words.
  Domains all 6 (Academic, News, Novel, SEO, Webtext, Wiki);
  generators all 4 (deepseek-v3, gemini-2.5-flash, gpt-4o,
  qwen-max). The native-verdict zeros are the quiet-verdict
  pattern: the highest human score (0.4964) and the highest
  machine score (0.4560) are both far below the detector's 0.68
  `ai_like` bar, so the categorical verdict never fires on this
  slice. A second `build_record` run reproduces the metrics
  exactly (deterministic re-seed from the same cache).

### Measured verification numbers (HEAD `ff662d1`, 2026-11-07, Python 3.12.3)

- Full suite, extras venv: **2576 passed, 0 failed, 86%** coverage
  (13,173 stmts, 1,501 missed, 4,568 branches, 710 partial).
- Full suite, bare core-only venv (`/tmp/tfc-core-venv`,
  recreated after a sandbox restart wiped `/tmp`; fastapi
  confirmed absent): **2464 passed, 0 failed, 112 skipped**.
- `ruff check` + `ruff format --check` clean (179 Python files
  under `src/`, `tests/`, `scripts/`).
- Claims gate: **33/33**; report-card diff clean (regenerated).
- Schemas: **9 OK**.
- `pre-commit run --all-files`: **13 hooks pass, 0 fail**.
- Gitleaks 8.24.3 (binary at `~/workspace/.gw-smoke/gitleaks`):
  **0 leaks** on `6e57340..HEAD` (3 commits).

### Incidents found during this wave

- **urllib cannot sustain the DetectRL-X download through the
  egress proxy, curl can.** The shared resumable downloader
  (`download_large_file`, urllib) failed after 6 attempts with
  "The read operation timed out" — it never got past the headers
  on this host — while curl to the same HF resolve URL pulled
  361 MB in 8 s and the full 878,631,989 bytes in ~5 min (with a
  mid-transfer slowdown to ~2.6 MB/s). The file was fetched with
  curl into the cache (`.part` + rename, mirroring the
  downloader's semantics) and verified by size + SHA-256 against
  the HF LFS oid; the shipped loader still uses
  `download_large_file` as its code path, and
  `download_detectrl_x` returns the verified file without
  re-downloading. Same transient-egress shape as the wave-1
  `raw.githubusercontent.com` incident, but on this host the
  urllib path never recovered — later workers fetching whole
  files (M4/M4GT-Bench) should expect the same and verify by hash.
- **Sandbox service restarts mid-run** (twice, as in wave 1 and
  worker A). `/tmp` is wiped on restart: a counting script and
  the bare core-only venv were both lost and recreated (the
  measurement's single streaming pass does the counting, so no
  separate count was needed; the core venv was rebuilt with
  `TMPDIR=$PWD/.tmp PIP_NO_CACHE_DIR=1`). Caches survived (they
  live in `~/.cache`, not `/tmp`).
- **detect-secrets flags the new artifact/record hashes**, as
  designed: the hook failed on the new U7 registry entry, the 3
  new values in the validation registry, and the public file-hash
  constant in code. Grafted entry-by-entry after recomputation
  (see above); the hook is green on the committed tree. The
  baseline entries are per (filename, value), so the
  cache/artifact/code-version hashes needed one entry under each
  filename that carries them (the seed graft added 3 such
  per-file entries; the new `registry_id` did not trip the
  plugin). The hook re-normalised the baseline after each graft
  (line numbers + within-file sort order); the entry multiset was
  verified unchanged by that normalisation both times.
- **Two edit slips caught by diff review before committing:**
  a `muse.edit` that dropped GhostWriter's `dataset_name` line in
  `seed_validation.py` (reverted immediately; diff empty) and one
  that consumed a GhostWriter test's `def` line (re-added; final
  diff purely additive). No wrong content was ever committed.

### What is NOT verified / NOT done here

- **No new claims.** The claims gate stays **33/33** and the report
  card still leads with worst-slice human FPR = unknown. The
  DetectRL-X native-verdict zeros are the same quiet-verdict
  pattern as the U1 seeds, not release-gate FPR evidence.
- **DetectRL, M4, M4GT-Bench, PAN 2025**: not this worker (later
  wave-2 workers; PAN is gated on Greg's TIRA access). No loader
  code for them was touched.
- **Full-corpus evaluation**: the measurement is a 400-row strided
  sample, not the 76,800-row split.
- **Per-language AUROC/TPR metrics**: the cache carries lang on
  every row and the artifact carries per-language counts and
  abstentions; sliced metrics are U1/wave-2 work.
- **The other 15 Binary files + all Ternary files**: unmeasured.
  The Ternary mapper path (`llm_refined_text` → mixed-origin) is
  code + mocked tests only; no Ternary file was downloaded.
- **Other Python versions**: measured on 3.12.3 only; CI covers the
  matrix.
- **No push, no release, no tag.** Pushing is the parent's step.

## Verification record — Phase 3, datasets wave 2, worker C: DetectRL, M4, M4GT-Bench (licence-blocked loaders) (2026-11-07)

Three licence-blocked loaders, MixSet precedent: specs + mappers
that refuse, mocked tests only. No live rows, no artifacts, no U1
records, no registry changes. Work is in `main` only, canonical
identity `Stratos <28989754+strmt7@users.noreply.github.com>`; no
push, no release, no tag. Commits `3a385f3` (DetectRL), `c09dce5`
(M4), `e5b9177` (M4GT-Bench), plus this docs commit, on top of
`ceca136` (workers A+B head). PAN 2025 is not this worker (gated on
Greg's TIRA access).

### What was built

- Three `DatasetSpec` entries in `src/textforensics/datasets.py`
  (`detectrl`, `m4`, `m4gt_bench`), all with `licence=None` and
  `licence_status="unresolved"`. Each `licence_note` documents
  exactly what was checked (sources, dates, `license:null`, no
  LICENSE file, per-source paper tables where they exist, including
  the NC terms) and what would unblock it (a dataset licence
  statement from the authors). Each spec's `notes` record the
  verified route, file lists, and scope-qualified counts — with
  contradictions stated, never resolved by picking one figure.
  All three have `configs=()` / `splits=()`: no loader splits are
  mapped until a live row is inspected. None of the three has a
  Hugging Face dataset, so `hf_id` holds the GitHub repo slug —
  never pass it to the datasets-server client.
- Three refusing mappers (`_map_detectrl`, `_map_m4`,
  `_map_m4gt_bench`), registered in `_MAPPERS` and reached through
  `map_row`. Each raises `DatasetFetchError` whose message states
  both conditions: the licence is unresolved AND no live row has
  been inspected — refusing to map. M4's schema is documented
  (`data/README.md`: `prompt, human_text, machine_text, model,
  source, source_ID`, one (human, machine) pair per row, label
  implicit, no numeric label column) but still unconfirmed against
  data, so it refuses too; DetectRL's and M4GT-Bench's field names
  are unverified and their docstrings say so.
- Tests in `tests/test_datasets.py` (mocked only, no network): per
  dataset a spec-presence/licence test (key registered,
  `licence=None`, status unresolved, gate raises, note/note
  contents), a licence-gate test (gate raises before any fetch
  attempt — mocked client, `client.rows` never called), and a
  mapper-refusal test (gate fires first via `map_row` with
  `DatasetLicenceError`; the mapper itself, called directly,
  raises `DatasetFetchError` naming both refusal conditions).
- No fetchers were written (deferred, by design): the git-clone /
  Drive-download fetchers cannot be tested without live data and
  the gate would refuse them anyway. The verified route + what the
  fetcher must do are recorded in each spec's notes.

### Licence verdicts (coordinator-verified live 2026-11-07; relied on, not re-researched)

- **DetectRL** (`NLP2CT/DetectRL`): **NO-GO.** GitHub API record
  `"license":null` (parent fork `junchaoIU/DetectRL` also null);
  no LICENSE file (404); no licence statement in the README. The
  FAU Erlangen reprocessed version
  (`philipp-ding/Contamination-in-Generated-Text-Detection-Benchmarks`,
  `cleaned_DetectRL_files/`) is ALSO `"license":null` with no
  LICENSE file — same gate.
- **M4** (`mbzuai-nlp/M4`): **NO-GO.** GitHub API record
  `"license":null`; no LICENSE file; no licence statement in the
  README. Per-source licences exist in paper Table 1 (arXiv HTML
  2305.14902, verified) — Wikipedia CC BY-SA-3.0; Reddit ELI5
  "Huggingface" (not a licence); WikiHow CC-BY-NC-SA; PeerRead
  Apache; arXiv abstract CC0; Arabic-Wikipedia CC BY-SA-3.0; True
  & Fake News MIT; Baike/Web QA MIT; id_newspapers_2018 CC
  BY-NC-SA-4.0; RuATD Apache 2.0; Urdu-news CC BY 4.0 — two
  sources are NC. Per-source licences do not add up to a dataset
  licence.
- **M4GT-Bench** (`mbzuai-nlp/M4GT-Bench`): **NO-GO.** GitHub API
  record `"license":null`; no LICENSE file; no licence statement
  in the README. Per-source licences exist in paper Table 2
  (arXiv HTML 2402.11175v2, verified) — Arabic-Wikipedia CC
  BY-SA-3.0; True & Fake News (Bulgarian) MIT; Baike/Web QA
  (Chinese) MIT; id_newspapers_2018 CC BY-NC-SA-4.0; RuATD Apache
  2.0; Urdu-news CC BY 4.0; News (Arabic) Apache 2.0; CHANGE-it
  News (Italian) CC BY-NC-SA 4.0; News (German) CC BY-NC-SA-4.0;
  Wikipedia (German) CC BY-SA-3.0 — three sources are NC.
  Per-source licences do not add up to a dataset licence.

### Routes and counts as recorded (verified, for the record — DO NOT clone/download for data)

- **DetectRL**: `git clone https://github.com/NLP2CT/DetectRL.git`
  (271,708 KB). Human data in `Benchmark/Original_Dataset/` (4 ×
  2,800 JSONs: arxiv, writing_prompt, xsum, yelp_review; 11,200
  human texts). Generated data in `Benchmark/Benchmark_Data/` (11
  subdirs). Task splits in `Benchmark/Tasks/` (Task1–4; Task1 ==
  Task2 content). Paper count 235,200 (100,800 H + 134,400 LGT)
  is a paper figure only; in-repo file row counts NOT verified.
  Labels implicit in file/directory (task × domain × LLM ×
  attack); field names inside the benchmark JSONs NOT verified.
  Traps recorded in the spec notes: `load_dataset.sh` only runs
  the four `get_*_data.py` samplers against LOCAL `*_all.json`
  files not in the repo (downloads nothing);
  `data_generation.sh` regenerates via paid LLM APIs (cannot
  re-run without keys); `benchmark_construction.sh` does NOT exist
  at the repo root (README stale) — the construction script is
  `Data_Generation/benchmark construction.py` (space in the
  filename). FAU shortcut finding recorded: 98.5% of Claude-LLM
  data shows simple patterns — do not use the original as a clean
  training set without the cleansing.
- **M4**: `git clone https://github.com/mbzuai-nlp/M4.git`;
  `data/` has 38 `.jsonl` files + README.md (1,005,995,293 B
  total, ~1.006 GB), naming `<DOMAIN>_<MODEL>.jsonl`
  (`russian_chatGPT.jsonl` 74,318,020 B largest). NO
  `*_human.jsonl` files exist despite `data/README.md`
  documenting that naming scheme — human text is embedded
  per-row. Counts, contradiction stated not resolved, quote none
  as the size: paper Table 1 total 147,895 (35,798 H + 112,097
  M); secondary figures 122K and 245K BOTH contradict the paper's
  own table. Per-file row counts NOT verified. The paper lists
  14,344 GPT-4 generations but NO `*gpt4*` file exists in
  `data/`; `flant5` only for arXiv/Reddit, `llama` only for
  PeerRead. No train/test split defined; authors' metrics are
  accuracy/precision/recall/F1.
- **M4GT-Bench**: Google Drive folder
  `https://drive.google.com/drive/folders/1xC-n5hHiXmaCLmA0q3p8Cbyd7Dk0dpDE?usp=sharing`
  (verbatim from the README, public link):
  `SubtaskA_multilingual.jsonl` 693.4 MB; `SubtaskA.jsonl` 480.5
  MB; `SubtaskB.jsonl` 332.3 MB; `subtaskC_test.jsonl` 73.8 MB;
  `subtaskC_train_dev.jsonl` 138.4 MB (≈1.72 GB total). Drive
  offers no row counts — Drive row counts NOT verifiable without
  downloading. Counts, scope-qualified only, from the paper's own
  tables: Task 1 EN 138,465 (65,177 H + 73,288 M); + multilingual
  65,100 + GPT-4 14,344 = 217,909 (≈217k); Task 3 adds 31,893;
  all-in with OUTFOX ≈281k. Tasks: (1) binary mono/multilingual;
  (2) multi-way generator identification; (3) mixed human-machine
  change-point detection (human share 0–50% of words) — the U4
  spine. Authors' metrics: Tasks 1/2 F1/precision/recall per
  generator + F1-macro and accuracy; Task 3 MAE on the boundary
  index. Report per-task, never pooled.

### Known limitation recorded for future fetchers

The shared urllib downloader (`download_large_file`) could not
sustain an ~879 MB DetectRL-X download (timed out after 6
attempts, never past headers) while curl fetched the full file in
~5 min with the SHA-256 verified; the shipped loader still uses
`download_large_file`. Recorded in the M4 and M4GT-Bench spec
notes: a future ~1.006 GB M4 fetch / ~1.72 GB Drive fetch will
likely need curl or a downloader fix. The downloader was NOT fixed
in this task; fetchers are deferred by the brief.

### What is NOT verified / NOT done here

- **No new claims.** The claims gate stays **33/33**; no registry
  was touched (U7 registry still 17 records, validation registry
  still 6 records). No run artifacts, no measurements, no U1
  records for any of the three datasets — there are no live rows
  to measure.
- **No dataset data anywhere.** Nothing was cloned or downloaded
  for data (no DetectRL clone, no M4 clone, no Drive download).
  No cache files, no raw text in the repo, tests, or docs.
- **No fetchers written.** The git-clone / Drive-download fetchers
  are deferred: untestable without live data, and the licence
  gate would refuse them anyway. A future fetcher must follow the
  route recorded in each spec's notes.
- **No baseline graft.** No new hashes were introduced (no
  artifacts, no records), so nothing tripped the secrets hooks;
  the `.secrets.baseline` is untouched (still 121 entries).
- **No downloader fix.** The `download_large_file` large-file
  limitation is recorded, not fixed.
- **PAN 2025**: not this worker (gated on Greg's TIRA access).
- **Other Python versions**: verified on 3.12.3 only; CI covers the
  matrix.
- **No push, no release, no tag.** Pushing is the parent's step.

## Verification record — Phase 3, U2 sealed replayable text-free case file (2026-11-07)

Work is in `main` only, canonical identity
`Stratos <28989754+strmt7@users.noreply.github.com>`; no push, no
release, no tag. Commits on top of `5ab3c45` (datasets wave 2 head):
`08d8e84` (Ed25519 + DSSE), `6af6f5b` (sealing-key files + case-body
signing), `8546bd9` (case-file v3 model), `acad2b4` (golden case file
regenerated as v3; property tests assert v3), `8eb4163` (RFC 3161
timestamping), `58f7978` (standalone verifier), `be47d7b` (MPL sealed
bundle packer), `cb9f0aa` (CLI: case verify/export/keygen), plus the
docs commit (this section, `docs/SEALING_KEYS.md`, README,
ARCHITECTURE, REVAMP_SPEC).

### Deliberate deviation

The brief said schema `textforensics.case-file/v2`, but the repo's
case-file schema was already v2, so the U2 format is **v3** (schemas
are public contracts; field meaning is never silently changed).
v1 and v2 case files still verify; v3 is what the system seals.

### What was built

- **Crypto (pure stdlib, no new core dependency).**
  `src/textforensics/ed25519.py` (RFC 8032 §5.1, extended
  coordinates; `verify` never raises, returns `False` on malformed
  input) and `src/textforensics/dsse.py` (DSSEv1 PAE, exactly one
  signature, canonical base64 round-trip, keyid = public-key
  fingerprint). Verified against the RFC 8032 §7.1 test vectors
  (fetched from rfc-editor.org 2026-11-07) and cross-checked both
  directions against `cryptography` 42.0.8 on 5 random messages.
  `src/textforensics/sealing.py`: `textforensics.sealing-key/v1`
  key files (atomic write, mode 0600, refuses overwrite, refuses to
  load a world-readable file on POSIX), `case_signing_payload`,
  `sign_case_body` / `verify_case_signature`.
- **Case-file v3** (`src/textforensics/casefile.py`,
  `src/textforensics/schemas/case-file.schema.json`): `input`
  (content hash only), `detector_observations`, `validation_refs`
  (into the U1 registry via `registry.matching`; `registry_sha256`
  == `registry_id` by construction), `limitations` (plain language +
  counterfactuals, names the nearest FPR record or honestly states
  none), `process` (D1–D10 checklist, "template, not legal advice";
  consistency re-derived at verification only — sealing an
  unsupported `satisfied` item succeeds, verification reports it),
  `custody` (hash chain, genesis prev-hash `"0"*64`), `seal`
  (T1 hash always; T2 Ed25519/DSSE object when signed; T3 timestamp
  record when requested), `gaps` (every absent item declared).
  `verify.py` accepts v3 Trust Maps (`stale` a distinct state; the
  U1 follow-up is fixed here, not deferred). The seal-manifest
  circularity is resolved the MPL way: the per-file manifest +
  bundle digest live in the bundle's `manifest.json` plus a companion
  seal record, never inside the case JSON.
- **T3 timestamping** (`src/textforensics/timestamp.py`, stdlib-only):
  DER encoder/parser, TimeStampReq builder, TSA client (1 MiB
  response cap), CMS token verification (imprint, nonce echo,
  signedAttrs messageDigest, RSA PKCS#1 v1.5 + ECDSA P-256/P-384
  against the embedded signer certificate). `qualified` is always
  `"unknown"` offline; tokens are labelled "RFC 3161 timestamp
  (non-qualified)". OIDs verified against the RFC 3161 text fetched
  2026-11-07.
- **Standalone verifier** (`src/textforensics/_standalone_verify.py`,
  stdlib-only, no package imports): MPL container checks (EOCD
  pre-parse, caps enforced in order before reads, sorted STORED
  normalised entries), seal checks (comment digest, manifest
  digests, case hash, v3 sections, custody chain, checklist
  re-derivation), DSSE signature, RFC 3161 token (imprint ==
  SHA-256 of `case.json` bytes). JSON report
  (`textforensics.verification-report/v1`) + one-line scope
  statement + both honest limits in the copy. Exit codes 0/1/2.
  Replay reported `unavailable` (no detectors standalone).
- **Sealed bundle** (`src/textforensics/sealed_bundle.py`):
  deterministic ZIP (canonical JSON, sorted ZIP_STORED, normalised
  ZipInfo, comment `mpl-bundle-sha256:<manifest SHA-256>`) carrying
  `case.json`, `verify.py`, an optional token and an MPL manifest
  (`textforensics.sealed-bundle-manifest/v1`, 10th schema). The
  signer record is part of the signed bytes; only the envelope is
  added afterwards. Packing refuses non-v3 cases, cases that do not
  verify, a seed without a signer, and a token whose imprint does
  not match the case-file bytes. `verify_sealed_bundle` replays only
  when the seal passes (any non-zero standalone exit gates replay
  as `unavailable` / `seal_failed`); the seal-record cross-check
  fails closed on malformed records or manifests instead of raising.
  The older `bundle.py` packer (DEFLATED, 2020 timestamp, its own
  format) was deliberately left alone.
- **CLI**: `case verify` accepts a sealed `.zip` or a bare case file
  (ZIP magic), with `--expect-digest`, `--text`/`--text-file`,
  `--public-key` (sealing-key file, public-key file, hex file or
  bare hex), `--timestamp-token` (bare files only); `case export`
  gains `--seal`, `--signing-key` (T2-signs the case AND the
  manifest with one key) and `--timestamp-url` (a token that cannot
  be obtained fails the seal, never silently downgrades); new `case
  keygen` (mode 0600, refuses overwrite, optional `--public-out`).
  Exit codes follow MPL: 0 verified, 1 seal failed, 2 checks could
  not run. The `verify` command keeps its own contract (failed ->
  2); three tests that asserted the old `case verify` code 2 now
  assert 1.
- **Docs**: new `docs/SEALING_KEYS.md` (generation, storage 0600,
  rotation, publication, loss, compromise + revocation procedure —
  no central revocation list in v1.0, by design decision);
  README "Sealed case files" section; ARCHITECTURE §1.7;
  REVAMP_SPEC §9 (v3 + sealed bundle).

### Real defects found and fixed during the work

- `_dsse_verify` checked the signature over the envelope's payload
  but never confirmed the payload IS the manifest — a valid
  signature over other bytes would have "verified". Now returns the
  payload and the caller compares it against the canonical manifest
  with the signature field null (regression test
  `test_signature_over_other_payload_fails`).
- `pack_sealed_bundle` passed the hex case digest to
  `verify_timestamp_token`, which expects raw digest bytes — every
  token was refused with `message_imprint_mismatch`. Fixed to pass
  the raw bytes.
- `test_agrees_with_package_implementation` tampered a signature by
  replacing its last byte with zero — a no-op whenever S's top byte
  is already zero, which made the test flaky (~1 in 6 runs). The
  tamper now flips a bit inside S (byte 40).
- A bundle whose digest/manifest/case/checklist check failed still
  printed the positive "integrity since sealing only" scope line.
  The scope statement now reads `seal: not verified (<failed check
  ids> failed)` when any check failed.
- The signer record was first placed inside the DSSE envelope, which
  the verifier's exact-field-set check rejects. It now lives in the
  manifest context and is part of the signed bytes.
- The initial Ed25519 implementation used the a=+1 curve addition
  formula; `[l]B` was not the identity, which exposed it. The a=−1
  form (RFC 8032 §5.1.4) is used, with a comment.

### Verification (measured, this tree)

- Extras suite: **2713 passed / 0 failed** on the final tree. The
  run at `cb9f0aa` showed 2712 passed / 1 failed
  (`test_memory_check` only; host at 96% memory when it ran —
  7614/7934 MB used, 320 MB available); after the VM restart the
  same test passes with the host unconstrained, and the final run
  is clean.
- Core-only suite (bare venv, fastapi absent, recreated after a
  /tmp clear): **2601 passed / 112 skipped / 0 failed**.
- Claims gate **33/33** (no new claims, no registry touched).
  Schemas **10 OK**. `pre-commit run --all-files` **13/13**.
- Gitleaks 8.24.3 over `5ab3c45..HEAD`: **0 leaks** (8 commits).
- Bundle determinism: two packs of one sealed case are
  byte-identical (SHA-256
  `c2b6c2f58128ad04be4d5189172bf66ab738315745678c29f52e812e5aba2682`,
  80,944 bytes).
- Live CLI end-to-end (temp dir, extras venv): keygen (mode 0600)
  -> export `--seal --signing-key` -> verify without key exits 2,
  with `--public-key` exits 0, `--expect-digest` match exits 0,
  mismatch exits 1, `--text-file` replay exits 0, tampered bundle
  exits 1, bare case without key exits 2, with key exits 0,
  `--timestamp-token` on a bundle is rejected (exit 3).
- `test_pack_is_deterministic`, `test_seal_is_deterministic`
  (deterministic mode), and the 5-run determinism re-check from
  earlier waves all hold; the v3 seal carries the seal time in its
  custody genesis entry, so ordinary (non-deterministic) seals of
  one bundle differ by design.

### What is NOT verified / NOT done here

- **Live-TSA interop: NOT achieved from this VM.** `request_timestamp`
  against `https://freetsa.org/tsr` and `https://timestamp.digicert.com`
  both hang via urllib (30 s each); curl POST to freetsa `/tsr` also
  hangs (HTTP 000, 30 s and 60 s attempts) while the freetsa homepage
  GET returns 302 in 0.6 s — the sandbox egress reaches those hosts
  but the `/tsr` POST path hangs. Request encoding is structurally
  verified (parse-back test) and token verification is verified
  against real CMS tokens built with the production encoder; the
  live round-trip must be re-attempted from an unrestricted host
  before it is claimed. No network test in the suite (CI stays
  offline).
- **No new claims.** The claims gate stays **33/33**; the report
  card still leads with worst-slice human FPR = unknown.
- **No push, no release, no tag.** Pushing is the parent's step.
- **Other Python versions**: verified on 3.12.3 only; CI covers the
  matrix.
- **No downloader fix.** The urllib large-file limitation from wave
  2 is untouched (release gate).
- **No hardware keys / managed PKI / revocation infrastructure.**
  Deferred by design decision (Phase 3 research §13, decision 5);
  `docs/SEALING_KEYS.md` documents the v1.0 procedure instead.

## Verification record — Phase 3, U3 drift observatory (2026-11-07)

Work is in `main` only, canonical identity
`Stratos <28989754+strmt7@users.noreply.github.com>`; no push, no
release, no tag. Commits on top of `ca3af3d` (parent's Python 3.15
base64 fix): `55b0e3d` (probe-run engine: per-run metrics,
persistence-gated tiers, demotion hook), `99de3c6` (Trust Map
longitudinal threading), `3f93f1c` (probe-run orchestration +
score series + Tier-1 flip-direction fix), `4565115` (CLI:
`tf drift run` / `tf drift status`), plus the docs/cadence commit
(this section, `docs/OBSERVATORY.md`,
`.github/workflows/observatory.yml`, REVAMP_SPEC touch).

### Deliberate deviations

- The brief said the corpus half and the observatory half land
  together; they did not. The frozen probe corpus v1.0.0
  (`probe_corpus.py`, `probe_metrics.py`,
  `scripts/build_probe_corpus.py`) lives on branch `u3-corpus` in
  the worktree `~/workspace/TextForensics-u3` and merges separately
  through the parent. This half never touched it. Until the merge,
  `tf drift run` exits 2 with a clear message, and the U3 tests
  drive the machinery through injected test doubles (closed-form
  primitives + a fake corpus module).
- The corpus has 8 slices, not the 9 prescribed: the
  `human-non-native` / ESL slice is cut in v1.0.0 — no licensed
  source was found (corpus half's decision, recorded in its
  manifest notes).
- The Trust Map has no `watch` state (exactly 5 states in v3), so a
  Tier-2 watch is carried in the dimension's `observed` dict
  (`u3_watch`) + a limitations line, never as a new state.
- Demotion is per-detector in v1.0, not per-slice (U1 records are
  regime-coarse).

### What was built

- **Engine** (`src/textforensics/probe_runs.py`, ~1,900 lines).
  Pre-registered thresholds (PSI 0.1/0.2, KS effect 0.10 + Holm
  p < 0.05, flip Tier 2 > 1% / Tier 1 > 5% human→AI on a human
  slice, ECE increase > 0.05, version-change stale after 7 days,
  FPR cap 0.05, 2 clean full runs for temporal support); §7.6
  metrics 1–7 per slice + overall (KS/PSI, directional flips with
  Wilson CI, ECE/Brier, verdict-based human FPR, attacked-slice
  TPR@1% FPR, conformal coverage, provider metadata diff); three
  tiers with the iron rules (drift statistic alone never demotes;
  one run never demotes; no alert silently changes a verdict);
  demotion hook into the existing `validation.py`
  `limits.demoted_by` → `stale` (fail-closed, re-signed, registry
  reloaded to verify); run manifests
  (`textforensics.probe-run/v1`) with a per-item score series
  (numbers + IDs only, never raw text) so the next run recomputes
  KS/PSI/flips without re-scoring.
- **Trust Map threading** (`validation.py`): `derive_trust_map(...,
  longitudinal=...)`; `temporal_version_stability` may exceed
  `partial` only with ≥ 2 consecutive clean full runs at the same
  detector version (run IDs + corpus fingerprint cited in
  `observed`); watch surfaced, never a state; fail-closed on wrong
  detector/version, bad fingerprint, or run-id count mismatch;
  demotion still wins over longitudinal support.
- **Orchestration** (`perform_probe_run`): scope-filters the
  corpus, scores via `DriftObservatory.take_snapshot`, loads the
  holdback labels only after scoring (callable loader — enforced
  in code, asserted by test), resolves the baseline (only
  full-scope runs can be one), evaluates tiers, saves the run,
  applies/clears demotions. Dry-run computes without writing.
- **CLI** (`tf drift run` / `tf drift status`): exits 0 completed,
  1 with `--fail-on-tier1` on Tier 1, 2 when the corpus module is
  absent, 3 on input errors. Corpus verified against the manifest
  before scoring; fail-closed on mismatch.
- **Cadence** (`.github/workflows/observatory.yml`, actionlint
  clean): monthly attacked + current-generator slices, quarterly
  full corpus, `workflow_dispatch` with scope input; machinery
  smoke (U3 tests + CLI smoke) always runs in CI; the scheduled
  job exits cleanly with a notice when the corpus cache is absent
  (CI cannot hold NC-licensed corpus text) — real runs execute on
  the corpus host.
- **Docs** (`docs/OBSERVATORY.md`): operator guide — concepts,
  the 7 metrics, threshold table, tiers + iron rules,
  demotion/watch semantics, Trust Map threading, cadence, CLI
  reference, manifest fields, honest limits.

### Real defects found and fixed by this work

- **Tier-1 flip rule demoted on recovery.** It fired on any flip
  direction > 5%, so the clean re-run recovering from a demotion
  re-demoted the detector and the demotion could never clear.
  Found by the end-to-end demotion test. Fixed: Tier 1 now
  requires > 5% human→AI flips on a human slice (an FPR event);
  recovery flips are Tier 2 at most, overall flips Tier 2 only.
  Two regression tests added.
- **Score-shift status lied on KS-only breaches.** The status was
  PSI-only while breaches also fire on KS, so a KS 1.0 / Holm
  p 0.0 slice showed status `stable`. Fixed: one helper
  (`_score_shift_status`) computes the status from the Tier-3 rule
  (PSI or KS with Holm-adjusted p), recomputed after the Holm
  fill; regression test added.
- **Partial-scope runs could become the baseline.**
  `resolve_baseline` did not filter by scope. Fixed in both
  `resolve_baseline` and `perform_probe_run`; regression test
  added.
- **Run manifests carried no baseline/previous records.**
  `perform_probe_run` originally passed `None` for both (the
  manifest holds metrics, not snapshot records), so drift metrics
  could never fire across runs. Fixed by storing the per-item
  score series in the manifest and rebuilding records from it
  (schema extended with optional `score_series`; no field meaning
  changed).

### Measured numbers (synthetic drift-injection demo, 470 items)

- Baseline run (stub detector, clean): 0 alerts, overall n 470,
  worst-slice FPR 0.0 (human-native FPR 0.0, CI [0.0, 0.03102],
  n_human 120).
- Second run, all scores shifted +0.25: 8 Tier-3 alerts, 8
  breaches. Human-native: KS 1.0, Holm-adjusted p 0.0, status
  `breach` (KS reason). PSI reads 0.0 here — a test-double
  artifact (the stub PSI uses quantile bins over a point-mass
  baseline, which collapse to one bin); the real
  `probe_metrics.psi` uses equal-width bins over the combined
  range and would also breach. The KS signal is real and is what
  the Tier-3 alert fired on.
- Third run, same shift: all alerts Tier 2, consecutive_runs 2.
- End-to-end demotion demo (stub detector flipping all human
  items to AI): Tier-1 FPR alert on the claimable human-native
  slice (FPR 1.0), demotion applied, the U1 record's effective
  status `stale`; the next clean full run clears the demotion.
  Labels load only after all 470 items are scored (asserted by
  test). No raw text appears in any run manifest.

### Full verification (this branch, before commit)

- Extras suite: **2789 passed, 1 failed** — the single failure is
  the known `test_memory_check` host flake (passes in isolation;
  host at 588 MB available during the run).
- Core-only suite (bare venv, fastapi absent): **2672 passed, 112
  skipped, 6 failed** — 5 `SchemaCLITests` failures are a PATH
  artifact (the tests shell out to the `textforensics` console
  script, which was not on PATH for that run; all 5 pass with the
  venv bin on PATH) plus the same `test_memory_check` flake. A
  re-run with the schema tests deselected gives 2672 passed, 112
  skipped, 1 failed (the same flake).
- Ruff check + format clean (182 files); `pre-commit run
  --all-files` green; claims gate **33/33**; schemas **11 OK**;
  gitleaks 8.24.3 over `ca3af3d..HEAD`: **0 leaks** (4 commits);
  `.github/workflows/observatory.yml` passes actionlint.

### What is NOT verified / NOT done here

- **Corpus half not merged.** No live probe run against the real
  frozen corpus has happened from this branch; the numbers above
  are synthetic-fixture demonstrations, not corpus measurements.
  A contract test against the real `probe_metrics` module must run
  after the corpus merge (the U3 tests use a closed-form stub).
- **Live-TSA interop, downloader fix, atheris, mutation:** untouched
  (release gate, as before).
- **No new claims.** The claims gate stays **33/33**; the report
  card still leads with worst-slice human FPR = unknown.
- **No push, no release, no tag.** Pushing is the parent's step.
- **Other Python versions**: verified on 3.12.3 only; CI covers the
  matrix.
- **Overall score-shift status reflects PSI only**: the overall KS
  is not part of the Holm family (per-slice only, §7.5 rule 4), so
  no overall KS breach is ever recorded and the overall status
  cannot say `breach` on KS. Consistent with the breach list, but
  the pooled KS value is visible in the manifest for inspection.
- **Per-slice demotion, MMD, conformal coverage:** unavailable in
  v1.0 by design (declared as gaps in every manifest).

## Verification record — Phase 3, U4 mixed-origin / co-authorship report (2026-11-07)

U4 builds the mixed-origin report (§8.6 output shape): verdict,
HART collaboration type, degree-of-change tiers, operation
hypothesis, per-segment evidence, the verbatim
non-monotonicity warning, and the idea-provenance note. Six commits
on top of `87dde38` (U3), all canonical identity, none pushed
(pushing is the parent's step):

- `6efc084` (f) canary tests proving no raw text appears in
  adversarial findings — the brief's original §(f) claim of a
  raw-text leak was wrong; `63eac08` holds, `adversarial.py`
  untouched.
- `9e70c8c` OpAI-Bench mapper preserves segment-level ground truth
  (`sentences`, `sentence_labels`, `ai_spans_char`), fail-closed.
- `94f822e` report builder `mixed_origin.py` + schema
  `textforensics.mixed-origin-report/v1` (12th schema).
- `720cd6a` `tf mixed-origin` CLI command.
- `e0f60ae` segment validation run tooling (5a, code only).
- `c663a23` segment validation run + U1 segment record (5b).

### Segment validation run (the §12(g) evidence)

Script `scripts/measure_segments.py --run-date 20261107`, run at
committed HEAD `e0f60ae` (code_version in the artifact is exactly
that commit; a pre-commit trial run reproduced byte-identical
metrics). OpAI-Bench, Apache-2.0, licence verified before the
fetch. Strided train n=500 of 196,029 + dev n=50 replication;
disjoint by document (0 shared docs, verified); one 1-word
segment shared between train and dev (a valediction, word counts
only — no dataset text in the repo). Ratio/label agreement 494/500
(6 rows disagree, max |diff| 0.032).

Artifact: `docs/evidence/runs/EV-20261107-dataset-opai-bench-segments.json`
(SHA-256 `5ecc111efa6b…`, U7 registry 17 → 18 records, badge
`available`, `preliminary: true`, 9 drops). Segment record
`evr-20261107-opai-bench-builtin-heuristic` (validation registry
6 → 7 records, status `partial`, editing_regime `LLM-edited` so it
never auto-matches a Trust Map dimension; slice_id
`opai_bench_segments-builtin-heuristic`).

Detector: builtin-heuristic 0.1.0 at the DECLARED operating point
(score ≥0.68 ai_like, ≤0.32 human_like, segments under 20 words
abstain; no threshold fitted). 1000 bootstrap resamples, seed
20261106. Pooled train, 10,053 segments (4,785 human / 5,268 AI):

- AUROC **0.4772 [0.4665, 0.4879]** — below chance (CI entirely
  below 0.5). Dev replication, 922 segments: AUROC 0.4743 [0.4391,
  0.512]. Mean score human 0.3404 vs machine 0.3342 (inverted).
- TPR@1%FPR 0.0015, TPR@5%FPR 0.0514; native FPR 0.0, native TPR
  0.0; coverage 0.445, abstention 0.555.
- Precision/F1 **undefined (null)**: no segment scores ≥0.68, so
  no AI prediction exists (tp=0, fp=0, fn=5,268); recall 0.0.
- By version: v4 highest AUROC 0.5672, v5 lowest 0.4191 —
  non-monotonic across the ladder; v0 (all-human) and v8 (all-AI)
  carry null AUROC by construction.
- By operation: compress 0.5672 best, expand 0.4191 worst;
  paraphrase 0.4691, polish 0.4679, style 0.4833.
- By length: segments under 20 words are 4,588/10,053 (46%) and
  never verdicted (coverage 0.0); 20+ word segments sit at chance
  (AUROC 0.5037 / 0.5095).
- By domain: news 0.4931 best, essays 0.458 worst; all at or
  below chance.
- Operation-hypothesis accuracy **0.0 (0/444)**: every doc
  predicted `unknown` (389) or `humanise` (55, from adversarial
  artifacts). With coverage, 388/444 mixed docs are verdicted
  `human` and 56 withheld.
- Segmentation fidelity: the builder's `SENTENCE_RE` split
  reproduces 8,443/10,053 dataset sentences (84.0%) and 204/500
  docs exactly (40.8%).

Headline, stated plainly: the builtin heuristic cannot separate AI
from human sentences, and the v1.0 report calls most mixed-origin
text human. No threshold was lowered and no metric relabelled to
hide this (AGENTS.md rules 4, 17, 18). Every segment claim stays
`partial` / `unknown`; the 8-condition bar for `supported` is not
met in any cell.

### What else was verified during the run

- The ratio cross-check the mapper asserted (mean of
  `sentence_labels` == `ai_sentence_ratio`) is FALSE on the full
  sample — 6/500 rows disagree. The check was removed from the
  mapper; the run measures the agreement instead of asserting it.
- `measure_datasets.auroc` was O(n²) per call: the segment
  bootstrap (1000 resamples × ~5,000 segments) would have taken
  hours. Rewritten rank-based (O(n log n)), verified identical to
  the pairwise form on tied data including a 5,000-item sample
  (same value 0.4974, 0.21 s → 0.0042 s per call).
- The engine verdict's reliability gate (`length_reliability` <
  0.28) would abstain on ALL short text by construction, so the
  segment verdict is defined by the declared operating point, not
  by `detect()` — recorded in the helper docstring, the record's
  limits, and the U4 report.
- The document cache was not overwritten: the U1 document record's
  cited `train.jsonl` SHA-256 still matches the file.
- Covered-path CLI check (live): a plain human text with
  `--language en --domain news` verdicts `human`, exit 0, with
  `validation_slice_covered: true`; `--domain legal` (uncovered)
  withholds. No raw text in the CLI output.

### Full verification (commits 1–4 + 5a, then 5b, before commit)

- Extras suite: **2851 passed, 0 failed** (152.4 s). Core-only
  suite (bare venv, fastapi absent): **2739 passed, 0 failed, 112
  skipped** (144.0 s). The `test_memory_check` host flake did not
  fire on either run.
- Ruff check + format clean; `pre-commit run --all-files`
  **13/13**; claims gate **33/33**; schemas **12 OK**;
  gitleaks 8.24.3 over `87dde38..HEAD`: **0 leaks** (6 commits),
  and 0 leaks over the staged 5b content before commit.
- `.secrets.baseline` 574 → 581 (+7 audited entries, 0 dropped,
  no duplicates): the 4 distinct hashes (segment-cache SHA-256,
  artifact SHA-256, commit SHA `e0f60ae`, record signature) across
  7 (file, line) locations. Audit script:
  `hidden_files/graft_baseline_u4_segments.py`. One graft-script
  bug caught during the work: re-running it duplicated entries —
  the script now refuses to duplicate and the baseline was restored
  from git and grafted once.
- The segment record loads with signature verification
  (`load_validation_registry` passes; signature recomputed ==
  stored), status `partial`, contamination `no`.

### What is NOT verified / NOT done here

- **No new claims.** The claims gate stays **33/33**; the report
  card still leads with worst-slice human FPR = unknown (the
  segment record's native FPR 0.0 is a quiet verdict — nothing
  fires — not evidence of separation).
- **No push, no release, no tag.** Pushing is the parent's step.
- **Segment-level calibration:** the document operating point
  (0.68/0.32) does not transfer to sentences — the AI side never
  fires. A segment-level operating point needs a disjoint
  calibration set (v1.1 work, not fitted on this sample).
- **ai→human direction:** no data source covers it; those cells
  are `unknown`. M4GT-Bench Task 3 (the real spine) is still
  licence-blocked; MixSet is licence-blocked and too small.
- **Population slicing:** no population-labelled source exists;
  the human-slice segment FPR is pooled by domain only.
- **Live-TSA interop, downloader fix, atheris, mutation:**
  untouched (release gate, as before).
- **Other Python versions**: verified on 3.12.3 only; CI covers
  the matrix.

## Verification record — Phase 4 Dependabot recovery (2026-11-07)

Recovery of the 10 Dependabot PRs #25–#34 closed unmerged by the
2026-11-06 history force-push, per
`hidden_files/phase4-dependabot-plan.md` (plan baseline `5ab3c45`;
execution baseline remote main `f1f391c`, U4 head). Full per-item
record — patches, SHA re-verifications, gate numbers, CI run ids —
is `hidden_files/phase4-dependabot-recovery.md`. Every plan claim
about "current version in main" was re-verified against the
execution baseline before acting; discrepancies are recorded there
and below.

**Method correction vs the plan (§4.1 path A):** `git rebase
origin/main` does NOT work for the surviving Dependabot branches.
Each is a single Dependabot commit on top of the OLD pre-rewrite
history and shares NO commits with rewritten main, so a rebase
tries to replay the entire old history. The correct equivalent is
**cherry-pick of the single Dependabot tip commit** onto a fresh
branch from `origin/main`, which preserves Dependabot authorship
(author `dependabot[bot]`, committer Stratos canonical). A plain
rebase DOES work for the recovery branches, which share history
with main.

### Recovered items (all 10 on main)

- **#30 pytest-timeout — no-op.** `pytest-timeout>=2.4.0,<3`
  already in both `pyproject.toml` and
  `requirements-pinned.txt`. Remote branch deleted. No commit.
- **#34 pytest-cov `<6` → `<8` — PR #35** (branch `recover/34`,
  cherry-picked tip `ca367fc` → `fe41839`, rebased onto `f7a80b3`
  as `b23fa1c`). Diff exactly 2 lines. CI on the rebased head:
  Core 3.11–3.15 ALL PASS on both runs, Dependency review PASS
  (7s), Pip Audit PASS (11s), claims gate PASS. Merged to
  `ba67a09`.
- **#25 attest-build-provenance v1 → v4 — PR #38** (cherry-picked
  tip `0d0d440` → `1c8627e`). SHA re-verified via tags API:
  v4.2.2 = `4d101475d8b20a2381f78447822ac1eab6504dd8`. Diff exactly
  3 lines: `container.yml` `@v1` → `@v4`, `release.yml` SHA pin
  + comment `# v1.4.4 (v1)` → `# v4.2.2`, release-notes echo
  `@v1` → `@v4`. Merged to `a809af5`.
- **#29 build-push-action v6 → v7 — PR #39** (cherry-picked tip
  `5657645` → `b2ae7e5`). Diff exactly 1 line. The Container
  workflow does not run on PRs; it ran on the merge commit and
  completed SUCCESS, proving the v7 step on main. Merged to
  `9a9fd8a`.
- **#27 cryptography `<43` → `<51` — `ac030c7`.** PyPI latest
  50.0.2, inside `<51`. Pinned file updated too (the old PR did
  not touch it). CI on the pushed head (run 42383119991): Core
  3.11–3.15 ALL SUCCESS, claims gate SUCCESS. Only failure:
  atheris pinned-install (known release-gate item).
- **#32 rich `<14` → `<16` — `4137c1b`.** Plan discrepancy: the
  plan says rich occurs twice in pyproject (`cli-rich` +
  `cli-typer`); no `cli-typer` extra exists — it was deleted in
  Phase 2 wave (b) before the plan was written. One occurrence
  only. PyPI latest 15.0.0, inside `<16`. CI on the pushed head
  (run 42383721159): Core ALL SUCCESS, claims gate SUCCESS.
  Only failure: atheris.
- **#33 pytest `<9` → `<10` — `868306d`, plus required
  follow-on `1b13129`.** PyPI latest 9.2.0, inside `<10`. The
  pushed head `868306d` was RED on all five Core jobs (CI run
  42384073692) — the ONLY failures were the 12
  `tests/test_performance.py` errors (`AttributeError: 'Function'
  object has no attribute '_nodeid'`): pytest-benchmark 4.0.0
  reads pytest's private `node._nodeid`, removed in pytest 9.2.0.
  Verified in an isolated probe venv (4.0.0 → 12 errors; 5.3.1 →
  12 passed) and fixed by widening the pytest-benchmark cap
  `<5` → `<6` (`1b13129`). CI on `1b13129` (run 42384474993):
  Core ALL SUCCESS, claims gate SUCCESS. Only failure: atheris.
- **#26 codeql-action → v4.39.3 — `fc20c65`** (NOT v4.39.2,
  superseded). SHA verified by dereferencing the tag object
  (`f3bbb056…` → `33d7b85da1a04171e211befe2c739303b9a4c066`).
  Exactly THREE usages (codeql.yml init + analyze, scorecard.yml
  upload-sarif — the dependency-audit.yml usage was removed by
  PR #36, see below). CI on the pushed head (run 42384859292):
  Core ALL SUCCESS, claims gate SUCCESS; CodeQL workflow run
  42384859218 completed SUCCESS. Only failure: atheris.
- **#28 setup-buildx v3 → v4 — `dc8a1e9`.** Latest v4.4.1,
  floating `@v4` correct. CI on the pushed head (run
  42385257727): Core ALL SUCCESS; Container run 42385257702
  completed SUCCESS.
- **#31 metadata-action v5 → v6 — `be2a344`.** Latest v6.2.0,
  floating `@v6` correct. Container run 42385719149 completed
  SUCCESS; CI run 42385719068: Core ALL SUCCESS, claims gate
  SUCCESS. Only failure: atheris.
- Remote main after the seven local commits: **`be2a344`**.
  Each was pushed one at a time by the parent, CI-gated on the
  pushed head before the next (per the plan). Local gates on the
  stacked head before pushing: ruff clean, format clean, claims
  33/33, schemas 12 OK, pre-commit 13/13, gitleaks 0 leaks over
  `9a9fd8a..HEAD`, extras 2850 passed + 1 known memory flake /
  57 subtests, core-only 2738 passed + 1 same flake / 112
  skipped / 57 subtests — baseline totals, no regression.

### Two pre-existing PR-only CI defects (found by PR #35, fixed as PRs #36/#37)

PR #35 was the first pull request since the rewrite; two workflows
only run on `pull_request` events (or PRs touching dependency
files), so their defects were invisible until then.

- **dependency-review.yml:25 — typo'd action SHA — PR #37.**
  Pinned `…f609a47…`; upstream v5.0.0 is `…f609c47…` (one
  character; the pinned SHA does not exist). One-character fix.
  Its own Dependency review check PASSED (6s). Merged to
  `3889086`.
- **dependency-audit.yml — `pip install sarif-tool` can never
  succeed — PR #36.** `sarif-tool` does not exist on PyPI (404);
  `sarif-tools` has no conversion command; pip-audit's `--format`
  choices are columns/json/cyclonedx-json/cyclonedx-xml/markdown
  (no SARIF). The dead Convert + Upload SARIF steps were removed;
  the JSON artifact is kept. Proven by a manual
  `workflow_dispatch` run (42373111977, completed success) and
  again on the rebased head (42374557149, completed success).
  Merged to `f7a80b3`. **Scope interaction:** removing the
  dependency-audit upload-sarif step is why #26 updates three
  codeql-action usages, not four.
- After #37 + #36 merged, PR #35's Dependency review (7s) and
  Pip Audit (11s) checks went green on fresh runs, as predicted.

### Flaky test fixed by the parent (found on PR #38)

`tests/test_timestamp.py::test_tampered_signature_fails` failed
once on Core 3.12 (PR run) and passed on retry. Root cause: the
tamper zeroed the first byte of an RSA signature, which is
already `0x00` with probability ~1/256 — a no-op tamper
(reproduced 1/400 fresh-key trials). Parent commit `e3cc99f`:
tamper now flips a bit mid-signature; test passes 10/10, full
file 15 passed, ruff clean. Same defect class as the U2 Ed25519
flaky tamper test.

### Node 24 sweep — PRs #40–#46 (rebased onto `be2a344`, CI-green, awaiting parent merge)

One workflow file per PR, each branched from `9a9fd8a` and
rebased onto `be2a344` with **zero rebase conflicts** (the
pushed commits' lines and the sweep lines did not overlap).
Each rebased head got the local gate (YAML parse, claims 33/33,
pre-commit 13/13, gitleaks 0 leaks); the Python tree is
byte-identical to the gated `be2a344` baseline, so the PRs' own
CI (full Core suite on each head) is the authoritative check.

| PR | File | Change | Rebased head |
|----|------|--------|--------------|
| #40 | container.yml | login-action @v3→@v4; upload-artifact @v4→v7.0.2 SHA | `5a99c7a` |
| #41 | dependency-audit.yml | upload-artifact @v4→v7.0.2 SHA | `1d8390f` |
| #42 | repository-integrity.yml | sbom @v0.21.0→@v0.24.3; upload-artifact @v4→v7.0.2 SHA | `82a127d` |
| #43 | reproducibility.yml | checkout @v4→v7.0.1 SHA ×4; setup-python @v5→v7.0.0 SHA ×4; upload-artifact @v4→v7.0.2 SHA ×3 | `1dda2f5` |
| #44 | semver.yml | checkout @v4→v7.0.1 SHA; setup-python @v5→v7.0.0 SHA | `a564cae` |
| #45 | fuzz.yml | checkout @11bd719→v7.0.1 SHA ×2; upload-artifact @5d5d22a→v7.0.2 SHA ×3 | `7c605e5` |
| #46 | mutation.yml | checkout @11bd719→v7.0.1 SHA ×2 | `b73a559` |

All three v7 SHAs were re-verified against the tags API and
match the in-repo pins exactly (checkout v7.0.1 `3d3c42e5…`,
setup-python v7.0.0 `5fda3b95…`, upload-artifact v7.0.2
`cf430e03…`). `container.yml:42 actions/checkout@v5` is already
Node 24 upstream — no action needed. `sigstore/cosign-installer@main`
untouched (out of scope).

**CI on all 7 rebased heads (verified 2026-11-07 ~16:00 CET):
39 pass / 3 fail / 3 skipping, 0 pending on every PR.**
Core Python 3.11–3.15 ALL PASS on both runs; claims gate,
build/wheel-install, OS smoke, Optional API/MCP, CodeQL,
Actionlint, Dependency review all PASS. The only failures
anywhere are the two known release-gate items (Pinned
requirements install ×2 — atheris; Diff-based Mutation —
0 mutations).

**CodeQL concurrency wart (pre-existing, not introduced by the
sweep):** `codeql.yml`'s concurrency group for PRs is the
shared `codeql-main` with `cancel-in-progress: true`, so the
seven PR-event CodeQL runs cancelled each other as the branches
were pushed in succession (#40–#45 showed a red CodeQL check
whose run conclusion was `cancelled`, not failed). All six
cancelled runs were rerun sequentially, one at a time, and all
six completed SUCCESS (runs 42386318075, 42386394409,
42386465080, 42386538946, 42386611636, 42386685608); #46's run
completed SUCCESS on its own (42386769828). Fixing the
concurrency group is a Phase 5 candidate, not part of this
sweep.

**Merge status (updated by the parent after the merges):** PRs
#40–#46 are all MERGED, in order, each by rebase merge, with
CI-green on main confirmed between merges (Core 3.11–3.15 +
claims gate green on the merge heads; the Container workflow
also ran SUCCESS on the #40 merge commit, proving login v4 +
upload-artifact v7.0.2 on main). Merge SHAs: #40 `f02f622`,
#41 `57e2c4a`, #42 `2e58018`, #43 `273e6be`, #44 `4a0c804`,
#45 `bdabbcb`, #46 `362d7d5`. No Node 20 stragglers remain on
main (the last ones — upload-artifact @v4, checkout @v4 /
@11bd719, setup-python @v5, sbom @v0.21.0 — were all covered
by #40–#46).

### Twine follow-up — pushed as `5b9e97a` (rebased from `1fb5b10`)

`twine>=4,<7` → `>=4,<8` in `pyproject.toml` + `requirements-pinned.txt`,
with the stale comment updated (the rich<14 conflict #32 removed
is gone). No Dependabot twine PR exists, so the manual edit is the
path (the plan says to prefer a Dependabot PR only if one exists).
PyPI latest twine **7.0.0**, which requires `rich>=14.3.3` —
satisfied by rich 15.0.0.

Evidence that rich 15 + twine 7 coexist: `pip install --dry-run
--upgrade -r requirements-pinned.txt` resolves **twine-7.0.0**
alongside rich 15.0.0 with no conflict; twine 7.0.0 + rich
15.0.0 in an isolated probe venv run (`twine --version` reports
rich 15.0.0) and `twine check` PASSED on the freshly built wheel
+ sdist. Local gate on `1fb5b10`: ruff check clean, format clean
(255 files), claims 33/33, schemas 12 OK, pre-commit 13/13,
gitleaks 0 leaks over `be2a344..HEAD`, extras suite **2851
passed / 0 failed / 57 subtests passed**, core-only suite
**2738 passed + 1 failed / 112 skipped / 57 subtests passed** —
the single failure is the known `test_memory_check` host flake
(host at 95.05% memory; the check fails when `mem.percent >
95`, and it fails even in isolation at that pressure).
`scripts/validate_pyproject_deps.py` green. The parent verified
and pushed this commit as `5b9e97a` (rebased from `1fb5b10`
onto `362d7d5` after the sweep merges; clean rebase, no
conflicts). CI on the pushed head (run 42389566451): Core
3.11–3.15 ALL SUCCESS, claims gate SUCCESS, build/OS smoke /
API/MCP SUCCESS. The pinned-install job failed ONLY at the
atheris wheel build (`ERROR: Failed building wheel for
atheris`, `failed-wheel-build-for-install`, `╰─> atheris`) —
dependency resolution itself succeeded with twine 7.0.0 +
rich 15.0.0, which is the coexistence proof.

### Final state checks

- **0 surviving `dependabot/*` branches** on the remote
  (verified 2026-11-07; the last one, build-push-action-7, was
  deleted after PR #39 merged).
- **0 open PRs.** All 7 sweep PRs (#40–#46) are merged; 0
  surviving `dependabot/*` branches; 0 open Dependabot PRs.
- Dependabot's next weekly run should find nothing outdated
  except genuinely new releases: every recovered cap now covers
  the current latest (cryptography 50.0.2 <51, rich 15.0.0 <16,
  pytest 9.2.0 <10, pytest-cov 7.1.0 <8, pytest-benchmark 5.3.1
  <6, twine 7.0.0 <8) and every action pin is at the current
  latest major/tag or SHA (attest v4.2.2, build-push v7.4.0,
  setup-buildx v4.4.1, metadata v6.2.0, login v4.8.0, codeql
  v4.39.3, checkout v7.0.1, setup-python v7.0.0, upload-artifact
  v7.0.2, sbom v0.24.3, dependency-review v5.0.0).

### What is NOT verified / NOT done here

- **Atheris + Mutation (release gate):** untouched in Phase 4.
  The pinned-install job still fails building atheris 1.0.11 on
  Python 3.12, and Mutation still runs 0 mutations. Both have
  known root causes and bounded fixes (see the release-gate
  investigation reports); they are Phase 5 work.
- **CodeQL concurrency group:** the shared `codeql-main` group
  with `cancel-in-progress: true` cancels parallel PR CodeQL
  runs. Diagnosed, worked around by sequential reruns; the fix
  itself is a Phase 5 candidate.
- **`sigstore/cosign-installer@main`** (repository-integrity.yml)
  is still a floating branch ref; pinning it is a separate
  decision, not a Dependabot recovery.
- **No release, no tag.** Nothing in Phase 4 creates a release.

## Verification record — Phase 5, wave 1: atheris, Mutation wiring, CodeQL concurrency (2026-11-07)

Three PRs, each verified locally and in CI on its own branch before
merging (stacked on the Phase 4 close `ca56440`):

- **#49 atheris 3.x** (`10d91c3`, 4 lines: `atheris>=3.0,<4` in
  pyproject `[fuzzing]` + pinned; both Fuzz jobs install
  `.[dev,fuzzing]`) → main `92bce94`. Pinned-install **SUCCESS** on
  main — the release-gate atheris failure is fixed there. Fuzz manual
  dispatch run 42391456528: all 5 jobs green, 9 targets in direct
  atheris mode, 0 crashes.
- **#50 Mutation cosmic-ray 8.x rewrite** (`027c361`) → main
  `8851f1f`. All five wiring defects fixed (changed_files output,
  push base `github.event.before`, module filter synced, runner
  rewritten for cosmic-ray 8.x `baseline → init → exec → dump`, no-op
  case passes). Mutation (Push) **PASS** on the PR via the genuine
  no-op path. Mutation Testing run on main at `67eab33` completed
  **SUCCESS** (no-op path, first green Mutation run on main).
- **#47 CodeQL per-PR concurrency** (`fd25079`, 1 line) → main
  `67eab33`. CodeQL runs 42391013563 (#47) and 42391079313 (#48)
  both **SUCCESS**, observed `in_progress` simultaneously.
- **PR #48** (throwaway CodeQL proof PR) closed unmerged.

**Post-merge Mutation proof (parent, commit `153b5ab`, comment-only
change to `src/textforensics/trust.py`).** Mutation Testing run
42393966895 on main ran real mutants: **total 200, killed 77,
surviving 123**, exit 2. The failure is the gate's designed
fail-on-survivor semantics, not a wiring failure; killed=77 matches
the local run exactly.

**Fuzz follow-ups (parent, after the merges).** The atheris bump
exposed a latent defect: five fuzz targets never bound
`instrument_func` when atheris was installed (dead
`if atheris is not None` guard inside the ImportError branch).
Fix `54d505e`; Fuzz run 42394702170 completed **SUCCESS**.
`-runs=0` verified empirically (with the flag: 0.1 s / 2 runs;
without: 6.1 s / 147,837 runs) and removed in `a269135`, with the
seed corpus now passed positionally instead of via `-dict=`. That
fix exposed a timeout-design bug (9 targets x 5 min = 45 min in a
30-min Regression job; Extended 9 x 10 = 90 min in 45 min), fixed
in `76fc8b1` (Regression 60 min, Extended 120 min). The Fuzz run
on `76fc8b1` itself never started (workflow `on.push.paths`
excludes workflow-only changes); the 60-min timeout is being
proven by the Fuzz run on `231a840` (42401880362), still in
progress at time of writing.

## Verification record — Phase 5, wave 2: mutation survivors (2026-11-07)

**PR #51** — equivalent-mutant baseline mechanism
(`58b2fe3` + consolidation `5bd2d4e`, 73 entries in
`mutation-baseline.toml`) → main `31d0a4b`. **PR #52** — 26 new
`TrustMutationKillTests` killing 50 of 54 killable survivors
(`3d14319` + `404684a`, tests only) → main `404684a`. Both
branch-CI fully green (41 pass / 0 fail each); neither PR's own
Mutation run proves the kills (both are no-op-path runs).

**Integration proof (coordinator, merged tree):** budget-200 run —
total 200, killed 127, surviving 73, equivalent 73, unexplained 0,
exit 0 ("[OK] All mutations caught!"). Arithmetic closes exactly:
77+50=127; 69+4=73; 127+73=200. Gate semantics unchanged (exit 2
on unexplained survivors, exit 1 on stale entries, equivalents
never counted as killed).

**Baseline refresh incident (parent).** The proof push `231a840`
(docstring record in trust.py) added 11 lines above every
baselined position, so all 73 entries went stale at once: the
Mutation run failed exit 1 and all five Core jobs failed on the
`EquivalentBaselineTests` — the mechanism failing loudly as
designed. Refresh `2d3c9a7` shifted every `start_pos`/`end_pos`
+11 lines and updated the 5 tests pinning absolute trust.py
positions; all 73 entries re-validate, and a local budget-200 run
reproduced the integration numbers exactly (200/127/73/0, exit 0).
A follow-up docstring edit `47e971d` miscounted the line delta
(2-line tail replaced with 3 lines, net +1; 88 local test
failures masked because `pytest ... | tail` returns tail's exit
code in a `&&` chain); fixed by `a36cb6f`, trust.py back to 616
lines, 84 trust/mutation tests pass. Lesson: never pipe a gate
command through `tail` in a `&&` chain; any docstring edit above
baselined positions must preserve the exact line count.

**CI proof on main (parent, commit `a36cb6f`, touches trust.py).**
Mutation Testing run 42403769698: Diff-based Mutation (Push)
**SUCCESS** — summary from the job log: killed 127, surviving 73,
equivalent 73, dormant 0, superseded 0. CI run 42403770029: Core
3.12–3.15, claims gate, pinned-install, build/OS smoke, API/MCP
all **SUCCESS**; Core Python 3.11 still running in Unit tests at
time of writing (its 404684a run finished SUCCESS; pre-commit,
compile and lint already passed on this head). Local gate on the
final tree: full suite 2902 passed / 0 failed (known
test_memory_check host flake deselected), pre-commit 13/13,
claims 33/33, schemas 12 OK.

## Verification record — Phase 5, wave 3: downloader urllib tuning + curl fallback (2026-11-07)

Design authority: `hidden_files/downloader-investigation.md`
(§5 rank 1: urllib tuning + curl fallback, combined). The incident
it fixes: the shared urllib downloader failed the ~879 MB
DetectRL-X fetch after 6 attempts, never past headers, while curl
fetched the file in ~5 min.

**PR #53** — implementation (`ed0fdab`, 4 files) → main `f0391eb`.
Split connect/stall timeouts (custom urllib handler, socket
timeout switches after `connect()`; plain `urlopen` path when the
budgets are equal); jittered capped back-off
(`random.uniform(0, min(60, 2·2**attempt))`); module logger with
per-attempt TTFB / bytes / slowest-read timing (host only, never
argv or curl stderr); `_download_with_curl` (argv list,
`shell=False`, `--` before URL, `--proto =https`, loopback-http
carve-out, non-loopback http refused, exit-33 restart, non-zero
exit → `DownloadError` with exit code only); `limit_bytes` prefix
probe; `download_detectrl_x` now `stall_timeout_s=300`,
`retries=8`, with the falsified "stalls under the 30 s default"
diagnosis corrected in its docstring (the incident ran six
attempts at a 120 s timeout). `--retry-all-errors` deliberately
NOT passed — verified locally to retry 404s (3 requests for one
404, curl 8.5.0). Found during implementation and fixed here: a
clean mid-body close is silent truncation in CPython 3.12
(`read()` returns `b""`); a body shorter than the declared
`Content-Length` now raises `IncompleteRead`, retries, and
resumes. Branch CI 41 pass / 0 fail.

**PR #54** — stall-server tests, prefix probe, probe workflow
(`1e0db22`, 3 new files) → main `3f1e113`. `ThreadingHTTPServer`
fixture (delayed headers, trickle, mid-body-drop resume,
Range-ignoring restart via forced curl); `scripts/
download_prefix_probe.py` (first 100 MiB, SHA-256 compare,
`--force-curl`); `.github/workflows/download-prefix-probe.yml`
(weekly Saturday 04:30 UTC + `workflow_dispatch` prefix/full).
Branch CI 42 pass / 0 fail. Reconciliation: worker A's
`DownloadStallServerTests` and worker B's
`tests/test_download_stall.py` overlap in behavior coverage but
differ in emphasis (handler timing + mocked argv vs end-to-end
fixture incl. curl exit-33); both kept, recorded as a known small
wart in the wave report.

Live evidence (2026-11-07, healthy egress): prefix probe urllib
MATCH 4.2 s / 23.95 MiB/s, forced curl MATCH 3.1 s / 31.99 MiB/s;
full download via shipped `download_detectrl_x()` — 878,631,989
bytes, SHA-256 match, 316.3 s (~5.3 min, 2.65 MiB/s), attempt 1/9,
urllib only (curl fallback NOT used — nothing stalled). NOT proven:
the curl fallback firing on a real stall, the stall timeout firing
live, the scheduled workflow running on GitHub Actions, the
`actions/cache` warm-hit path.

Parent verification on merged main `3f1e113`: `tests/
test_datasets.py` + `tests/test_download_stall.py` 99 passed;
full extras suite **2923 passed / 0 failed** (known
`test_memory_check` host flake deselected); pre-commit 13/13;
claims 33/33; schemas 12 OK. CI on `3f1e113`: all jobs SUCCESS
except Core Python 3.11 still running at time of writing (the
branch CI on the identical tree passed Core 3.11).

## Verification record — Phase 5, wave 4: latent defects register (2026-11-07)

All 13 findings from the latent-defects register
(`hidden_files/latent-defects-register.md`) are fixed and on main
`721b564`. Detail: `hidden_files/phase5-wave4-latent-defects.md`.

#1 + #8 (High — silent anti-rollback bypass, fixed together):
`PolicyRevisionFloor._load_state` no longer fail-opens; corrupt state
raises `PolicyStateCorruptError`, a wrong-length key file raises
`PolicyKeyError` instead of being silently overwritten, legacy 32-byte
raw keys are converted explicitly, state/key writes are atomic, the
CLI fails closed with exit 3. Two pinned tests that asserted the
reset were changed. A real defect found while fixing: the 32-byte
length was checked AFTER `.strip()` — a legacy key whose first/last
byte is ASCII whitespace lost a byte and failed the check (Core 3.15
CI failure, fixed in `284b118`). A flaky test using `os.urandom(32)`
failed ~4.5% of runs for the same reason; now a fixed key.

#3 (Medium): `EnterprisePolicyEngine.evaluate` implements the
`"disable"` action the schema enum and docstring already advertised.
#2 (Low): `_hash_directory` docstring corrected (missing dir returns
`""`, empty dir returns the empty-string hash). #13 (Low): file reads
streamed in 1 MiB chunks instead of unbounded `read_bytes()`.

#4a/#4b/#4c/#10/#11/#12 (adversarial): `analyze` de-dup now feeds
risk + report (was computed and discarded); duplicated `_sha256`
removed; `false_positive_rate` no longer defaults to a fabricated
0.0; `detect_regex_artifacts` hashes the real matched span, not
`text[:200]`; dead `HumanizationPattern` dataclass deleted; two
discarded no-op statements removed.

#5 (Low): `ModelCard.load`/`load_model_card` are real loaders now
(they parsed JSON and unconditionally returned `None`). #9 (Low):
v3 overall on zero dimensions returns `"insufficient"` in both the
primary and the replay path. #6 (Low): the gitleaks false positive
(`tests/test_watermarking.py:533`, runtime-generated keypair
comparison) is allowlisted in `.gitleaks.toml`.

Mutation — policy.py is the second target module with a kill/baseline
proof after trust.py (wave 2). The runner itself needed a fix:
`test_command_for` mapped `textforensics.policy` to
`tests/test_policy.py`, which does not exist (tests live in
`tests/test_enterprise_policy.py`), so it fell back to the full
suite and the 30 s per-test timeout killed the baseline before any
mutant ran — that is exactly what failed PR #56's Mutation job
before the mapping fix landed. New baseline kind
`"unobservable-value"` (a NumberReplacer mutant whose replacement
value is provably unobservable) reuses the `unreachable-condition`
validation path exactly; the loader rejects unknown kinds. Baseline
entries are position-keyed: the strip fix added +5 lines above the
baselined positions, so 42 entries pointed 5 lines too high — caught
by the runner's own re-validation (51 test failures, all position
failures) and fixed by shifting positions only, same as the wave-2
+11 precedent.

Proofs (all parent-verified independently): #55 branch head
`9a89264` — budget-200 diff run: total 200, killed 118, surviving
82, equivalent 82, unexplained 0, stale 0, exit 0; full suite 3007
passed / 0 failed (1 deselected, known `test_memory_check` host
flake); branch CI Mutation job pass (6m5s). #56 branch head
`721b564` (rebased onto `9a89264` with zero conflicts) — budget-200
diff run: total 200, killed 119, surviving 81, equivalent 81,
unexplained 0, stale 0, exit 0; full suite 3016 passed / 0 failed
(1 deselected); branch CI Mutation job pass (6m54s), 39 pass / 0
fail. Gate not weakened: exit 2 on unexplained survivors, exit 1
on stale entries, equivalents never counted as killed.

Process change (Greg, 2026-11-07 21:51 CET): development ONLY in
main, no PRs, no lingering branches, no manual review by Greg. The
parent merged #57 (adversarial, `db2b331`), #58 (misc, `65d761b`),
#55 (`9a89264`) and #56 (`721b564`) directly by fast-forward of the
exact verified commits, closed redundant PR #59 unmerged, and
deleted every non-main branch including the leftover
`codeql-proof-pr2`. End state: only `main` exists locally and
remotely; 0 open PRs.

Honest gaps: 298 unexecuted work items in the 498-item policy
session (incl. 3 Pow mutants deliberately not baselined) remain
unknown until a larger-budget run; the baseline stays position-keyed,
so any edit above a baselined position that changes the line count
must refresh the baseline or the gate fails loudly by design.
