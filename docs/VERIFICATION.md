# Verification record — Phase 1 (2026-11-06)

## Current state (HEAD `7a3d28f`, 2026-11-10)

Read this first. The dated sections below are historical records;
their numbers are the numbers as measured at the time, and some of
their "NOT verified" items have since been superseded (marked
inline). The current picture, measured on `fb1e23a` (Python 3.12.3,
`test_memory_check` host flake deselected — see the HEAD section at
the end of this file):

- **Since `8c8a1cf` (merges to `48ae5bc`):** full verification on
  `8c8a1cf` (extras 3933 passed / 81%, core-only 3813 passed /
  78.50% exact, claims 33/33, schemas 12 OK, pre-commit 13/13,
  manual checks byte-identical to `fb1e23a`; report
  `hidden_files/phase5-full-verification-8c8a1cf.md`), the
  worst-slice human-FPR wave (`cc9a272`: OpAI-Bench n=2000 sample,
  218 human / 223 AI, Wilson 95% upper 0.0173 — the worst slice now
  passes the bar; 4 U1 duplicates excluded by content hash;
  GhostWriter threshold robustness measured, threshold unchanged;
  human-FPR run artifact now conforms to run-artifact/v1), and the
  registry apply (`48ae5bc`: validation registry 8 → 9 records,
  evidence registry 32 → 34 pins; report-card lead stays unknown —
  no FPR claim is written). Neither the FPR merge nor the apply
  changes any `src/` code, so the `8c8a1cf` suite numbers stand as
  the latest full measurements.
- **Since `48ae5bc` (merge to `7a3d28f`):** live-TSA interop
  (`7a3d28f`): a live timestamp round-trip was achieved against
  freetsa (`valid=True`, four independent runs 08:50–09:40 UTC,
  serials strictly increasing), closing the release blocker. The
  wave found and fixed two pre-existing client defects from
  `8eb4163` that had made every conforming token unverifiable: the
  wrong id-signedData OID (`1.9.16.1.2` → `1.7.2`) and wrong P-384
  curve constants (`n` had 8 extra leading `F`s, `gy` was truncated
  to 64 hex chars) — both verified numerically by the parent
  (generator on curve, `n*G` = infinity, values match OpenSSL's
  secp384r1 exactly) and by a fresh live round-trip (09:40 UTC,
  serial `166107095`, `valid=True`). Gates on the merged tree:
  claims 33/33, schemas 12 OK, pre-commit 13/13, 55 timestamp
  tests passed. Evidence seeding for the round-trip is an open
  design question (`seed_evidence.py` has no TSA measurement); the
  round-trip is recorded in `docs/TSA_INTEROP.md` with token SHAs.
  This merge DOES change `src/` (`timestamp.py`,
  `_standalone_verify.py`), so the `8c8a1cf` suite numbers remain
  the latest full measurements; only the TSA-affected test files
  were re-run on the merged tree.

- **Since `fb1e23a` (merges to `8c8a1cf`):** action upgrades
  (`21ff98e`: checkout v7.0.1, gitleaks v3.0.0, scorecard v2.5.0),
  the `fb1e23a` verification record and its figure fixes
  (`245056c`/`ad6446d`), SBOM regeneration (`96f3032`/`bfb2097`:
  filelock 4.2.10, typer 0.29.0, 122 components), the §2.6
  fresh-checkout verification rule (`b52db9b`), and the
  mid-body-drop test hardening (`8c8a1cf`).
  No full suite was re-run on `8c8a1cf`; the suite numbers below
  are the `fb1e23a` measurements and stand as the latest full
  measurements.
- **Full suite (extras): 3933 passed, 0 failed, 1 skipped, 1
  deselected, 1985 subtests passed in 464.80 s (7:44).** The 1 skip
  is the SBOM full-pinned-install check (atheris/wheel not in the
  main venv); the 1 deselected is the known `test_memory_check`
  host flake. The first attempt died at ~39% in a VM reboot; the
  cited run is a clean full re-run, reproduced exactly by an
  independent re-measurement (3933/1/1, 1985 subtests, 270.41 s).
  Core-only suite (fresh bare venv, `pip install -e ".[dev]"`,
  venv `bin/` first on PATH): **3813 passed, 0 failed, 121 skipped,
  1 deselected in 409.00 s, coverage 78%** (18,038 statements,
  3,455 missed, 6,834 branches, 946 partial; gate 75% passed) — the
  121 skips are all core-only-venv environment artifacts (fastapi
  not installed, API dev deps, web_ui module not available, MCP dev
  deps, API deps, uvicorn, the full-pinned-install check,
  cyclonedx) — the extras surface is not installed in a core-only
  venv by design. Coverage correction: the original core log
  reported 82% (2,795 missed). That figure did NOT reproduce — an
  independent re-measurement in a fresh bare venv measured 78%
  (3,455 missed) with identical pass/skip counts, and four clean
  core measurements give 3,454–3,456 missed. The 82% figure
  is an unverified artifact (one file, `_standalone_verify.py`,
  carried 657 traced lines in that one data file that no
  reproducible run produces; how they got there was not
  established) — see the HEAD section below. Core coverage is
  essentially unchanged from `e65fde9` (78.49%, 3,454 missed).
- **Claims gate: 33 passed, 0 failed.** **Schemas: 12 OK.**
  **Pre-commit: 13/13** (see the HEAD section below).
- **U7 evidence registry: 32 records**
  (`docs/evidence/registry.json`). **Validation registry:
  8 records** (`docs/validation/registry.json` — 7 `partial` + the
  RAID humans record, the first `supported` record).
- **Mutation baseline: 1697 equivalent mutants** (arg 1340, return
  170, annassign 11, domain-equivalent 135, unobservable-value 29,
  ulp-equivalent 6, unreachable-condition 6; runtime 176) across 9
  modules; every full-session proof exits 0 with 0 unexplained.
  Wave 2 totals: 4068 items, 3176 killed, 892 equivalent,
  0 unexplained.
- **Worst-slice human FPR: unknown** (`docs/evidence/report-card.md`).
  Pooled human FPR 0.0 [0.0, 0.0298] was measured on the first U3
  live probe run, and native-verdict FPR 0.0000 on the U1 seeds —
  neither is release-gate FPR evidence. The best measured per-slice
  Wilson 95% upper is 0.0038 pooled docs (0/1002); the worst document
  slice is OpAI-Bench 0.0642 (n=56), which fails the bar.
- **Manual end-to-end checks (this verification):** `textforensics
  scan` on a 35-word human-like text → score 0.3446
  `insufficient_evidence`; on a 35-word machine-like text → 0.6686
  `insufficient_evidence` (just below the 0.68 `ai_like` threshold),
  sane direction. Case-file round-trip: `case keygen` creates a
  0600 key file; `case export --seal` produces the bundle; the
  standalone stdlib verifier in the bundle exits 2 without a public
  key and 0 with the correct key (signature verified, key
  fingerprint matches).
- **CI on HEAD `fb1e23a`: no test failed.** The six workflow runs
  concluding "failure" are a GitHub platform incident artifact
  (incident `tp8cghg7tlc4`, "Incident with Actions and Checks API",
  2026-11-09 18:12:37–18:59:32Z): 14 job records were lost at
  scheduling time, and the affected runs were finalized as failure
  even though every job that ran succeeded — 22 check-runs: 20
  success, 2 skipped, 0 failure. CodeQL re-run (attempt 2)
  succeeded 20:35:39Z. No repo-side fix is needed; see
  `phase5-ci-caveat-investigation.md` in the goal hidden_files. The
  separate 54c1e25 Core Python 3.12 failure was a single-test
  loopback socket race (`test_mid_body_drop_resumes_with_range`,
  requests_seen 1 != 2) — a test/fixture fragility, not a
  `download_large_file` defect; it passes on `fb1e23a` (CI Core
  3.12: 3814 passed, 121 skipped, 1985 subtests).
- **CI on current main `8c8a1cf`: all 8 workflow runs completed
  SUCCESS** (CI, CodeQL, Mutation Testing, Supply-chain security,
  Repository Integrity, Reproducibility, Scorecard, Semver; created
  2026-11-09 22:36:44Z) — 36 check-runs: 34 success, 2 skipped,
  0 failed. This supersedes the `21ff98e` SBOM-staleness failure
  (recorded in the `fb1e23a` section below): the SBOM was
  regenerated (`96f3032`/`bfb2097`) and the staleness job passes.
- **Open items:** live-TSA interop (never achieved from the sandbox
  VM) and PAN 2025 (Greg-side TIRA registration, unconfirmed).
  Closed since `fb1e23a`: the `test_mid_body_drop_resumes_with_range`
  socket-race hardening (merged `8c8a1cf`) and the SBOM staleness on
  `21ff98e` (SBOM regenerated `96f3032`/`bfb2097`).
- **Closed since `e65fde9`:** the casefile Phase-2 proof (merged
  `54c1e25`: 2118/2118, corrected true counts 1416 killed / 702
  equivalent / 0 unexplained, baseline 1665) and the policy 298
  proof (merged `fb1e23a`: 506/506, 392 killed / 114 equivalent /
  0 unexplained, baseline 1697); the coverage numbers aligned
  (`--fail-under=95` → 75, `--cov-fail-under=80` → 75,
  `minimum_coverage` 80 → 75, merged `caa80ca`); the bare
  `pip-audit` / `bandit` step fixed (run from `.audit-env/bin/` +
  the `#egg=textforensics` grep bug, merged `caa80ca`); the
  ROADMAP coverage-gate statement updated (merged `fd8d0ad`)
  and SECURITY pinning status updated (merged `1e4d333`); the three
  action upgrades (checkout v5.1.0 → v7.0.1, gitleaks v2.3.9 →
  v3.0.0, scorecard v2.4.1 → v2.5.0, merged `21ff98e` — after
  `fb1e23a`). The coverage gate is `--fail-under=75`
  in CI (`ci.yml:70`) and is measured on **core-only** coverage —
  78% on `fb1e23a` (78.49% on `e65fde9`), a ~3.5 pp margin —
  NOT on the extras-venv 81% this section used to cite. The
  extras figure is a different measurement and must never be used
  as the gate basis.

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
python scripts/check_pip_audit.py   # exit 0: no new findings
```

pip-audit is a **failing gate**, not a report-only scan
(Phase 5 pip-audit gate wave, 2026-11-08). The gate script
`scripts/check_pip_audit.py` runs pip-audit against the installed
environment **and** `requirements-pinned.txt`, deduplicates repeat
reports of the same vulnerability, and compares every finding
against the checked-in `pip-audit-baseline.toml` — one entry per
accepted finding (package, vulnerability id, affected version,
reason, review date). Exit 0: every finding baselined. Exit 2: a
new finding (new package, new vulnerability id, or new affected
version). Exit 1: configuration error, or a still-present finding
whose baseline entry is past its review date. There are no blanket
ignores and no `--ignore` flags. The gate is owned by
`.github/workflows/supply-chain.yml` (single `pip-audit-gate` job:
push to `main`, PRs touching dependency files, weekly Monday
04:23 UTC); the former duplicate zero-tolerance jobs
(`pip-audit --path . || exit 1`) and the never-failing
`dependency-audit.yml` job are deleted.
`enterprise-deep-verification.yml` keeps its own weekly
zero-tolerance audit of the frozen requirements file, which
`pip freeze` builds without pip itself, so it does not conflict
with the baselined installer findings.

**Current state (2026-11-08, re-seeded record
`EV-20261108-pip-audit`): 12 findings in 1 package, all baselined.**

| Package | Installed | Findings | Fixed in |
|---------|-----------|---------:|----------|
| pip | 24.0 | 12 (6 unique ids, each reported twice) | 25.3 – 26.2 |

- `pip` 24.0 is the virtualenv's own installer, not a shipped
  project dependency; the project pins no pip version. The six
  unique ids are PYSEC-2026-1795 (fix 25.3), PYSEC-2026-1796
  (fix 26.0), PYSEC-2026-2875 (fix 26.1), PYSEC-2026-2876
  (fix 26.1), PYSEC-2026-196 (fix 26.1.2), PYSEC-2026-3721
  (fix 26.2). Every other installed package reports 0 findings.
  A rebuilt venv with pip >= 26.2 clears all six; review date
  2027-02-06.
- `cryptography` 0 findings (cap `>=42.0.8,<51` since Dependabot
  #27, Phase 4); `pytest` 0 findings.
- The pinned-requirements audit reports **0 findings** after the
  `setuptools` cap was widened `<80` → `<85` in this wave: the
  `<80` cap forced the vulnerable 79.x line, and the pinned audit
  had reported 3 findings in setuptools 79.0.1
  (PYSEC-2026-3447 ×2, fixed in 83.0.0; GHSA-xmj3-9gf7-h52w,
  fixed in 84.1.0). The cap was widened instead of baselining a
  fixable build-backend vulnerability — the same call as
  Dependabot #27 for cryptography.

Gate proven both ways live (2026-11-08, worktree venv, pip 24.0):
clean run exits 0 (12 raw / 6 unique findings, all baselined,
pinned audit 0 findings); a planted new finding (temporary
requirements file pinning `cryptography==42.0.8`, never a real
pin) exits 2. Comparison logic is unit-tested in
`tests/test_pip_audit_gate.py`.

**25 findings in 3 packages** (2026-11-06 measurement, kept as a
dated record):

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
  **Update (Phase 4, 2026-11-07): #27 LANDED** — commit `ac030c7`
  widened the cap to `cryptography>=42.0.8,<51` in `pyproject.toml`
  (both occurrences) and in `requirements-pinned.txt`; the 42.x
  forced line above is history. The 25-findings table above is the
  2026-11-06 measurement, kept as a dated record; re-run pip-audit
  before the release and re-seed if the counts moved.
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
  **Superseded by the datasets wave 1 / wave 2 sections below:**
  RAID, MAGE, Beemo, OpAI-Bench, GhostWriter and DetectRL-X are now
  measured (preliminary); DetectRL, M4, M4GT-Bench and MixSet are
  licence-blocked with refusing loaders.
- Python 3.11 / 3.13 / 3.14 / 3.15: only 3.12.3 was run locally. Those
  versions are in the CI matrix (`.github/workflows/ci.yml`); local
  verification on them is not claimed.
- Human false-positive rate: no human-FPR evidence exists yet. It is a
  Phase 5 release gate (AGENTS.md rule 10), not a claim made here.
  **Partly superseded, still open:** native-verdict FPR 0.0000 was
  measured on the U1 seeds (see the U1 and wave 2 sections below) and
  pooled human FPR 0.0 [0.0, 0.0298] on the first U3 live probe run —
  but worst-slice human FPR is still **unknown** (see the current-state
  summary at the top of this file), so the release gate is still blocked.
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
  **Resolved in U2 (see the U2 section below):** `verify.py` now
  accepts v1/v2/v3 Trust Maps, with `stale` a distinct state. No new
  work — this item is closed, recorded here so the U1 section is not
  misread as current.
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

## Measured numbers at HEAD `264344e` (2026-11-07)

Docs wave, branch `docs/roadmap-verification`. The tree at this head
is code-identical to main `264344e` (Phase 5 wave 4); only
`ROADMAP.md`, `docs/VERIFICATION.md` (this file) and the goal working
notes `hidden_files/roadmap.md` changed. Environment: Linux VM,
Python 3.12.3, main clone's extras venv (`.venv`), `PYTHONPATH` set
to this worktree's `src/` so the worktree code is what ran.

- Full suite, extras venv: **3016 passed, 0 failed, 1 deselected,
  232 subtests passed in 635.91 s.** The 1 deselection is the known
  `test_memory_check` host flake (`tests/test_diagnostics.py::
  TestDiagnosticsEngine::test_memory_check`), deselected because the
  host was at 7,739/7,934 MB used during the run; it is a host-memory
  assertion, not a code failure. Command:
  `python -m pytest tests/ -q -p no:cacheprovider --deselect
  "tests/test_diagnostics.py::TestDiagnosticsEngine::test_memory_check"
  -o addopts=''`.
- Same suite with coverage: **3016 passed, 0 failed, 1 deselected,
  232 subtests passed in 652.20 s; 83% line coverage** (17,831
  statements, 2,375 missed, 6,716 branches, 1,214 partial). Coverage
  is down from the 86% recorded in earlier waves because the tree
  grew (11,582 statements at U7 → 17,831 now); the new modules
  (probe runs, mixed-origin, sealing) carry the lower-coverage tail.
  This is the measured number the Phase 5 coverage-gate item refers
  to: CI still enforces `--fail-under=70`, not 83%.
- Claims gate: **33 passed, 0 failed**
  (`python scripts/check_claims.py`, exit 0).
- Schemas: **12 OK** (`python scripts/validate_schemas.py`).
- Ruff: **0 errors, 210 files formatted**
  (`ruff check` + `ruff format --check` over `src/ tests/ scripts/`).
- Registries (read, not re-seeded): U7 evidence registry **18
  records** (`docs/evidence/registry.json`); validation registry
  **7 records, all `partial`** (`docs/validation/registry.json`).
- Report card still leads with worst-slice human FPR = **unknown**.
- Core-only suite not re-run in this pass (no bare venv was built
  for a docs-only change); last recorded in the U4 section above.
- `pre-commit run --all-files`: **13 hooks pass, 0 fail** (run after
  the docs edits above; ruff lint + format, json-schema-validator,
  detect-secrets, trailing-whitespace, end-of-file-fixer and the
  rest all green).

## Verification record — Phase 5, docs wave: all 59 audit findings (2026-11-08)

Input: `hidden_files/docs-audit.md` (59 findings: 4 P0, 11 P1, 8 P2,
4 P3), written against main `5ab3c45` — stale in places (pre-U2/U3/
U4, pre-Phase 4, pre-waves 1–4); every fact re-verified from the
tree. Detail: `hidden_files/phase5-docs.md`.

- **Spec (SP-1–SP-13):** §§11.1–11.3 rewritten from the actual
  CLI/API/MCP surfaces (real commands incl. `mixed-origin`,
  `case keygen`, `drift run/status`; exit codes 0/1/2/3 — exit 3
  exists, `EXIT_ERROR = 3`; 16 registered MCP tools, response
  shape `{success, exit_code, ...}`); new §6.4 (Trust Map v3 /
  `stale` / `mixed` cap), §5.5 (U1 registry), §9 (T1/T2/T3 seal
  tiers), §10 (real gate checks (a)–(f)), §14 (release definition:
  claims gate, CI green, human-FPR evidence, live-host
  verification, no PR self-review); §5.1 labelled
  illustrative/fictional; §12.2 line coverage corrected 86% → 83%
  by the parent (two independent measurements + committed
  `EV-20261107-suite.json`, 17,831 stmts, 83%).
- **CHANGELOG + CLAIMS (C-1–C-3, CL-1–CL-6):** [Unreleased] now
  covers Phases 2, 3, 4 and 5 waves 1–4, every number traced to
  this file or a phase report. `security.pip_audit_tracked`
  reconciled the new way — the cryptography cap WAS widened by
  Dependabot #27 in Phase 4 (`ac030c7`), now `<51`; fresh pip-audit
  re-seed: 12 findings in 1 package (pip 24.0: 12), cryptography 0,
  pytest 0. Suite claims re-seeded via `seed_evidence.py` (no
  artifacts hand-edited): extras 3016 passed / 1 flake / 83%,
  core-only 2904 passed / 1 flake / 112 skipped / 81%. U7 registry
  rebuilt 18 → **29 records** (11 new 2026-11-07 artifacts; the
  wave report's "28" is wrong — parent re-counted: 18 old retained
  + 11 new = 29, and re-verified all 29 sha256s against the files
  on disk, 0 mismatches; the two suite-record sha256s match the
  cited prefixes exactly). `.secrets.baseline` 581 → 607 entries,
  grafted per the U7 precedent (each value recomputed, never a
  naive rescan).
- **README + SECURITY + RELEASE (R-1–R-7, S-1–S-2, RL-1–RL-3):**
  Trust Map v2/v3 + `stale`, all 10 dimensions, new "Validation
  evidence and the claims gate" section with no performance
  numbers, `[all]` retitled "API + MCP surfaces", no tagged
  release exists, T1/T2/T3 seal tiers, RELEASE evidence gate,
  human-FPR checkbox blocked.
- **ROADMAP + VERIFICATION (RM-1–RM-6, V-1–V-4, HR-1–HR-6):**
  checklists reconciled against U2/U3/U4 and Phase 4/5 delivery;
  "Current state" summary atop this file (updated to HEAD
  `3d88f94` by the parent: registry 29, core-only 2904/1/112/81%);
  #27 note corrected; hidden roadmap brought to `264344e`.

Audit errors caught by the workers (verified from the tree): exit 3
exists; `trust_map_from_capability_ledger` exists (legacy v1 view);
only 16 MCP tools registered; RAID AUROC is 0.5937 in the committed
artifact, not 0.6414.

Deliberately NOT fixed — follow-up wave needed (code/claim
decision, not a docs edit): bandit now reports **3 MEDIUM** (B310
`urlopen` in `datasets.py:517,1204`, `timestamp.py:379`) + 26 Low, so
`security.bandit_no_medium_high` ("0 medium, 16 Low") no longer
describes current `src/`; and network imports now exist in
`datasets.py`, `ollama.py`, `timestamp.py`, so
`core.local_first`'s "only network import is ollama.py" note is
stale. The claims stay on their valid 2026-11-06 records; the gate
still passes 33/33.

Parent verification on merged main `3d88f94`: pre-commit 13/13,
claims 33/33, schemas 12 OK, full extras suite 3016 passed / 0
failed (1 deselected flake) — re-run by the parent on the merged
tree; the four branches were merged by rebase + fast-forward of the
exact verified commits, in the order spec → changelog-claims →
readme-security → roadmap-verification. Two workers left their
changes uncommitted (C, D); the parent reviewed the diffs, ran the
gates, and committed them.

## Verification record — Phase 5, follow-up wave: bandit B310 + core.local_first (2026-11-08)

Detail: `hidden_files/phase5-followup-bandit-localfirst.md`.

- **Bandit:** the 3 MEDIUM B310 `urlopen` findings got a real fix,
  not a suppression — a shared `_require_https_or_loopback_http()`
  validator (https anywhere, http only on loopback) now guards
  `download_large_file`, the HF client constructor, and
  `_require_https_tsa_url()` guards `request_timestamp`, which
  previously took a user-supplied `--timestamp-url` with zero
  validation. Each site also carries a narrow `# nosec B310` with a
  written justification, because scheme validation alone does not
  clear the static rule (proved empirically). New counts: **0
  MEDIUM / 0 HIGH / 26 Low** (was 3 / 0 / 26). Evidence:
  `EV-20261108-bandit` (sha256 `23cac071…`, seeded with
  `TZ=Europe/Berlin` so the seeder's date-derived record ID did not
  overwrite the pre-fix `EV-20261107-bandit` record); registry
  29 → 30. Claim `security.bandit_no_medium_high` restated to
  0/0/26. Honest residual: urllib follows redirects, so an https URL
  could redirect to http (curl pins `--proto-redir =https`); bounded
  by SHA-256 verification on downloads and cryptographic verification
  on TSA tokens.
- **core.local_first:** restated, not moved. The statement is still
  true in substance; the notes/values were stale. The AST scan now
  lists all three network-importing files with per-file
  justification: datasets.py (licence-gated fetch path, downloads
  only, never uploads text), ollama.py (opt-in adapter; the scan
  also counts its real `aiohttp` import, line 36), timestamp.py
  (TSA POST of a hash digest only, behind `--seal`). The
  `EV-20261107-code-audit` record already existed un-cited and was
  `--force` re-seeded (code_version `264344e` → `910db75`). The
  claim's statement is unchanged; only notes/values describe the
  actual 3-file surface. Neither claim was weakened.

Parent verification on merged main `7f349c1`: bandit branch gates
re-run by the parent (claims 33/33, pre-commit 13/13, datasets +
timestamp tests 119 passed); local-first branch rebased onto the
bandit merge with zero conflicts — the registry union (30 records)
landed cleanly, and the parent re-verified all 30 sha256s against
the files on disk (0 mismatches) plus claims 33/33 and pre-commit
13/13. The coordinator's predicted line shifts were wrong
(datasets.py urlopen at :551/:1246, not :548/:1240); the parent
fixed the four stale citations from the actual tree
(:517→:551, :1204→:1246, :379→:410, cli.py :1790-1791→:1791-1792)
before merging. Full extras suite on the merged tree: **3026
passed / 0 failed** (1 deselected flake; +10 new tests).

## Verification record — Phase 5, U2 follow-up: seal-time not_reproducible declaration (2026-11-08)

Detail: branch `fix/u2-not-reproducible` (base `3e53278`); closes
U2 report §(h), the one partial criterion carried to the release
gate.

- **Schema v4:** `textforensics.case-file/v4` is the default seal
  (v1–v3 still verify). v4 is v3 plus per-observation determinism:
  `detector_observations[]` items gain optional `determinism`
  (`deterministic` / `non_deterministic` / `unknown`) and
  `determinism_reason`; the v4 `allOf` branch requires `determinism`
  on `kind: "observed"` items. The detector-result schema gains the
  same two optional properties so analysis-time `detector_results`
  entries validate. The golden case file was regenerated as v4
  (case_sha256 `0f15e188ccac0ab6010b19410b5f573850dd2243fbe47965c0c761079ce538f5`).
- **Seal-time sources:** the builtin heuristic detector declares
  `deterministic`; the Ollama adapter (`OllamaDetectorMixin`)
  declares `non_deterministic` with a sampling reason; anything
  undeclared is `unknown`. `build_forensic_bundle` records the
  declaration into each `detector_results` entry at analysis time.
  `seal_case_file` accepts explicit `determinism` /
  `determinism_reasons` overrides keyed by detector ID; an override
  wins over the bundle-recorded value and is written into the sealed
  bundle copy as well as the observations, so verification rebuilds
  exactly what was sealed (the declaration itself is protected by
  the case hash / T2 signature). Unknown detector IDs and invalid
  values are rejected at seal time, never silently dropped.
- **Replay:** a score/verdict/version/calibration mismatch on a
  detector whose sealed observation declares `non_deterministic`
  yields check status `not_reproducible`, no mismatch errors, and a
  warning `not_reproducible:<detector_id>[:<reason>]`.
  `deterministic` / `unknown` mismatch fails closed, exactly as
  before. `replay_case_file` returns `replay_outcome`:
  `reproduced` (no errors, nothing not_reproducible) /
  `inconclusive` (no errors, >=1 not_reproducible) / `failed` (any
  error); `valid` keeps its meaning, so inconclusive is
  valid-but-inconclusive, never silently passed. A sealed-bundle
  verification of an inconclusive replay exits 2 (the existing
  valid-plus-warnings rule); `case verify` on a bare case file does
  the same, and both surface `replay_outcome` in their JSON output
  (bare case files also in the scope statement).
- **Verification compatibility:** v3 files sealed before determinism
  existed still verify — v3 observations are compared ignoring the
  determinism fields (present declarations must still be valid);
  v4 compares exactly, determinism included. The standalone verifier
  mirrors the new fields, accepts v4 bundles, and rejects a tampered
  determinism field (hash check when un-rehashed, observations check
  when re-hashed).
- **Deviations from the brief, recorded:** (1) the `deterministic`
  attribute is documented on the `Detector` protocol but is NOT a
  protocol member: the protocol is `runtime_checkable`, and
  `isinstance` rejects any object missing a declared member, so
  making it a member would break every existing detector that does
  not declare it (verified empirically). It is read via
  `detector_determinism()` with `getattr`, missing/`None` meaning
  `unknown`. (2) `replay_outcome` is `reproduced` when no detectors
  are supplied and nothing errors — per the pinned definition —
  even though no detector re-execution was attempted; the
  `checks["detectors"]` status (`not_supplied`) disambiguates, and
  the caveat is documented in `replay_case_file` and the spec. The
  CLI does not re-run detectors, so a CLI replay can only reproduce
  or fail; `replay_outcome` is still reported.
- **Docs:** `SEALING_KEYS.md` (new determinism section),
  `README.md`, `ARCHITECTURE.md` §1.7, `REVAMP_SPEC.md` §9,
  `CHANGELOG.md` ([Unreleased]). No claim was weakened: claims
  33/33, `casefile.replay_verifies` still holds (replay now also
  reports `replay_outcome`).

Verification on the branch (extras venv, bin/ on PATH,
`PYTHONPATH` = worktree `src`): pre-commit **13/13**,
`scripts/check_claims.py` **33/33**, `tests/test_schema.py` **26
passed**, full extras suite **3057 passed / 0 failed** (232
subtests passed; 3026 baseline + 29 new `test_casefile_v4.py` tests
+ 1 new explicit-v3 test in `test_casefile_v3.py` + 1
`test_memory_check` host test that passed this run instead of being
deselected). The golden file verifies via
`scripts/verify_golden.py`. Two ruff findings from the first pass
were fixed, not suppressed (a lambda in `_standalone_verify.py`,
an unused loop variable in `report.py`).
## Verification record — Phase 5, U2-leftovers: live-TSA interop re-attempt (2026-11-08)

Branch `fix/u2-tsa-interop`, based on main `3e53278`. No push, no
merge, no release, no tag (parent merges).

- **Live-TSA interop: STILL BLOCKED from this VM.** Re-attempted
  2026-11-08 00:11–00:22 UTC with 10 s timeouts, max 2 attempts per
  endpoint, every attempt wrapped in a hard outer timeout.
  `request_timestamp(timeout=10.0)` against `https://freetsa.org/tsr`
  and `https://timestamp.digicert.com` both timed out on read
  (10.51 s / 10.30 s); a second attempt via raw urllib with a real
  62-byte `TimeStampReq` timed out the same way (10.35 s / 10.27 s);
  curl POST to freetsa `/tsr` gave HTTP 000 in 10.002 s, 0 bytes,
  exit 28. Controls: freetsa homepage GET 200 in 1.08 s (urllib) /
  302 in 0.63 s (curl) — egress reaches the host, only the `/tsr`
  POST path hangs. DigiCert homepage GET itself timed out at
  10.12 s this time. No production timeout was edited; no retry was
  added; no claim was changed. Full probe record and the exact
  unrestricted-host re-attempt procedure: `docs/TSA_INTEROP.md`
  (pointer also in `docs/SEALING_KEYS.md`, Timestamps section).
- **Mock-TSA tests (new):** `tests/test_timestamp_mock_tsa.py`
  (4 tests) — stdlib `http.server` on loopback accepts a
  TimeStampReq and returns a TimeStampResp carrying a real CMS token
  built with the production DER encoder (`tests/_token_fixture.py`);
  `request_timestamp` round-trips and verifies it through
  `verify_timestamp_token` exactly as it would a live token. Covers:
  successful round-trip (incl. request Content-Type and digest/nonce
  echo), token over the wrong digest rejected
  (`message_imprint_mismatch`), non-200 (500) handled, rejection
  status (2) handled. No live-network test in the suite; CI stays
  offline.
- **Claims gate:** 33/33, unchanged — no live round-trip is claimed,
  `qualified` stays `"unknown"`. No evidence artifact was produced
  (nothing succeeded to record).

## Verification record — Phase 5, U2-leftovers merged (2026-11-08)

Both U2 release-gate gaps are closed as far as this VM can close
them. Detail: `hidden_files/phase5-u2-leftovers.md`.

- **not_reproducible (merged `a384ec1`):** case-file v4 is the
  default seal; per-observation determinism is declared at seal
  time and a mismatch on a declared non-deterministic detector
  reports `not_reproducible` (inconclusive, exit 2) instead of
  failing as tampering; deterministic/unknown mismatches still fail
  closed. Parent-verified on the branch: claims 33/33, pre-commit
  13/13, casefile tests 106 passed (incl. all 29 new v4 tests).
- **Live-TSA interop (merged `bc2190b`):** still blocked from this
  VM — freetsa and DigiCert `/tsr` POSTs time out on read at 10 s
  while homepage GETs succeed, the same pattern as U2. The client
  path is proven against a stdlib mock TSA (4 new tests), and the
  exact unrestricted-host re-attempt procedure is in
  `docs/TSA_INTEROP.md`. Parent-verified on the rebased branch:
  claims 33/33, pre-commit 13/13 (exit 0; an earlier "12" count was
  a grep artifact of the schema-validator hook's verbose output),
  mock+timestamp+schema tests 49 passed. The rebase conflicted only
  on this file (both branches appended a section); the parent kept
  both sections, in order.
- Full extras suite on the merged tree: **3060 passed / 0 failed**
  (1 deselected flake; 3026 + 30 v4 tests + 4 mock-TSA tests).

## Phase 5 — RAID humans-100 + human-FPR evidence (merged 2026-11-08, apply `bce1e90`)

- **RAID humans past 100 (merged `ef6bfc7`):** new n=6000 sample, 171 human /
  5829 AI, AUROC 0.5958 [0.5621, 0.6314], native FPR 0.0. First `supported`
  validation record (`evr-20261108-raid-builtin-heuristic`, all 8 conditions
  verified from the code). Parent-verified on the branch: claims 33/33,
  pre-commit 13/13, 203 tests passed.
- **Human-FPR evidence (merged `802a61e`):** per-slice Wilson 95% FPR uppers
  (all k_fp = 0); worst document slice OpAI-Bench 20261106, 0.0642 (n=56,
  fails the n>=100 + upper<=0.05 bar); pooled docs 0/1002, upper 0.0038.
  GhostWriter max human score 0.6740, 0.006 below the 0.68 threshold.
  Parent-verified on the branch: claims 33/33, pre-commit 13/13, 12 tests.
- **Wave-2 Phase-1 kill tests (merged `4817971`, `6dc777c`, `8569e3f`):**
  detectors 181 tests, analyzers 15, engine 46 — tests only, no baseline
  changes. Parent-verified on each branch: claims 33/33, pre-commit 13/13.
- **Parent registry apply (commit `bce1e90`, pushed):** validation registry
  7 -> 8 records (RAID record inserted, all 7 Wilson CI replacements
  applied, every touched record re-signed, registry id recomputed,
  RAID still `supported`); evidence registry 30 -> 31 records (RAID run
  artifact pinned). The FPR artifact is NOT pinned — it fails run-artifact/v1
  (6 errors) and pinning it would fail the claims gate; it stays a standalone
  artifact in `docs/evidence/` and the report-card lead stays "unknown".
  The committed-registry test was updated seven -> eight records (RAID
  20261108 `supported`, rest `partial`). Verified on the applied tree:
  claims 33/33, pre-commit 13/13, schemas OK, validation/RAID/FPR tests
  115/115.

## Verification record — Phase 5, pip-audit failing gate (2026-11-08)

pip-audit is now a failing gate with an explicit per-finding
baseline, modelled on the mutation gate. `supply-chain.yml` is the
single owner (one `pip-audit-gate` job: push to `main`, PRs touching
dependency files, weekly Monday 04:23 UTC); the two duplicate
zero-tolerance jobs (`pip-audit --path . || exit 1`) and the
never-failing `dependency-audit.yml` job are deleted.
`enterprise-deep-verification.yml` keeps its own weekly
zero-tolerance audit of the frozen requirements file, which
`pip freeze` builds without pip itself, so it does not conflict
with the baselined installer findings.

- **Gate (`scripts/check_pip_audit.py`, stdlib + pip-audit only):**
  runs pip-audit against the installed environment **and**
  `requirements-pinned.txt`, deduplicates repeat reports of the
  same vulnerability on (package, version, vuln id), and matches
  every finding against `pip-audit-baseline.toml`. Exit 0: every
  finding baselined. Exit 2: a new finding (new package, new
  vulnerability id, or new affected version — a different version
  of a known vuln is new). Exit 1: configuration error, or a
  still-present finding past its baseline `review_by` date.
  Dormant entries (finding fixed) are reported, not failed.
  No blanket ignores, no `--ignore` flags, no severity
  downgrades. A `--report` JSON summary is uploaded as a CI
  artifact.
- **Baseline (`pip-audit-baseline.toml`):** 6 entries, all pip
  24.0 — the dev-venv installer, not a shipped dependency — each
  with aliases (id-or-alias matching, so a future report under a
  GHSA id still matches), exact affected versions, fix version,
  reason, and review date 2027-02-06.
- **setuptools cap widened `<80` → `<85`** (`pyproject.toml`,
  `requirements-pinned.txt`, `engineering.toml` S06): the `<80`
  cap forced the vulnerable 79.x line. The pinned audit had
  reported 3 findings in setuptools 79.0.1 (PYSEC-2026-3447 ×2,
  fixed in 83.0.0; GHSA-xmj3-9gf7-h52w, fixed in 84.1.0). The
  cap was widened instead of baselining a fixable build-backend
  vulnerability — the same call as Dependabot #27 for
  cryptography. The installed setuptools is already 84.2.1.
- **Live proofs (worktree venv, pip 24.0, pip-audit 2.10.1):**
  clean run exits 0 — installed env 12 raw / 6 unique findings,
  all baselined; pinned audit 0 findings. Planted new finding
  (temporary requirements file pinning `cryptography==42.0.8`,
  never a real pin) exits 2 with 7 unique new findings.
  Comparison logic is unit-tested in
  `tests/test_pip_audit_gate.py` (13 tests: dedupe, alias
  matching, new-version-is-new, dormant, expiry, baseline
  validation, CLI exit codes, report).
- **Claim:** `security.pip_audit_tracked` restated for the gate
  and re-seeded from a real run (`EV-20261108-pip-audit`,
  run_date 2026-11-08, code_version `51c7d26`, sha256
  `537fbdaa4fc6…`; registry rebuilt, 31 records): 12 findings,
  pip 12, cryptography 0, pytest 0. The new record's installed
  package set differs from the old venv's by 5 packages with 0
  findings each (absent now: opentelemetry-sdk /
  opentelemetry-exporter-prometheus /
  opentelemetry-semantic-conventions / prometheus-client /
  py-cpuinfo; present now: atheris, wheel) — venv-build drift,
  not a finding change.
- **Pre-commit blind spot found by this wave:** `pre-commit run
  --all-files` silently skips untracked files — it reported
  13/13 while the new gate script carried an F541 f-string error
  and two files were unformatted; only the claims gate's
  `ruff check src/ tests/ scripts/` caught it. New files must be
  covered (`git add -N` the new paths, or run ruff check +
  format `--check` on the paths directly) before claiming
  pre-commit green. Fixed here: F541 removed, both files
  formatted, pre-commit re-run 13/13 with the new files
  intent-to-add staged.

### Full verification (this branch, before commit)
- Claims gate: **33 passed / 0 failed** (`scripts/check_claims.py`,
  exit 0; report card regenerated to 33/33, including the restated
  `security.pip_audit_tracked` against `EV-20261108-pip-audit`).
- Schemas: **12 OK** (`scripts/validate_schemas.py`, exit 0).
- Pre-commit: **13/13** (`pre-commit run --all-files`, exit 0) —
  after the blind-spot fix (new files intent-to-add staged so the
  hooks actually cover them) and the direct `ruff check` +
  `ruff format --check` runs on the new files.
- Gate proofs re-run on the final tree: clean run exit 0
  (installed env 12 raw / 6 unique, all baselined; pinned audit 0);
  planted `cryptography==42.0.8` exit 2 with 7 new unique findings.
- Full suite: **3243 passed, 5 failed, 1 deselected, 904
  subtests passed** in 2:09:57 (single invocation, `pytest
  tests/ -q -p no:cacheprovider`, test_memory_check deselected
  as the known flake, `tests/fuzz` ignored). The 5 failures are
  all one self-inflicted invocation artifact, not a code
  defect: the `SchemaCLITests` invoke the `textforensics`
  console script as a subprocess, and this run was started via
  `.venv/bin/python` without the venv `bin/` dir on `PATH`, so
  the executable was not found (`FileNotFoundError`). Re-run of
  exactly those 5 tests with `PATH=$PWD/.venv/bin:$PATH`:
  **5 passed in 19.97 s** — so effectively 3248 passed / 0
  failed. Lesson (same class as the pre-commit blind spot
  above): always export the venv `bin/` dir onto `PATH` before
  running pytest, as the sibling waves do. The first full-suite
  attempt (run 1) was killed by a VM reboot at ~11:50 UTC after
  100 min (68%, 1 failure: a test_datasets.py stall-server
  timing flake under full sibling load, passing 100/100
  standalone); run 2 above is the complete run and the datasets
  flake did not recur.

## Verification record — Phase 5, release gate: checked-in reproducible SBOM (2026-11-08)

Decision (rescope): a checked-in SBOM is needed. The three existing SBOMs
are all expiring CI artifacts, never compared against anything: the
container SBOM (container.yml, CycloneDX, verified live — run 42431729810
on main head `a384ec1`, SUCCESS, artifact
`textforensics-sbom-0.2.0-a384ec1a225882e148b53d2a83619f72e8d7f8b0`,
5,100 bytes, unexpired) only builds on container-path changes, weekly
Sunday 03:00 UTC, or manual dispatch — a change to
`requirements-pinned.txt` alone does not trigger it; the supply-chain
SBOM is syft JSON, not an interchange format; the release SBOM exists
only on a manual release. The checked-in SBOM makes dependency changes
reviewable in the diff and lets the gate fail on every push.

- **Generator:** `scripts/generate_sbom.py` (stdlib only, no new
  dependency), CycloneDX 1.6 JSON at `sbom/textforensics.cdx.json`:
  123 components — the resolved dependency closure of
  `requirements-pinned.txt` as installed (`pip install -r
  requirements-pinned.txt`). `pip` is a genuine transitive dependency
  (`pip-audit` → `pip-api` → `pip`); `setuptools`/`wheel` are direct
  pins. No `metadata.timestamp` (optional in CycloneDX) and no embedded
  source-commit field (it would make every commit stale by construction);
  provenance is the git history of the SBOM file. `serialNumber` is a
  deterministic UUIDv5 of the content hash.
  `cyclonedx-python-lib` 11.12.0 is used only as a cross-check in tests
  (`Bom.from_json(...).validate()`), not as a generation input.
- **Reproducibility proof:** generator run twice from the same install,
  `diff sbom/textforensics.cdx.json /tmp/sbom-run2.cdx.json` → identical.
- **Staleness proof:** `--check` exits 0 when fresh; after deliberately
  changing one component version in the committed file it exits 1 and
  prints a unified diff; restoring the file returns exit 0.
- **CI:** new `sbom` job in `ci.yml` (installs `-r
  requirements-pinned.txt`, runs `python scripts/generate_sbom.py
  --check`); `release.yml`, `supply-chain.yml` and `container.yml`
  untouched. `anchore/sbom-action@v0` remains UNPINNED in those three
  workflows — pinning belongs to the cosign worker, flagged in
  `docs/QUALITY_GATES.md`, not changed here.
- **Wheel/sdist:** a built wheel and sdist contain no `sbom/` entry
  (the only substring match is `tests/test_generate_sbom.py` in the
  sdist), so the SBOM stays out of the shipped artifacts.
- **Docs:** `docs/QUALITY_GATES.md` gained gate item 91 plus a full
  SBOM section (four-SBOM table: format, scope, home, retention, and
  what "stale" means for each). Also flagged there, pre-existing:
  `enterprise-deep-verification.yml` runs `cyclonedx-bom -r
  requirements.txt`, but no `requirements.txt` exists and the step ends
  in `|| true`, so it silently produces nothing.
- **Tests:** 11 new tests in `tests/test_generate_sbom.py`, all passing
  (synthetic-repo determinism, serial-number sensitivity, unresolved
  handling, `--check` pass/fail, cyclonedx-lib validation, real-repo
  generation).
- **Claims gate:** 33/33 ("All claims verified", exit 0). First run was
  32/33: `ruff_lint_clean` failed on SIM401 in the new script
  (`metadata["Name"] if "Name" in metadata else None` → `.get`), which
  the pre-commit run had missed because `pre-commit run --all-files`
  only covers tracked files and the new files were still untracked —
  fixed the line, applied `ruff format`, re-ran the gate green. The
  first pre-commit run also failed its local hooks with "Executable
  `python` not found" until `.venv/bin` was put on PATH; after `git add`
  the re-run covers the new files (see below).
- **Schemas:** 12 OK.
- **Pre-commit:** 13/13 passed on the final staged tree (re-run after
  `git add`, so the new files are covered). Two things the first run
  taught: (a) `pre-commit run --all-files` only covers tracked files,
  so new files must be staged first — the unstaged run missed a SIM401
  in the new script that the claims gate then caught; (b) the SBOM's two
  SHA-256 property values are flagged by `detect-secrets` as Hex High
  Entropy Strings — they are recorded as audited false positives in
  `.secrets.baseline` (surgical +16-line addition only; a blanket
  `detect-secrets scan --baseline` was tried and reverted because it
  rewrote the whole baseline, +91/−226 lines). A first `git add` +
  pre-commit run failed only on detect-secrets; after the baseline
  entries were added it passed 13/13 with no file modifications. The
  local hooks also need `.venv/bin` on PATH (`python` is otherwise not
  found).
- **Full suite:** **3364 passed, 904 subtests passed, 6 failed** in
  7872.37 s (2:11:12) — full log `~/workspace/fullsuite-sbom.log`.
  All 6 failures are explained, none is caused by this change:
  `test_memory_check` is the known flake (passes in isolation,
  re-verified: 1 passed in 2.46 s); the 5 `SchemaCLITests` failures
  were `FileNotFoundError` because the suite was run without
  `.venv/bin` on PATH, so the `textforensics` console script they
  shell out to was not found — re-run with the correct PATH: **5
  passed in 17.74 s**. (The first full-suite attempt was killed by a
  VM reboot at ~17.5 CPU-min with no surviving output; the rerun above
  is the recorded one. The run is slow because the box is shared with
  several parallel suites plus a live cosmic-ray run; the suite stalls
  longest in `test_mutation.py`'s 787-entry baseline validation, which
  this change does not touch.)

## Verification record — Phase 5, mutation-survivors kind wave: two new baseline kinds (2026-11-08)

Wave-1 full sessions on the three safety-critical modules left 100
unexplained survivors (benchmark 27, consensus 11, calibration 62).
All 100 were hand-verified as equivalent mutants, split across two new
narrow baseline kinds approved by the parent:

- **`"domain-equivalent"` (94 entries):** the mutant changes a value
  or operator whose two versions are provably identical on the
  function's actual domain (e.g. a comparison whose operands can never
  cross the mutated boundary). Each entry carries a hand-applied-mutant
  differential probe (a grid of inputs run under both versions, SHA-256
  compared, 0 diffs) plus the module tests under both versions.
- **`"ulp-equivalent"` (6 entries, calibration only):** the mutant
  changes a floating-point result by at most a measured number of
  ULPs. Each entry records `ulp_bound_ulps` (a non-negative int) and
  the `swept_domain` it was measured over. The bounds are MEASURED
  MAXIMA — 2, 3, 0, 3, 1, 1 — not the blanket "≤2 ULPs" the wave-1
  header claimed; two entries refuted ≤2 on re-run. The bound-0 fix in
  the same wave relaxed the validator from positive to non-negative
  (`GtE_Gt:0` measured 0, bit-identical on 1,150,004 points), and a
  vacuous-test bug (literal `\n` escapes in TOML test cases) was fixed.

Runner fix in the same wave: a record is now treated as incompetent
when `test_outcome` is `"incompetent"`, with a unit test; the
calibration prefix proof was re-run to show error 0.

- **Proofs (all exit 0, 0 unexplained):** benchmark 909 total / 713
  killed / 196 surviving / 196 equivalent (error 0); consensus 792 /
  653 / 139 / 139 (error 0); calibration 1937 / 1539 / 397 / 397
  (error 0, incompetent 1).
- **Baseline:** 787 → **887** (arg 656, return 107, domain-equivalent
  94, unobservable-value 19, ulp-equivalent 6, unreachable-condition 5;
  runtime 124; modules trust 73, policy 82, benchmark 196, consensus
  139, calibration 397).
- **Merges (main `a966ac2`):** kinds `5427284`, benchmark `2f6cde7`,
  consensus `cb340dd`, calibration `a966ac2`. Parent verification per
  branch: claims 33/33, schemas OK, pre-commit 13/13, kind tests and
  count tests passed.
- **Parent incidents, owned:** (a) the consensus and calibration
  branches both added `test_domain_equivalent_mutants_accepted`, so the
  merge produced a duplicate definition (ruff F811) — replaced with one
  union test; (b) the parent merged `cb340dd` (the union-test commit)
  instead of the ruff-format fix commit on top of it, so main briefly
  carried an unformatted line, fixed as a side effect by the
  calibration merge. Lesson: merge the branch HEAD, never an earlier
  hash.

## Verification record — Phase 5, Core 3.11 stall fix: per-module AST cache (2026-11-08)

CI on main `2e28466` cancelled all five Core jobs at the 15-minute
timeout; raising it to 30 minutes (`0d9d2d1`) left 3.11 cancelled at
30m19s, and a 3.11-specific 45 minutes (`380353a`) also failed (run
42503380894, cancelled 45m18s). The 3.11 log ends after 2561 progress
chars (71.0% of 3605 tests); the 30-minute run reached the identical
2561 chars — a stall, not linear slowness. The stall point is test
2562, `test_dormant_and_superseded_reported`, which calls
`parse_results` → `classify_baseline`, re-validating all baseline
entries with one full `ast.parse` per entry plus a whole-module walk
calling `ast.get_source_segment` per annotation, no caching.

- **Fix (merged `ad15419`, main `dd8bd83`):** per-module
  `_ModuleContext` cache in `scripts/run_mutation.py` (parse +
  annotation spans + function table + fingerprints, keyed by
  path/mtime/size; an edited file is re-parsed, never stale).
  `validate_baseline_entry`'s signature is unchanged; the two
  `_validate_*_entry` helpers take the context.
- **Measured on the same CPython 3.11.18 venv:** test 2562 alone
  599.92 s timeout → **3.53 s**. Full `tests/test_mutation.py` on
  3.12: **54 passed / 1051 subtests in 9.91 s** (was ~35 min CPU).
  On 3.11: 46 passed / 8 env failures (4 need PyYAML, 3 need
  cosmic-ray — neither in the minimal 3.11 venv) / 1051 subtests in
  25.56 s.
- **Real bug found by the 3.11 full-file run:** the calibration merge
  had raised the domain-equivalent count to 94 but
  `test_domain_equivalent_mutants_accepted` still asserted 38 — fixed
  as a separate commit `dd8bd83`. Lesson: after a merge, run the FULL
  affected test file on the merged tree, not only the tests the merge
  touched.
- **CI consequence:** CI on `dd8bd83` is SUCCESS (run 42528702649),
  and CI on the later head `a1e7857` is SUCCESS with Core 3.11 green
  (see the Phase-2 section below). No timeout change was made.

## Verification record — Phase 5, mutation-survivors wave 2 Phase 2: detectors / analyzers / engine baselines (2026-11-09)

Phase 1 measured full sessions for detectors (606), analyzers (516)
and engine (322) and added kill tests only. Phase 2 baselined the
survivors. Each worker re-ran its module's full session on `dd8bd83`
as the proof (Phase-1 dumps were in deleted worktrees); every survivor
set reproduced the Phase-1 list position-for-position before
baselining; each domain entry carries a hand-applied-mutant
differential probe.

| Module | Entries added | Proof (total/killed/surviving/equivalent/unexplained) |
|---|---|---|
| detectors | 66 annotation + 1 domain | 606 / 539 / 67 / 67 / 0, exit 0 |
| analyzers | 4 domain | 516 / 512 / 4 / 4 / 0, exit 0 |
| engine | 4 unobservable + 1 domain | 322 / 317 / 5 / 5 / 0, exit 0 |

- **Baseline:** 887 → **963** (arg 678, return 140, annassign 11,
  domain-equivalent 100, unobservable-value 23, unreachable-condition
  5, ulp-equivalent 6; runtime 134; modules trust 73, policy 82,
  benchmark 196, consensus 139, calibration 397, detectors 67,
  analyzers 4, engine 5).
- **Merges (main `a1e7857`):** detectors `6e7d3f2`, analyzers
  `12c1dc6`, engine `a1e7857` (the engine merge includes a parent fix
  commit for the runtime count, see below). Parent verification per
  branch and on merged main: claims 33/33, schemas OK, pre-commit
  13/13, full `tests/test_mutation.py` 55 passed / 1137 subtests in
  ~10 s on each rebased tree and on merged main.
- **Detectors correction (worker, verified by the coordinator):** the
  domain entry's `source_text` is `"is not"`, not `"is not None"` as
  briefed — the dump span is [260,75]–[260,81]. The test asserts
  `"is not"`.
- **Parent incidents, owned:** (a) the analyzers rebase first used
  `origin/main`, which had not yet received the detectors merge push —
  it reported "up to date" and changed nothing; rebased onto local
  `main`. (b) A resolution script keyed two conflicts on the same
  first line and broke the cache test's `try` block (SyntaxError) —
  key on the full line including indentation. (c) Same-number trap,
  twice: the cache module count (both sides wrote 6, union needs 7,
  then 7 vs 6 → 8) and the runtime count (both sides wrote 129, union
  needs 134) merged cleanly because the two sides AGREED — both were
  caught only by running the full test file on the rebased branch.
  Standing lesson: after a union merge, re-derive EVERY count from the
  resolved baseline, including counts that did NOT conflict.
- **CI on the merged head `a1e7857` (run 42533532099): SUCCESS — all
  19 jobs green**, including Core Python 3.11 / 3.12 / 3.13 / 3.14 /
  3.15, the claims-to-evidence gate, the checked-in SBOM staleness
  job, and all OS smokes. Core 3.11 is green after the cache fix
  above; CI on `dd8bd83` was also SUCCESS.
- **Full verification at HEAD `a1e7857` (2026-11-09, bare core-only
  venv `~/workspace/.tfc-core-venv`, Python 3.12.3, `pip install -e
  ".[dev]"`, venv `bin/` first on PATH): 3513 passed, 121 skipped, 1
  deselected (the known `test_memory_check` host flake), 1209 subtests
  passed in 291.25 s, coverage 76.95% (gate 70% passed). The 121 skips
  are all core-only-venv environment artifacts (51 fastapi not
  installed, 22 API dev deps, 20 web_ui, 15 MCP dev deps, 7 API deps,
  2 uvicorn, 1 full-pinned-install check, 1 cyclonedx) — the extras
  surface is not installed in a core-only venv by design. The
  extras-venv full suite on the same head: **3633 passed, 1 skipped,
  1 deselected, 1209 subtests passed in 347.69 s, 81% line coverage**
  (18,020 statements, 2,936 missed, 6,830 branches, 1,073 partial),
  exit 0, 0 failures; the single skip is the SBOM
  full-pinned-install check (atheris/wheel not in the main venv).
- **Manual end-to-end checks (2026-11-09, main venv, HEAD
  `a1e7857`):** `textforensics scan` on a 29-word human-like text
  scores 0.2947 (`insufficient_evidence` — honest abstention on short
  text); on a 35-word machine-like text 0.6697
  (`insufficient_evidence`, just below the 0.68 `ai_like` threshold),
  sane direction. Case-file round-trip: `case keygen` creates a
  0600 key file; `case export --seal` produces the bundle; the
  standalone stdlib verifier in the bundle exits 2 without a public
  key and 0 with the correct public key (signature verified, key
  fingerprint matches).
- **Still open (wave 2):** casefile only. Its full session (2118
  items) is running under the monitor cron; 1408/2118 at resume
  00:08 CET 2026-11-09, integrity ok.

## Verification record — Phase 5, release-gate follow-ups: VERIFICATION.md coverage-gate correction (2026-11-09)

- **What was wrong:** the "Current state" header still referenced
  HEAD `a1e7857`, and its open-items list said the coverage gate was
  "still `--fail-under=70` in CI, not yet raised to the measured
  ~81%". Both halves were wrong after the release-gate wave (main
  `e65fde9`): the gate is `--fail-under=75` (`ci.yml:70`), and the
  ~81% is the extras-venv coverage — CI installs `.[dev]` only and
  measures core-only coverage. The same list also still carried the
  11 unpinned action refs and the silent SBOM step (both fixed in
  the wave) and a stale casefile count (1605/2118 at 00:23 CET,
  contradicted by the verified counts).
- **Correction (this change):** "Current state" now references HEAD
  `e65fde9`; the full-suite line is the parent-measured extras run
  on `e65fde9` (3893 passed, 1 skipped, 1 deselected, 1209 subtests
  in 194.80 s); the open-items list drops the pinned refs and the
  fixed SBOM step, adds the two remaining gate inconsistencies
  (`engineering.toml` `--cov-fail-under=80`,
  `enterprise-deep-verification.yml:107` `--fail-under=95`) and the
  bare `pip-audit` / `bandit` step, and gives the casefile proof as
  1355/2118 at ~15:59 CET 2026-11-09 under its diagnostic resume.
- **Core-only re-measurement on `e65fde9` (2026-11-09, bare
  core-only venv `~/workspace/.tfc-core-venv`, Python 3.12.3, `pip
  install -e ".[dev]"`, venv `bin/` first on PATH,
  `PYTHONPATH=<worktree>/src`): 3774 passed, 0 failed, 121 skipped,
  0 deselected, 1209
  subtests passed in 644.20 s, coverage 78.49%** (18,038 statements,
  3,454 missed, 6,834 branches, 946 partial; gate 75% passed). The
  121 skips break down exactly as on `a1e7857` (51 fastapi, 22 API
  dev deps, 20 web_ui, 15 MCP dev deps, 7 API deps, 2 uvicorn, 1
  full-pinned-install check, 1 cyclonedx). The `test_memory_check`
  host-flake test ran and passed in this run (0 deselected — the
  deselect string used, `TestDiagnostics::test_memory_check`,
  matched nothing; the correct class is `TestDiagnosticsEngine`). A first attempt without
  the venv `bin/` on PATH failed 5 `test_schema.py` CLI tests with
  `FileNotFoundError: 'textforensics'` (the console script was not
  resolvable) and measured 78.47% — a harness artifact, not a repo
  regression; the clean re-run with `bin/` first on PATH is
  0-failed and is the cited measurement. CI on `e65fde9` (run
  42639520382) is SUCCESS, all 19 jobs green.
- **Gates on this branch:** claims 33/33, schemas 12 OK,
  pre-commit 13/13 (run with the main venv `bin/` first on PATH;
  without it the hooks fail with "Executable `python` not found",
  since this machine has `python3` only).
- **Still open:** casefile Phase-2 proof (1355/2118, diagnostic
  resume), live-TSA interop, the two `--fail-under` inconsistencies
  above, the bare `pip-audit` / `bandit` step, and the policy
  session's 298 unexecuted work items.

## Verification record — Phase 5, full verification on HEAD `fb1e23a` (2026-11-09)

- **Measured on:** `fb1e23a` (branch `fix/verification-fb1e23a`,
  worktree `~/workspace/TextForensics-verify-fb1e23a`), Python
  3.12.3, main venv `~/workspace/TextForensics-rewrite/.venv` for
  the extras suite and a fresh bare core-only venv for the core
  suite. Evidence logs in the goal hidden_files:
  `full-verification-fb1e23a-extras.log`,
  `full-verification-fb1e23a-core.log`,
  `full-verification-fb1e23a-claims.log`,
  `full-verification-fb1e23a-schemas.log`,
  `full-verification-fb1e23a-precommit.log`,
  `full-verification-fb1e23a-manual.txt`.
- **Extras suite:** 3933 passed, 0 failed, 1 skipped, 1 deselected,
  1985 subtests passed in 464.80 s (7:44), coverage 81% (18,038
  statements, 2,903 missed, 6,834 branches, 969 partial). The 1
  skip is the SBOM full-pinned-install check (atheris/wheel not in
  the main venv); the 1 deselected is the known `test_memory_check`
  host flake. The first attempt died at ~39% in a VM reboot; the
  cited run is a clean full re-run. An independent re-measurement
  reproduced this figure exactly (3933/1/1, 1985 subtests, 270.41 s,
  identical per-module table).
- **Core-only suite:** 3813 passed, 0 failed, 121 skipped, 1
  deselected in 409.00 s, coverage 78% (18,038 statements, 3,455
  missed, 6,834 branches, 946 partial; gate 75% passed). The 121
  skips are all core-only-venv environment artifacts (fastapi /
  API dev deps / web_ui / MCP dev deps / API deps / uvicorn / the
  full-pinned-install check / cyclonedx).
- **Coverage correction — the original core log's 82% was wrong:**
  the original core log reported 82% (2,795 missed). That figure
  did NOT reproduce: an independent re-measurement in a fresh bare
  venv (`~/.tfc-core-venv-workerA`, Python 3.12.3, `pip install -e
  ".[dev]"`, venv `bin/` first on PATH, `pytest
  --cov=textforensics` + the same deselect) measured 3813 passed,
  121 skipped, 1 deselected in 260.86 s with TOTAL 18,038 / 3,455
  / 6,834 / 946 = 78% (78.49% at 2 dp). Four independent clean
  core measurements give 3,454–3,456 missed (this re-measurement
  3,455; a concurrent repro 3,456; an earlier core run preserved
  in the main repo's `.coverage` 3,455; `e65fde9` 3,454) — the
  2,795 figure is the lone outlier. (Provenance caveat: the main
  repo's `.coverage` file is dated 16:29 CET, before `fb1e23a`
  was pushed at ~19:24 CET, and records no commit — only its
  3,455-missed count is verified, not that it measured
  `fb1e23a`.) Nearly the entire discrepancy was one file:
  `_standalone_verify.py` showed 61% covered (354 missed) in the
  original core data file but 0% (1,011 missed) in every
  reproducible run — 657 of the 660-line gap (2,795 → 3,455
  missed). The other 3 lines are one-line flips in
  `diagnostics.py` (11 → 12 missed), `evidence.py` (217 → 218),
  and `timestamp.py` (103 → 104). (For comparison, core vs
  extras differs by 552 missed lines, as expected for the 121
  skipped extras tests: web_ui +394, api +84, mcp +71, cli +3,
  evidence +2, ed25519 −2.) How the 657 traced lines got into
  that one data file was
  NOT established — the venv, the coverage entry point (`coverage
  run` vs pytest-cov), concurrent execution, import style, and
  tool versions were each tested and none reproduced it — so the
  82% figure is recorded as unverified, not as evidence of
  anything about the new kill tests' coverage. The correct figures
  are core-only 78% and extras 81%; core does not exceed extras.
  The original core run's slower time (409.00 s vs 260.86 s
  sequential) is consistent with it having run concurrently with
  the extras suite, but concurrency did not reproduce the 657-line
  difference. Evidence:
  `core-coverage-remeasure-workera.log`,
  `extras-coverage-remeasure-workera.log`,
  `core-coverage-repro-workera.log`,
  `extras-coverage-repro-workera.log` (+ matching `.coverage-*`
  data files) in the goal hidden_files.
- **Coverage correction, mechanism established (2026-11-10):** the
  657 traced lines are now explained. Executing the
  standalone-verifier tests through a normal import of
  `textforensics._standalone_verify` (instead of the suite's
  `importlib.spec_from_file_location` + `exec_module` loader),
  plus the v4 tampered-observations tests, reproduces the 61% /
  354-missed row exactly — the missing-lines list is byte-identical
  (1,120 chars) to the original core log line 167. Merging those
  arcs into a clean core run (`coverage combine`) reproduces TOTAL
  18,038 / 2,796 / 1,077 / 82.12%, one line off the original 2,795 /
  1,076 (the `diagnostics.py:418` live-memory flip); the
  `--cov-append` merge channel was also proven to work. The suite's
  own importlib path records zero arcs in every configuration
  tested, and no repo code normally imports the module. What remains
  unrecoverable is which exact command in the original 2026-11-09
  session produced the traced arcs — the original data file was
  never preserved and the log records no command or environment.
  The 82% figure is therefore explained as merged traced arcs, but
  it was never a valid core-only measurement and stays recorded as
  unverified as a core figure. Correct core coverage is 78.49%
  (3,455 missed at `fb1e23a`); five independent clean core
  measurements now cluster at 3,453–3,456 missed (78.48–78.50%).
  Evidence: `coverage-artifact-a.md`, `coverage-artifact-b.md`,
  `coverage-artifact-c.md` (+ `.coverage` data files and logs) in
  the goal hidden_files.
- **Gates on this branch (re-run by the coordinator):** claims
  33/33 ("All claims verified"), schemas 12 OK, pre-commit 13/13.
- **Manual end-to-end checks:** `textforensics scan` on a 35-word
  human-like text → score 0.3446 `insufficient_evidence`
  (confidence 0.1089); on a 35-word machine-like text → 0.6686
  `insufficient_evidence` (confidence 0.1221), sane direction
  (machine-like > human-like, both honestly abstaining below the
  80-word minimum). Case-file round-trip: `case keygen` creates a
  0600 JSON key file; `case export --seal --signing-key` produces
  case.json (case-file/v4, raw_text_included false) + the sealed
  zip with the bundled stdlib verifier; the standalone verifier
  exits 2 without a public key (signature present, origin not
  authenticated) and 0 with the correct key (signature verified,
  key fingerprint matches the keyid).
- **CI on `fb1e23a`:** the six workflow runs concluding "failure"
  are a GitHub platform incident artifact (incident `tp8cghg7tlc4`,
  "Incident with Actions and Checks API", 2026-11-09
  18:12:37–18:59:32Z): 14 job records were lost at scheduling time
  (CI lost 6 legs, Reproducibility 4 of 5, CodeQL its only job),
  and the affected runs were finalized as failure even though every
  job that ran succeeded — 22 check-runs: 20 success, 2 skipped
  (Full Mutation, DeepSource), 0 failure. CodeQL re-run (attempt 2)
  succeeded 20:35:39Z; the other five runs were not re-run (the
  incident is established, and current main's CI is the live
  confirmation). No repo-side fix is needed. Full investigation:
  `phase5-ci-caveat-investigation.md` in the goal hidden_files.
  The separate 54c1e25 Core Python 3.12 failure was a single test,
  `test_mid_body_drop_resumes_with_range` (requests_seen 1 != 2) —
  a BrokenPipeError loopback socket race in the test/fixture's
  exact request-count assert, not in `download_large_file` (the
  file was complete after a single request). It passed on all
  other Pythons on the same commit and passes on `fb1e23a`.
  Follow-up: harden that test against the socket race.
- **CI on current main `21ff98e` (run 42694796649, completed):**
  concludes "failure" — solely the "Checked-in SBOM is not stale"
  job (filelock 4.2.9 → 4.2.10, typer 0.28.0 → 0.29.0 upstream
  releases; `requirements-pinned.txt` pins typer as a range
  `typer>=0.12,<1`, so a fresh install picks up new releases; the
  committed SBOM needs regeneration + commit). All 5 Core jobs
  green, claims gate green, all OS smokes green; the other 9
  workflow runs on `21ff98e` are success. This is not a `fb1e23a`
  issue (the SBOM job passed on `fb1e23a` at 18:24Z) and not an
  incident artifact (the incident resolved 18:59:32Z; this run
  started 20:37:52Z).
- **Release-ready? NO — not called release-ready.** The suites,
  gates, and proofs on `fb1e23a` are all green, but: the SBOM
  staleness job fails on current main `21ff98e` (needs a
  regeneration + commit); live-TSA interop was never achieved from
  this VM; PAN 2025 registration is unconfirmed; the worst-slice
  human FPR is still unknown. No release is created by this change.
  [Superseded in part: the SBOM was regenerated
  (`96f3032`/`bfb2097`) and the staleness job passes on current main
  `8c8a1cf` — see Current state.]
- **Still open:** live-TSA interop, PAN 2025, the socket-race test
  hardening, the SBOM regeneration on main. [Superseded in part:
  the hardening merged `8c8a1cf` and the SBOM was regenerated
  (`96f3032`/`bfb2097`) — see Current state.]
