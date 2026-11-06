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
