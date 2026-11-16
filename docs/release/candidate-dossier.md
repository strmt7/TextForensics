# TextForensics release candidate dossier (audit W10)

**Status:** candidate dossier, prepared by W10 worker D (branch
`audit-w10-d`). The W10 final gate verdicts are **not yet filled in**
— see §2, which carries explicit placeholders for the W10 coordinator
to complete during final verification. Nothing in this dossier
authorizes a release. **Greg decides release authorization; no
release, tag, container image, or other publication has been created
from this work, and none is created by this dossier.**

**Candidate identity (at dossier time):** staging branch `audit-w7`
at `9b148d4` ("W9 refresh: pre-commit formatting reflow in D
optional-deps test", verified and held as the W10 base), plus the
`audit-w10-d` branch work (this dossier; the privacy-gate W10 half;
the Dockerfile container lockfile — see §2.4 and §5). The final
candidate SHA is the `audit-w7` head **after** W10 integration, set by
the W10 coordinator — it is not `9b148d4` and it is not any
`audit-w10-d` head. `main` is at `7d2112c` and must not move until the
single clean merge after W10 verification (Greg's 2026-11-16
correction: W7–W10 stage on the single local integration branch
`audit-w7`, never pushed; the remote has only `main` at all times).

**How to read this dossier:** every number below traces to a wave
report in `goals/textforensics-complete-revamp/hidden_files/` or to a
committed run artifact cited by record ID. No benchmark number is
copied from external work. A score is not a probability. Human
false-positive rate is a release gate, and every serious claim is
sliced — see §4 for the honest reading, including the no-utility
result.

## 1. What the candidate is

TextForensics 0.2.0 (pre-1.0), a local-first AI-text detector
reliability and forensics layer: detector evidence + validation
coverage + stability/drift + provenance + reproducible case files.
Core has no mandatory third-party runtime dependencies; heavy
dependencies are optional extras (see §3). The candidate is the
product of the external audit of 2026-11-10 (91 numbered findings:
CORE 11, CRYPTO 23, INTERFACES 19, STATEFUL 22, ENGINEERING 16;
45 P1 / 46 P2; plan `docs/RELEASE_READINESS_PLAN.md`, waves W0–W10 in
strict order) plus the pre-audit revamp phases. W0–W6 are merged to
`main` (`7d2112c`); W7–W9 are verified and held on the staging branch
`audit-w7`; W10 is the release-assembly rehearsal without publication.

Wave reports (evidence of record for the numbers in §2):

| Wave | Head | Report |
| --- | --- | --- |
| W6 (merged) | main `7d2112c` | `hidden_files/audit-w6-report.md` |
| W7 (verified, held) | `17b8951` | `hidden_files/audit-w7-report.md` |
| W8 (verified, held) | `4374990` | `hidden_files/audit-w8-report.md` |
| W9 (verified, held) | `9b148d4` | `hidden_files/audit-w9-report.md` |
| W10 (this dossier) | TBD by coordinator | `hidden_files/audit-w10-d-report.md` |

## 2. Gate verdicts

<!-- W10-COORDINATOR: fill in final gate verdicts -->
<!-- The W10 final verification (fresh checkout of the exact integrated
     head, per CONTRIBUTING §2.6) has not run yet at dossier time.
     Replace the TBD cells in §2.1 with the measured results and delete
     this comment block only when every cell is filled. Do NOT fill a
     cell from a run on any other head, and do NOT mark a gate pass on
     a local-only run — CI confirmation is a separate row, not implied. -->

### 2.1 W10 final gates (TO BE FILLED BY THE W10 COORDINATOR)

| Gate | Result | Run ID / log |
| --- | --- | --- |
| Full suite (fresh checkout, exact head) | TBD — W10 coordinator | TBD |
| Claims (`scripts/check_claims.py`, 3 consecutive runs) | TBD — W10 coordinator | TBD |
| Schemas (`scripts/validate_schemas.py`) | TBD — W10 coordinator | TBD |
| Pre-commit (`pre-commit run --all-files`) | TBD — W10 coordinator | TBD |
| Mutation baseline re-derived (tomllib) + stale check | TBD — W10 coordinator | TBD |
| Rehearsal: typed asset manifest + no-publication promotion | TBD — W10 coordinator | TBD |
| Rehearsal: second clean verifier reproduces the unpublished asset set | TBD — W10 coordinator | TBD |
| Rehearsal: deliberately bad candidates rejected (removal / tampering / mismatched SHA / tag / version / missing confirmation / failed-skipped-stale required check) | TBD — W10 coordinator | TBD |
| Cosign positive path (mock-verified only through W9 — W10 rehearsal) | TBD — W10 coordinator | TBD |
| Report-card lead | `unknown` — W10 does not change it (see §4.3) | `docs/evidence/report-card.md` |
| CI on the merged head | TBD — CI has never run on the staging branch; first true check is CI after the final merge (see §5.1) | TBD |

### 2.2 W9 — end-to-end qualification (verified, head `9b148d4`)

| Gate | Result |
| --- | --- |
| Full suite (fresh checkout, exact head) | **7054 passed / 0 failed / 3 skipped / 8567 subtests** (729 s; workspace-disk basetemp/TMPDIR) |
| Claims | **33 passed, 0 failed** (3 consecutive runs, sequentially, /tmp clean) |
| Schemas | **13 OK** |
| Pre-commit | **13/13 Passed** |
| Baseline re-derived (tomllib) | **7010 / 7010 unique / 1336 positions / 46 modules / 0 stale**; `test_mutation.py` 65 passed / 8147 subtests; W4 twin occ 7 still absent |
| Report-card lead | **`unknown`** (unchanged) |
| Standalone verification, NO package installed | **PASS** — empty venv, embedded `verify.py` byte-identical to source, exit 0, **30/30 checks**, tampered → exit 1 |
| No-network core | **PASS** — fresh core-only venv in `unshare -n`; scan/report/case-verify exit 0; strace shows **zero** network syscalls |
| Installed wheel + sdist | **PASS** — reproducibility re-confirmed (two clean SDE-pinned builds byte-identical: wheel `f7f070fa…`, sdist `34809070…`); CLI/API/web/MCP flows pass in both installs; cross-surface score identical (`0.2954`, `human_like_patterns`, consensus `abstain`) |
| Workflows end to end | **All 9 PASS** (scan + report; remote selection/refusal; emergency stop 0.003 s, zero partial files; calibration held-out refusal + disjoint success; case T1/T2; custody successor; packing; installed verification; standalone verification) |
| Registry / drift / faults | **PASS** — validation 15 records / 8 supported (registry_id `3202e9a9…`); evidence 50 records, every artifact re-hashes to its recorded SHA-256; demotion/recovery, reload, cache/retry/health, bounded cancellation, recoverable restart (SIGKILL-mid-write leaves the registry loadable) |
| Container health | **PASS** — HEALTHCHECK assertions in `container.yml` acceptance steps; non-root/read-only posture confirmed; SBOM scans the locally loaded image; Dockerfile base pin verified live against Docker Hub |

Defects found by W9 qualification and fixed red-test-first on the
staging branch: bare-install console scripts failing the missing-extra
contract (`textforensics-web` raw `ModuleNotFoundError` traceback;
`textforensics-api` message preceded by a full chained traceback) and
`textforensics-web` ignoring `TEXTFORENSICS_PORT`/`HOST`; standalone
`verify.py --public-key` rejecting the tool's own keygen JSON
public-key file; five optional-dependency failure contracts
(web, api, diagnostics/psutil, ollama/aiohttp, `run_fuzz` atheris
guard). Baseline refresh: 243 stale entries re-anchored (A-fix +
B-fix rebase), 74/74 new live mutants killed, 0 appended; positions
1337 → 1336.

### 2.3 W8 — scientific qualification (verified, head `4374990`)

| Gate | Result |
| --- | --- |
| Full suite (fresh checkout, exact head) | **6973 passed / 0 failed / 3 skipped / 8557 subtests** (797 s) |
| Claims | **33 passed, 0 failed** (3 consecutive runs) |
| Schemas | **13 OK** |
| Pre-commit | **13/13 Passed** |
| Baseline re-derived | **7010 / 7010, 0 stale** — positions 1337, modules 46; W4 twin occ 7 still absent |
| Registry | validation **15 records, 8 supported** (registry_id `3202e9a9…`); evidence **50 records** |
| Aggregation | worst slice **0.5615** (MAGE testbed:dialogsum, 0/3); 90 slices n>0 (28 pass); 43 unmeasured |
| Report-card lead | **`unknown`** (0.5615 blocking reason) |
| Independent reproduction | **All AGREE** — Beemo 1318/1318, GhostWriter 879/879, OpAI-Bench 386/386, RAID 3519/3519 (+ second implementation 3521/3521), MAGE 3134/3134, DetectRL-X 2134/2134 (+ 37/37 identity checks), registry baseline 9/9 |
| Mutation proof | No new proof required — W8 changed no decision-logic code; baseline unchanged at 7010/0 stale |

### 2.4 W7 — security and supply-chain coverage (verified, head `17b8951`)

All 11 findings CLOSED (ENG-04/05/06/07/10/11/12/13/14/15/16) plus
the CC-18 mutation-proof extension to `dsse` + `ed25519` and the
privacy-gate W7 half.

| Gate | Result |
| --- | --- |
| Full suite (fresh checkout, exact head) | **6960 passed / 0 failed / 3 skipped / 8557 subtests** |
| Claims | **33 passed, 0 failed** (3 consecutive runs) |
| Schemas | **13 OK** |
| Pre-commit | **13/13 Passed** |
| Baseline re-derived | **7010 / 7010, 0 stale** — positions 1337, modules 46 (dsse 24, ed25519 49); W4 twin occ 7 still absent |
| SBOM `--check` (fresh canonical venv) | **passes — 122 components** (120 pins + 2 vendored) |
| Pip-audit gate | **PASSED, exit 0** — 6 baselined findings; installed 122 = 121 audited + 1 skipped + 0 unresolved; pinned 118 = 117 + 1 + 0 |
| Mutation proof | **0 unexplained** — proofset 1239 (dsse 216, ed25519 1023): 1156 exec-killed, 82 survived, 1 incompetent, 0 unexplained; baseline 6937 → 7010 (+73), 0 stale; 0 mismatches / 0 missing on cross-check |
| Alert inventory (fresh, paginated) | **299 alerts ever — 12 open, 287 fixed, 0 dismissed** |

The CC-18 "641 module-level live items" figure was retired in W7
(parent decision): it reproduces by neither method (AST: **321**,
sqlite: 303). The correct count is **321**. Do not quote 641.

### 2.5 W10 worker-D contributions (on `audit-w10-d`, part of this dossier)

| Item | Result |
| --- | --- |
| Candidate dossier | This file (`docs/release/candidate-dossier.md`) |
| Privacy gate, W10 half | Scan of candidate source archive, wheel/sdist, image contents (build context — no Docker daemon on the scan VM; the image itself could not be built there), and published evidence (`docs/evidence/`). Found 26 `actual-personal-path` occurrences beyond the known W0/W7 items (18 in three W8 registry-bound run artifacts, 8 hardcoded worker-checkout paths in five W8 reproduce scripts); **all resolved by forward fix, none by history rewrite** — see §6. No credentials, keys, or real user text found anywhere. Wheel: zero home-path occurrences (86 members). Sdist: only the two known host-neutral fixtures (335 members). |
| Dockerfile floating pip wheel (alert #294) | **CLOSED by code** — new `requirements-container-hashed.txt` (17-package api closure, exact subset of `requirements-pinned.txt`, 473 sha256 hashes) and builder stage builds dependency wheels with `pip wheel --require-hashes`; local package wheel built separately with `--no-deps`. Verified: `pip download --require-hashes` for Python 3.15 on linux/amd64 + linux/arm64 (17/17 each) and `pip wheel --require-hashes` natively (17/17). The alert *state* flips only on the next post-merge Scorecard scan on main — see §5.2. |

No decision-logic code was touched by worker D. No thresholds
re-tuned (S17 contracts unchanged). No tests dropped, no baselines
grown except the proven W9 refresh, no findings suppressed.

## 3. Supported profiles

Declared support (`pyproject.toml`: `requires-python >=3.11`,
classifiers 3.11–3.15). What was actually exercised, and where the
evidence stops:

| Dimension | Supported | Evidence |
| --- | --- | --- |
| Linux × Python 3.12.3 | Yes — fully exercised | Full suite, claims 33/33, schemas, pre-commit, SBOM, packaging, standalone verification (W9, this VM) |
| Linux × Python 3.11 / 3.13 / 3.14 / 3.15 | Declared; **CI is the authority** | Not runnable on the audit VM (no such interpreters); CI core matrix covers 3.11–3.15 on Ubuntu |
| macOS / Windows × Python 3.11 / 3.15 | Declared in installation docs; **OS-smoke only** | CI `os-smoke` runs two shallow CLI operations (`--version`, one `scan --json` piped through a JSON parse). Full pytest/coverage, evidence/claims/SBOM, sealing, dataset-fixture handling and installed-distribution web tests run nowhere in the Windows/macOS CI lanes (audit ENG-09, closed for the lockfile split; the breadth gap is recorded, not claimed away). The W0 Windows extras suite was red at baseline (3,961 passed, 21 failed, 4 errors, 1 skipped); W9 did not re-run it. |
| Container | linux/amd64 + linux/arm64, Python 3.15-slim base (digest-pinned), non-root user, read-only rootfs capable, HEALTHCHECK (`/healthz`, 30 s interval) | W9 container qualification; SBOM scans the locally loaded image. No image is pushed until a signed release exists (ENG-14). |
| Core (no extra) | Yes | No mandatory third-party runtime dependencies; forensic core importable without GPU stacks |
| `api` (fastapi, jinja2, uvicorn, websockets) | Yes | Installed wheel + sdist users pass (W9-A); container lockfile hash-pins the 17-package closure (W10-D) |
| `mcp` (mcp) | Yes | MCP over stdio, 19 tools (W9-A) |
| `all` (api + mcp) | Yes | As api + mcp |
| `cli-rich` (rich) | Yes | `--rich` terminal output |
| `enterprise` (cryptography) | Yes | Sealing/policy features; used by the OS-smoke install |
| `diagnostics` (psutil) | Yes | Diagnostics; absent-dep failure contract tested (W9-D) |
| `ollama` (aiohttp) | Yes | Ollama/local-LLM adapter; absent-dep failure contract tested (W9-D) |
| `fuzzing` (atheris) | **Linux-only** | manylinux wheels only; atheris marker `python_version >= "3.12" and < "3.15"` (ENG-09) |
| `dev` / `security` | Yes (CI tooling) | `.[dev]` is the CI venv; bandit / pip-audit gates |

**Explicitly NOT supported:** remote tenancy / multi-user hosted
service (no authentication, no per-user isolation, no tenant model);
qualified timestamps (only a QTSP timestamp carries an eIDAS
presumption; free public TSA tokens are honestly labelled "RFC 3161
timestamp (non-qualified)"); portable canonical-lock install (the
exact-pin lock is Python 3.12 / Ubuntu by design; per-environment
locks do not exist yet); Windows/macOS full-workflow qualification
(see above).

**Profiles and the CI matrix (jobs that must pass at the candidate
SHA):** Core (ubuntu × 3.11–3.15), OS smoke (ubuntu/windows/macos ×
3.11, 3.15), API/MCP surface (ubuntu × 3.11, 3.15), Claims gate /
Pinned install / SBOM / Package (ubuntu × 3.12), Full suite +
Coverage (enterprise-deep-verification, ubuntu × 3.11–3.15 / 3.12),
Fuzz (ubuntu × 3.11–3.13), Mutation (ubuntu × 3.11),
Reproducibility / Container / Supply-chain (ubuntu × 3.12). The
authoritative required set lives in `scripts/promotion_gate.py`
(`--list-required` prints it).

## 4. Measured claims and limitations

### 4.1 The 33 claims (all verified, `docs/evidence/report-card.md`)

`core.local_first`, `core.no_telemetry`, `core.agpl_license`,
`detector.score_not_probability`,
`detector.calibration_fail_closed`,
`detector.content_hash_integrity`,
`detector.storage_collision_free`, `trustmap.qualitative_only`,
`trustmap.evidence_conditioned`,
`trustmap.no_authorship_probability`, `casefile.raw_text_excluded`,
`casefile.seal_deterministic`, `casefile.tamper_detection`,
`casefile.replay_verifies`, `detector.tfdp2_protocol`,
`detector.deterministic_output`, `evidence.registry_validation`,
`evidence.no_silent_upgrade`, `api.rest_endpoints`,
`mcp.tools_exposed`, `test_suite_measured`,
`test_suite_measured_core`, `python_version_support`,
`ruff_lint_clean`, `security.bandit_no_medium_high`,
`security.pip_audit_tracked`, `deterministic_builds`,
`web_ui.index_renders`, `core.emergency_stop_headless` —
**33 passed, 0 failed** (W7, W8, W9; local, 3 consecutive runs each
wave). In CI the same gate reads 33/33 on main `7d2112c` (fetch-depth
fix B1; run 43811471303, claims-gate check success). Quote claims
figures with their environment — local vs CI — never bare.

### 4.2 Scientific qualification (W8, native operating point, k_fp = 0 everywhere)

Predeclared before any W8 result existed
(`docs/evidence/w8-predeclared-claims.md`, SHA `c7a37097…`). Final
evaluation inaccessible to tuning; no threshold, calibration, or
selection fitted anywhere. Gate per pooled slice: n≥100, Wilson 95%
upper ≤0.05.

| Corpus | n_human | FPR Wilson 95% upper | Native TPR | AUROC | Coverage | Gate |
| --- | --- | --- | --- | --- | --- | --- |
| RAID | 121 | 0.0308 | 0.0199 | 0.5926 [0.5494, 0.6324] | 0.4941 | PASS |
| MAGE | 299 | 0.0127 | 0.0033 | 0.5276 [0.4840, 0.5739] | 0.4500 | PASS |
| Beemo | 874 | 0.004376 | 0/3059 | 0.4027 (below chance) | 0.5169 | PASS |
| DetectRL-X | 2400 | 0.001598 | 0/2400 | 0.5994 | 0.8390 | PASS |
| GhostWriter | 354 | 0.0107 | 0/507 | 0.4468 [0.4074, 0.4882] | 0.5447 | PASS |
| OpAI-Bench | 146 | 0.0256 | 0/147 | 0.4120 [0.3482, 0.4746] | 0.5597 | PASS |

Pooled across all 6 corpora: **0/4194, Wilson upper 0.000915**
(pooled value — never a worst-slice statistic). Validation registry:
15 records, 8 supported (registry_id `3202e9a9…`); evidence registry:
50 records. All 7 independent reproductions AGREE (see §2.3).

**The honest reading (recorded in every artifact, stated here, not
hidden):** FPR is bounded low only at the cost of near-zero detection
power — native TPR is 0.0 almost everywhere, abstention is ~45–55%,
and several AUROCs sit at or below chance (Beemo 0.4027, GhostWriter
0.4468, OpAI-Bench 0.4120). This is a **no-utility result**, recorded
as such. No threshold was moved. A top-level probability requires a
separately validated calibration artifact for the exact ensemble
definition; none is claimed. Short text (≤60 words) abstains ~100%.
Out-of-domain (66 original texts, 11 slices): human FPR 0/66 (Wilson
upper 0.0550), abstention 27.3%. The refusal/abstention contract
holds end to end (engine/API/CLI/bundle). PAN 2025 is an explicit gap
(not available; not attempted).

**Threshold sensitivity (GhostWriter):** zero-FPR at 0.68 does NOT
survive −0.02 on full final-test (1/354 at 0.66) — but the flipping
row is the known U1 row; on fresh rows alone (292) max is 0.6496 and
zero-FPR DOES survive −0.02. Threshold UNCHANGED.

**§7.1.4 amendment (coordinator decision 2026-11-16, parent
APPROVED):** a final holdout qualifies if it is a frozen,
pre-registered partition whose final evaluation was inaccessible to
tuning, even with U1 content-hash overlap — provided the overlap is
measured and disclosed per corpus, no row was selected or excluded by
score, and the pooled slice meets n≥100 + Wilson ≤0.05. Overlaps:
Beemo 180/3933, OpAI 271/1283, GhostWriter 262/1263, DetectRL-X
152/4800. The amendment clarifies the definition; it changes no
number, threshold, or gate value. Decision file:
`hidden_files/audit-w8-s714-amendment-decision.md`.

### 4.3 Report-card lead: `unknown` (fail closed) — W10 does not change it

Two independent blockers, either sufficient:

- (a) **Finer required slices fail.** Worst slice in the W8
  aggregation (`docs/evidence/runs/EV-20261116-human-fpr.json`, 90
  slices with n_human > 0, 28 pass, 43 unmeasured): **MAGE
  testbed:dialogsum, 0/3, Wilson upper 0.5615** (n_human=3, n_ai=2 —
  both below the 100-row minimum; upper exceeds the 0.05 ceiling).
  One other sub-100 slice: Beemo final-test Closed QA, n_human=82,
  Wilson upper 0.044752 — not expandable (single 2,187-row split
  already fully used).
- (b) The pre-W8 worst slice (OpAI-Bench document slice, n=56,
  Wilson 0.064196) was resolved by expansion (pooled final-test
  n_human=146, upper 0.0256; supported record
  evr-20261110-opai-bench-builtin-heuristic, n=218, upper 0.0173),
  so (b) no longer blocks — (a) does.

Pooled-only would flip the lead (worst pooled RAID 0.0308). It is
NOT flipped on that basis: the predeclaration and the plan require
the worst REQUIRED slice, and flipping on pooled-only would be a
favorable-direction judgment call made after seeing the numbers.
Underclaiming is safe and reversible; overclaiming is not. **Fail
closed.** Expanding the MAGE dialogsum slice needs more licensed
MAGE dialogsum human rows; no wave could expand it.

## 5. Open findings

Nothing below is hidden, suppressed, or relabelled. Items marked
"out of scope" land after the final merge, in the order stated.

### 5.1 CI (red on main, out of W10 scope)

CI has **never run on the staging branch** (never pushed, by design).
The first true CI check is CI after the final merge into main. CI on
main `7d2112c` is RED (run 43811471303 — claims gate SUCCESS, 33/33 in
CI as well as locally; the failures are elsewhere):

1. **Every 3.11 job fails at install** — `backports.tarfile`, a
   transitive URL dep from `jaraco-context==6.1.2`
   (`requirements-hashed.txt` line 1192), rejected by
   `--require-hashes` ("all requirements must have their versions
   pinned with =="). Same cause in Mutation run 43811471244 and Fuzz
   run 43811471180. Fix is agent-side in hash-lockfile generation
   (mishandles transitive URL deps — same class as the earlier psutil
   URL dep); `gen_hashed_lock.py` is still not in the repo (see §5.4).
2. **Core 3.15: 3 identity (`is not`) test failures** — `assert 300
   is not 300`, `assert 257 is not 257` (W4 ledger /
   workspace-integrity tests), only on 3.15.
3. **Windows 3.15 OS smoke fails at install** — same hash-mode class
   (`colorama` from `build==1.6.1`, line 17).
4. Enterprise Deep Verification run 43834911600 also completed
   failure — cause **not diagnosed**; do not conflate with the CI
   verdict above.

Green on main `7d2112c`: SBOM-not-stale, Build/wheel-install, Core
3.12/3.13/3.14, OS smoke ubuntu/macos 3.15, API/MCP 3.15, Container,
CodeQL, Reproducibility, Supply-chain, Semver, Scorecard, Workflow
Lint, Pinned-requirements-install. Sigstore fails by design.

### 5.2 Code-scanning alerts

Fresh paginated inventory at W7 (all 3 states, `--paginate`):
**299 alerts ever — 12 open, 287 fixed, 0 dismissed** (zero
dismissals: no alert was ever manually dismissed). Of the old 92, 86
fixed; 6 still open; 6 new. Inventory:
`hidden_files/audit-w7-d-alert-inventory.txt`.

- **#294 PinnedDependencies (`Dockerfile:63`) — CLOSED BY CODE in
  W10 (worker D, this branch).** The flagged command was the runtime
  `pip install "textforensics[api]==0.2.0"` (version pin, no hash);
  W7 restructured the runtime install to local-wheel glob and W10
  hash-pinned the builder-stage dependency resolution with
  `requirements-container-hashed.txt` (`pip wheel --require-hashes`,
  17-package closure, 473 hashes; verified for Python 3.15 on
  linux/amd64 + linux/arm64). The alert **state** flips only on the
  next post-merge Scorecard scan on main — no scan has run on the
  staging branch, so the state cannot be confirmed from staging.
  Confirm it flips to `fixed` on the first post-merge scan.
- **#1 py/polynomial-redos (`src/textforensics/features.py:63`) —
  state stale.** The possessive-quantifier fix is effective in the
  scanner (latest main CodeQL analyses account exactly for the other
  open CodeQL alerts); only the alert state has not transitioned.
  Confirm it flips to `fixed` on the next post-merge CodeQL scan,
  else a structural rewrite is the follow-up.
- **#246 py/overly-permissive-file
  (`tests/test_sealing.py:300`) — open.** Carried forward; no fix
  attempted in W7–W10.
- **#3 Maintained, #4 CodeReview, #5 SecurityPolicy, #6
  CIIBestPractices (Scorecard, no file) — open, genuinely unfixable
  by code.** CodeReviewID + CIIBestPracticesID are Greg-only
  governance decisions (`RELEASE_PLAN.md` §9).
- **#295–#299 py/tarslip — FIXED in W7** (`filter="data"` on all
  extraction sites).

### 5.3 Release-process items (W10 rehearsal / owner decisions)

- **Cosign positive path mock-verified only** (no cosign binary on
  the audit VM) — W10 rehearsal item; §2.1 records the outcome.
- **Signer identity is the workflow identity**
  (`https://github.com/<owner>/<repo>/.github/workflows/release.yml@<ref>`
  with the GitHub Actions OIDC issuer). The human-only
  signer-identity decision recorded in
  `docs/verification/promotion-boundary.md` remains open.
- **Benchmark bootstrap needed after integration:** dispatch
  `benchmark.yml` on main once with an empty `baseline-ref` to
  publish the first stamped baseline.
- **No release/tag/publish was created anywhere in W7–W10.**
  Publication happens only behind the promotion boundary
  (`docs/verification/promotion-boundary.md`): exact-SHA required
  acceptance set + manual confirmation exactly `RELEASE` (release)
  or `PROMOTE` (container), tag created only by `create-tag` at
  exactly the candidate SHA, upload verified by reading the
  published release back, image push only after a signed release is
  verified to exist for that SHA.

### 5.4 Carried engineering items

- **`~/workspace/gen_hashed_lock.py` is still not in the repo**
  (W7 §8.10, carried through W8/W9/W10) — consider committing it
  under `scripts/` (parent decision, not taken). It is also the
  generator behind the W10 container lockfile; the container
  lockfile header cites its workspace path until then.
- **Refresh-method runner defect** (`validate_baseline_entry`
  occurrence-blind for runtime entries) — NOT fixed; later wave
  (W7-F). The cross-checks show it did not bite on the W7 (+73) or
  W9 (+0) entries.
- **Known flakes untouched** — `test_config_mismatch_with_no_current_config`,
  `test_memory_check`, `test_policy_engine_add_multiple`. The separate
  flake-fix wave owns them. `test_config_mismatch…` fails under load
  (0.1 s fixture TTL) and fails the claims gate 32/33 under load;
  it passes in a quiet window.
- **ENG-08 Windows leg** — canonical-LF hashing closed ENG-08 in W6,
  but the Windows leg is proven by simulated autocrlf on Linux only;
  a real Windows CI run of the new tests is still outstanding.
- **Live-TSA carry-overs:** Sectigo bare-`rsaEncryption` rejection
  (needs decision); standalone verifier sha256-imprint limitation
  (pre-existing).
- **W5 carry-overs:** IF-05 token/session stays a human decision;
  decode still materializes the payload; 4 unadvertised formats not
  transported.
- **W4 twin occ 7 NOT re-added** (parent decision, main `7d2112c`) —
  verified absent in every re-derived baseline since. This is a
  decision, not an open item.

## 6. Privacy gate (W10 half)

Scan: candidate source archive, wheel/sdist, image contents
(build context — the image itself could not be built on the scan VM:
no Docker daemon; the build context was scanned instead, and the
image's only inputs are the scanned context files plus the
hash-pinned container lockfile), and published evidence
(`docs/evidence/`). Tools: `grep -r` over six patterns (home paths
`/home/`, `/Users/`, `C:\Users`; email addresses; key/secret material
`PRIVATE KEY` / `ghp_` / `github_pat_` / `AKIA…` / `sk-…`; the public
GitHub handle, counted only) plus the `detect-secrets` pre-commit
hook; counts and filenames only — matched values are never copied,
quoted, or reproduced anywhere (W7 hard rule). Full commands,
coverage, and classification are in
`hidden_files/audit-w10-d-report.md`.

**Outcome — resolved, nothing unresolved, nothing blocking:**

- Wheel (86 members, sha256 in the W10-D report): **zero**
  home-path / key / secret occurrences. One reserved-domain example
  address (`security@textforensics.example` in `model_card.py`);
  `strmt7` only in public schema `$id` URLs and the README clone URL.
- Sdist (335 members): only the two known host-neutral fixtures
  (generic `/home/` probes in `tests/test_privacy_minimized.py` and
  `tests/test_w1_web_console.py:493`); emails are all reserved-domain
  test addresses; `strmt7` only in public repo URLs; no keys/secrets.
- **26 new `actual-personal-path` occurrences found and resolved by
  forward fix (no history rewrite):** 18 in three W8 registry-bound
  run artifacts (`EV-20261116-ood-short-refusal.json` 6×
  `cache_file`; `EV-20261116-reproduction-detectrl-x.json` 3×
  `detail`; `EV-20261116-reproduction-registry.json` 9×
  `cache_file`) and 8 hardcoded worker-checkout paths in five W8
  reproduce scripts. The artifacts are digest-bound (U7(b)), so the
  originals stay byte-identical and minimized successors were created
  in `docs/evidence/runs/privacy-minimized/` (textual line
  replacement only; diff shows only the 6/3/9 minimized lines; both
  original and successor validate against
  `run-artifact.schema.json`; lineage in the README; successors never
  registered). The scripts were minimized in place to
  `REPO_ROOT`-relative paths (all five compile and `--help` clean).
  Regression tests in `tests/test_privacy_minimized.py` (9 tests).
- Known W0/W7 items unchanged: the two digest-bound suite JSONs
  (originals byte-identical, successors exist); the two fixtures; the
  canonical public noreply identity (published by GitHub itself, not
  personal data). No credentials, keys, or real user text found
  anywhere.
- Removing old material from public Git history is a separate
  owner-authorized operation with a recovery/provenance plan; this
  audit authorizes no rewrite. No scanner ignores were added.

## 7. Migration, rollback, and incident recipes

### 7.1 Upgrading (migration)

- **Install:** `pip install textforensics==<version>` (wheel/sdist
  per version; `python -m build` + `twine check` for local builds).
  Pre-1.0 semver policy (`docs/RELEASE.md`): public schemas and
  detector/calibration semantics are contracts — version them
  deliberately; breaking changes get migration notes in
  `CHANGELOG.md` (see the `[Unreleased]` section at dossier time).
- **Extras are additive:** adding an extra (e.g. `.[api]`) never
  changes core behavior; the core stays importable with no mandatory
  third-party runtime dependencies. A bare install that lacks an
  extra fails with a clean single-line install hint (W9 A-fix/D),
  never a bare traceback.
- **Result-codec migrations:** configured `CodecConfig.migrations`
  callbacks are actually invoked; a migration that cannot run fails
  loudly (never silently skipped). Schema-version map is enforced by
  the generic validator.
- **Case-file versions:** case-file schema v4 is the current
  default (Phase 5 U2-leftovers: per-observation determinism,
  mismatch on a declared non-deterministic detector → inconclusive
  exit 2). Older sealed bundles remain verifiable — see §7.2.
- **Calibration:** thresholds are S17 audit contracts, not tuned
  values. A new calibration is admitted only on a disjoint
  fit/evaluation proof (`benchmark --calibration-dataset`); a
  contaminated pair, fingerprint mismatch, or unverifiable proof
  fails closed and the run is labelled `held_out_evaluation` only
  when the proof verifies.

### 7.2 Rolling back

- **Releases are immutable.** Tags are created only by `create-tag`
  at exactly the candidate SHA, inside the promotion boundary; branch
  protection blocks force-pushes and deletions. A bad release is
  never fixed by moving a tag: **roll back by publishing a new
  release from the previous known-good SHA** (new version number, new
  tag, new promotion-boundary run). Record the rollback in
  `CHANGELOG.md` with the reason and the SHA pair.
- **Install downgrade:** `pip install textforensics==<previous
  version>`; verify with `textforensics --version` and a
  `scan --json` smoke run. The previous wheel/sdist remain available
  per version; the SBOM and lockfiles are per-version artifacts.
- **Case files and evidence never roll back silently.** Sealed
  bundles verify with the standalone verifier (no package installed;
  W9: 30/30 checks, tampered → exit 1, wrong key → exit 1). A bundle
  sealed under an older case-file version stays verifiable under its
  recorded version; do not re-seal old evidence with new code to
  "fix" it — re-sealing would break the seal chain and the claims
  gate digests. Registry records are hash-bound; a bad registry
  entry is handled by demotion/recovery (tested in W9-C: drift
  snapshot/compare/run, demotion/recovery, reload), never by editing
  a record in place.
- **Calibration rollback:** re-admit the prior calibration artifact
  (it carries its own disjoint fit/evaluation proof). Never re-tune
  a threshold on final-test data to recover a metric — a
  below-chance or no-utility result stays a negative result.
- **Container rollback:** the candidate identity is the image
  digest; roll back by promoting the previous digest (rebuild from
  its exact SHA, re-run running-image acceptance, re-verify the
  signed release for that SHA). Never re-tag a digest in place.

### 7.3 Incidents

- **Emergency stop:** `textforensics` emergency stop is headless
  and tested end to end (W9-B: 0.003 s, zero partial files). A stop
  is a stop: halt completely at the first word, confirm the halt,
  do not queue replacement work.
- **Tampered / wrong-key / malformed evidence:** case verify fails
  closed (tamper → exit 1, wrong key → exit 1, malformed keygen JSON
  → refused; packing tamper → exit 2). Treat a verification failure
  as the finding it is — never bypass the verifier, never relabel
  `unknown` as `supported`.
- **Suspected benchmark contamination:** freeze the run, record the
  overlapping content hashes, disclose the overlap per corpus (the
  §7.1.4 amendment route), and do not select or exclude rows by
  score. If the overlap reaches the final holdout's selection, the
  run is exploratory, not tuning data, and the lead stays `unknown`
  until a clean partition exists.
- **A red gate after merge:** do not patch the gate, the baseline,
  or the threshold to make it green. Reproduce first (red-test
  first), fix the cause, re-run the full verification on a fresh
  checkout of the exact head, and re-check CI itself — local green
  has repeatedly hidden CI red (Phase 1/2, datasets wave 1,
  U2-leftovers, W0 pin, W2 pydantic, claims fetch-depth,
  code-scanning pagination).
- **Privacy incident (personal data in a candidate):** follow §6 —
  classify (hosted-runner output / intentional fixture / actual
  personal path), minimize forward (successors for digest-bound
  artifacts, in-place for the rest), never rewrite public history
  without owner authorization and a recovery/provenance plan.

## 8. Cold-start handover (reproduce the candidate and the gates from scratch)

For a new maintainer with a clean machine. Every step is verifiable
without Greg and without any unpublished state.

1. **Clone and check out the exact candidate.**
   `git clone https://github.com/strmt7/TextForensics.git` (remote has
   only `main`); `git checkout <candidate SHA>` — the SHA from §2.1
   once the coordinator fills it in. Verify `git log --oneline -1`
   shows that SHA and `git status` is clean (a dirty tree is not a
   verifiable candidate: `verify_release.py` exits 2 without running
   any gate).
2. **Canonical environment.** Python **3.12.3**, pip **24.0**.
   `python3 -m venv <venv>` (on workspace disk, never `/tmp`);
   `<venv>/bin/python -m pip install -r requirements-pinned.txt`
   with TMPDIR inside the repo and `PIP_NO_CACHE_DIR=1`. This is the
   canonical dev venv shape; CI's `. [dev]` install is the
   equivalent. Never run the claims gate concurrently with the full
   suite (the 512M `/tmp` tmpfs fills and `deterministic_builds`
   fails ENOSPC — W7 lesson); clean `/tmp/pytest-of-root` first.
3. **Full suite.** Put the venv on PATH and use a basetemp/TMPDIR on
   workspace disk **outside any git repo**, with **absolute paths**
   (never `~` — unreliable in this tool's command handling):
   `TMPDIR=/home/hatch/workspace/.tmp
   python -m pytest --basetemp=/home/hatch/workspace/.tmp/pytest`
   (a basetemp *inside* the worktree breaks 2 tests; the shared
   `/tmp` cannot hold two concurrent suites). Expect the W10 numbers
   from §2.1 (W9: 7054 passed / 0 failed / 3 skipped / 8567
   subtests).
4. **Claims, schemas, pre-commit (sequentially, /tmp clean).**
   `python scripts/check_claims.py` (expect 33/33; run 3×),
   `python scripts/validate_schemas.py` (expect 13 OK),
   `pre-commit run --all-files` (expect 13/13). After ANY pre-commit
   run that modifies files, check `git status` and commit the fixes —
   a second passing run does not mean the tree is clean.
5. **Supply chain.** `python scripts/generate_sbom.py --check`
   (expect 122 components) and the pip-audit gate (expect PASSED).
   Regeneration rules: after any `requirements-pinned.txt` change,
   regenerate `requirements-hashed.txt` with
   `gen_hashed_lock.py` AND the SBOM in the same commit; after any
   api-closure change, regenerate
   `requirements-container-hashed.txt` too (procedure in its header).
6. **Builds and standalone verification.**
   `python -m build` (wheel + sdist); `twine check dist/*`;
   reproducibility: two clean SDE-pinned builds byte-identical.
   Standalone verification with NO package installed (empty venv,
   embedded `verify.py`, expect exit 0, 30/30 checks).
7. **Canonical verification command.** `PYTHONPATH=$PWD/src
   PYTHONDONTWRITEBYTECODE=1 <venv>/bin/python
   scripts/verify_release.py --json <out>.json` — the single command
   mirroring the complete CI surface (exit 0 pass / 1 gate failed /
   2 incomplete; required gates accept ONLY `pass`). See
   `docs/verification/canonical-verification.md`.
8. **Fresh-checkout verification (CONTRIBUTING §2.6).** Before any
   merge is called green, re-run the gates on a fresh linked
   worktree at the exact head — in-worktree runs have repeatedly
   missed what a fresh checkout catches.
9. **Where the evidence lives.** Wave reports and proof evidence:
   `goals/textforensics-complete-revamp/hidden_files/` (`audit-w7*`,
   `audit-w8*`, `audit-w9*`, `audit-w10*`); run artifacts:
   `docs/evidence/runs/` + `docs/evidence/registry.json`;
   validation registry: `docs/validation/registry.json`; report
   card: `docs/evidence/report-card.md` (generated by the gate — do
   not hand-edit); promotion boundary:
   `docs/verification/promotion-boundary.md`; release plan:
   `docs/RELEASE_READINESS_PLAN.md`; release checklist:
   `docs/RELEASE.md`.

Standing lessons that have bitten before: validate every NEW action
pin against its upstream repo (`gh api repos/<owner>/<repo>/commits/<sha>`);
verify in a bare core-only venv matching CI's `. [dev]` install;
paginate API reads fully; quote claims figures with their environment;
never delete a worktree until its gitignored working files are
committed or copied to a durable location; after any branch merge,
delete the remote branch too (remote must have only `main`).

## 9. Release authorization

**Greg decides whether and when to authorize release.** This dossier
is a qualification record, not an authorization. No release, tag,
container image, or package upload has been created from this work,
and none may be created on the strength of this dossier alone. When
(and only when) Greg authorizes it, promotion goes through the
boundary in `docs/verification/promotion-boundary.md` at the exact
candidate SHA, with the required acceptance set green at that SHA and
the manual confirmation exactly `RELEASE` (or `PROMOTE` for the
container image). If any gate in §2.1 is still TBD, failed, or
CI-unconfirmed at that point, the candidate is not promotable.
