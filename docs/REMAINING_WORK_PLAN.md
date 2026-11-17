# Remaining Work Plan — TextForensics

**Status:** `DRAFT-FOR-GREG` — written 2026-11-17, main `3fff202`, after the CI-FIX-3 wave.
**Purpose:** the exhaustively detailed plan for everything that is still unfinished, still open, or still a decision for Greg — and the exact steps to implement each item. Nothing in this plan authorizes a release, a tag, or a publication. **Greg alone decides the release.**

**How to read this plan.** §1 is the verified snapshot of the repo as it stands. §2 is the process every future wave must follow (condensed from the standing rules, so a future implementer does not have to re-derive them). §3 is the remaining work, one item at a time, each with its exact location, its evidence, its implementation steps, and its verification criteria. §4 is the list of decisions only Greg can make — flagged, never decided here. §5 is the exact path to a stable release once Greg authorizes it. §6 is the standing verification gates. §7 is the distilled lessons. §8 is the evidence appendix.

---

## 1. Current state (verified 2026-11-17, main `3fff202`)

### 1.1 Head and hygiene

| Fact | Value |
|---|---|
| Main head | `3fff202` — "CI-FIX-3 refresh: ruff-format fix in new dict dumps kill test" |
| Remote branches | Only `main` |
| Local branches | Only `main` |
| Open PRs | 0 |
| Tags | 0 |
| Releases / publications | None created |
| Git status | Clean (no uncommitted work, no stashes, no worktrees besides the main clone) |
| Canonical identity | Stratos `<28989754+strmt7@users.noreply.github.com>`, id 28989754 |

### 1.2 Local gates (parent verification, fresh checkout, exact head `3fff202`)

| Gate | Result |
|---|---|
| Full suite | **7137 passed / 0 failed / 6 skipped / 8597 subtests** (864.28 s, Python 3.12.3) |
| Claims | **33 passed, 0 failed** (3 consecutive runs, `/tmp` clean, NOT concurrent with the suite) |
| Schemas | **14 OK** |
| Pre-commit | **13/13 Passed** |
| Mutation baseline (re-derived via tomllib) | **7034 / 7034 unique / 1341 positions / 46 modules / 0 stale** |
| Baseline kinds | return 885 / arg 5007 / unreachable-condition 23 / unobservable-value 254 / domain-equivalent 815 / ulp-equivalent 6 / annassign 44 |
| Baseline modules | dsse 24, ed25519 49; W4 twin occ 7 still absent |
| Report-card lead | **`unknown`** (unchanged — see §1.4) |

The 6 skips are: 3 cosign tests (cosign binary not on PATH in the local run — they pass with cosign on PATH), 1 SBOM full-install skip (needs atheris+wheel), 2 Windows ACL tests (Windows-only). None of these is a failure.

### 1.3 CI verdict on `3fff202` (read from the GitHub API + failed-job logs, 2026-11-17)

**CI is fully green except by-design Sigstore.** This is the first time the entire CI surface has been green on a merged head in this program.

- **CI workflow on the final head `3fff202` (36 check runs):** everything passes except **Sigstore Verification (by design — no releases exist)**. All five Core jobs (3.11, 3.12, 3.13, 3.14, 3.15) pass. Claims gate passes (33/33 in CI). All OS smoke, API, MCP, Mutation, Reproducibility, CodeQL, Scorecard, Semver, Supply-chain, SBOM, pip-audit pass. (DeepSource and Full Mutation (Weekly) show as skipped — they are scheduled/weekly jobs, not push jobs.)
- **Container and Fuzz did not run on the final head `3fff202`** — Worker C's refresh commits touched only the mutation baseline and test files, which match neither workflow's path filter. **But both fixes ARE verified in CI on their own fix commits**, because each push during the wave triggered them:
  - **Container on `8446546` (Worker A's fix commit): `Build candidate image (no push): success`.** (Promote skipped — expected, no push on a non-release.)
  - **Fuzz on `9a8b9ab` (Worker B's fix commit): `Fuzz Summary: success`, `Fuzz Regression (Python 3.11/3.12/3.13): success`.** (Fuzz Extended skipped — it is a scheduled job.)
- **Sigstore fails by design** until a release exists. It flips green at release time, not before. It is not a defect and not something to "fix" before a release.

### 1.4 The §11 definition of done — status

`docs/RELEASE_READINESS_PLAN.md` §11 (written 2026-11-15) defines "ready for release" as ten conditions. Their status on `3fff202`:

| # | Condition | Status |
|---|---|---|
| 1 | W0–W10 all complete and merged, each with a complete wave report and a mutation proof (0 unexplained, baseline re-derived, 0 stale) | **MET** — W10 merged 2026-11-17 (`fefd81e`); all wave reports complete; baseline 7034, 0 stale, 0 unexplained |
| 2 | Full test suite green, 0 failures, on all five Pythons (3.11–3.15) in CI, and locally | **MET** — CI workflow green on all five Pythons; local suite 7137/0/6/8597 |
| 3 | Claims 33/33 local and 33/33 in CI | **MET** — 33/33 local (×3) and 33/33 in CI |
| 4 | Schemas 13 OK; pre-commit 13/13 | **MET, with a count update** — schemas are now **14 OK**, not 13, because W10 added the 14th schema (`textforensics.candidate-manifest/v1`). Pre-commit 13/13. The "13" in §11 is stale; the correct figure is 14 |
| 5 | CI fully green except the two by-design items (Sigstore + documented non-blockers) | **MET** — CI fully green except Sigstore by design (see §1.3) |
| 6 | No unresolved P1 finding within advertised scope; P2 findings affecting advertised correctness also fixed | **MET** — all 91 audit findings (45 P1 / 46 P2) closed across W0–W10 |
| 7 | Scientific claims qualified (W8) | **MET, on the `unknown` branch** — the report-card lead stays `unknown` because no worst-slice aggregation meets the bar (n≥100 per slice, Wilson upper ≤0.05). The worst slice is MAGE testbed:dialogsum 0/3, Wilson 95% upper 0.5615. §11 explicitly allows this: "otherwise it stays `unknown` and the release ships with that limitation stated." The release ships with the near-zero-detection-power limitation stated, not hidden. See §1.5 |
| 8 | End-to-end qualification (W9) passes | **MET** |
| 9 | No-publication rehearsal (W10) passes | **MET** — second clean verifier byte-identical, 16/16 bad candidates rejected, 9/9 planted-defect demos exit 1, 0 remote writes |
| 10 | No release, tag, or publication has been created; Greg alone decides | **MET** — nothing released; the decision is Greg's |

**Conclusion: the §11 definition of done is met. The repo is ready for a stable release, pending Greg's release authorization (§4.1).** The remaining work in §3 is follow-up hardening and maintenance — it does not block the release decision, and none of it is a §11 condition. Do not let §3 items silently become release blockers; if Greg wants any of them done before release, he must say so explicitly.

### 1.5 The honest caveat (do not dress this up)

The report-card lead stays `unknown`. The honest reading, recorded in the W8 report and in every parent verification since, is: **human FPR is bounded low only at near-zero detection power** (native TPR ~0, ~45–55% abstention, several AUROCs at/below chance). This is a no-utility result. No threshold was moved to hide it, and none should be. The release, if Greg authorizes it, ships with this limitation stated in the release notes and in `docs/evidence/report-card.md`. It is not a defect to fix by tuning; it is a property of the current detector evidence. Improving detection power is a research program, not a bug fix — see §3, item R13.

### 1.6 What was completed (for orientation, not for re-doing)

- **Audit W0–W10** (91 findings, plan `docs/RELEASE_READINESS_PLAN.md`): all complete, verified, merged into main. Reports in `~/workspace/goals/textforensics-complete-revamp/hidden_files/audit-w{0..10}-report.md`.
- **CI-FIX** (main `dd11ebb`, 10 commits): fixed all 6 CI failure classes from the `fefd81e` verdict (hash-lockfile grid closure, test-harness items, container driver-opts). Report: `hidden_files/audit-cifix-report.md`.
- **CI-FIX-2** (main `2ee1330`, 5 commits): fixed the 7 remaining CI failures (EnumType `in`, PlainName intern, SBOM count by version). Report: `hidden_files/audit-cifix2-report.md`.
- **CI-FIX-3** (main `3fff202`, 7 commits): fixed the last 2 CI blockers (Container acceptance duration literal, Fuzz `json_parsing` RecursionError with a fail-closed depth bound of 100). Baseline 7010 → 7034 (deliberate, verified — see §1.2). Report: `hidden_files/audit-cifix3-report.md`.
- **Live-TSA** (main `7a3d28f`): live timestamp round-trip vs freetsa, valid=True. Two pre-existing client defects fixed (wrong OID_SIGNED_DATA; wrong P-384 curve constants).
- **Worst-slice human FPR** (main `cc9a272`): OpAI-Bench document slice n=56→218, k_fp=0, Wilson 95% upper 0.0642→0.0173.
- **Code-scanning fix** (main `a4bf2a3`): 72 of 92 alerts fixed by code; 20 cannot be fixed by a code change (documented, left open, NOT dismissed).
- **Branch protection** (2026-11-14): main protected with minimal rules (force-pushes blocked, deletions blocked; no required status checks, no required PR reviews, no restrictions, admins not enforced) — identical to FlitzZip.
- **Dependabot PRs #63 + #64 merged** (2026-11-14): pre-commit 3.8.0→4.7.0, websockets 12.0→17.4. PR #65 CLOSED, not merged (downgrades setuptools/wheel, breaks the tools lockfile — see §3, item R12).

---

## 2. How to do the remaining work (process — read this first)

Every future wave follows these rules. They are the distilled standing rules from the audit program; violating them is how the program repeatedly lost time (local-vs-CI blind spots, lost worktrees, stale branches, unverified merges).

### 2.1 Branch and merge discipline (non-negotiable)

- **Development ONLY in main.** No PRs. No lingering branches. Greg does not review code manually.
- Use short-lived worker branches off main. Integrate each into main **immediately** after verification and **delete the worker branch + worktree right away** — including the **remote** branch (`gh api DELETE refs/heads/<branch>`), not just the local one. The remote must have **only `main`** at all times. Verify with `gh api repos/strmt7/TextForensics/branches --paginate`.
- Merge by fast-forward of the exact verified commits. Always `git checkout main` and confirm the current branch before a ff-merge (a coordinator once merged into the wrong branch).
- **Never delete a worktree** until its gitignored working files are committed or copied to the goal `hidden_files/` directory. (A casefile Phase-1 dump was lost this way on 2026-11-09.)
- Worktrees: one linked worktree per worker under `~/workspace/TextForensics-<wave>-<letter>`. Never run a suite with TMPDIR/basetemp inside a worktree (see §2.3).
- **No release, tag, or publication** without Greg's explicit permission. No detector-bypass features. Scope is TextForensics only; other repos are read-only.

### 2.2 Verification gates (every wave, every merge)

Parent verification runs on a **fresh checkout** of the exact head (new linked worktree, detached at the head) or with all `__pycache__` deleted + `PYTHONDONTWRITEBYTECODE=1`. Record the worktree path + commit hash in the wave report. The gates are:

| Gate | Command (from the fresh checkout) | Expected |
|---|---|---|
| Full suite | `TMPDIR=/home/hatch/workspace/.tmp PATH=<main-clone>/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$PWD/src <main-clone>/.venv/bin/python -m pytest tests/ -q --tb=line -p no:cacheprovider --basetemp=/home/hatch/workspace/.tmp/pytest` | 0 failures (skips: 3 cosign without cosign on PATH, 1 SBOM full-install, 2 Windows ACL) |
| Claims | `TMPDIR=/home/hatch/workspace/.tmp PATH=<main-clone>/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$PWD/src <main-clone>/.venv/bin/python scripts/check_claims.py` — run **3× sequentially**, `/tmp` clean, NOT concurrent with the suite | `Results: 33 passed, 0 failed` each time |
| Schemas | `PATH=<main-clone>/.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$PWD/src <main-clone>/.venv/bin/python scripts/validate_schemas.py` | **14 OK** (not 13 — see §1.4, item 4) |
| Pre-commit | `PATH=<main-clone>/.venv/bin:$PATH <main-clone>/.venv/bin/pre-commit run --all-files` | **13/13 Passed** |
| Baseline | Re-derive via tomllib from `mutation-baseline.toml` (`d['equivalent']` is a LIST) | Total / unique / positions / modules match the wave's recorded figures; **0 stale**; the FULL computed operator Counter diffs to 0 against the `test_mutation.py` literal |
| CI | Read the verdict via GitHub API + failed-job logs on the merged head | CI fully green except by-design Sigstore; quote claims figures **with their environment** ("33/33 local" vs "33/33 CI") — never quote a local figure as the CI figure |

**Standing rules that must not be re-learned the hard way:**
- `pre-commit run --all-files` every time, on the exact tree being merged. After any pre-commit run that modifies files, check `git status` and commit the fixes — a second passing run does not mean the branch is clean.
- Never pipe a gate command through `tail` in a `&&` chain (masks exit codes). Run the FULL affected test file after any merge.
- **`/tmp` is a 512 MB tmpfs, wiped on reboot.** Never run `scripts/check_claims.py` concurrently with the full suite (the suite fills `/tmp` and `deterministic_builds` fails ENOSPC, 32/33). Always use ABSOLUTE paths on workspace disk OUTSIDE any git repo for TMPDIR/basetemp (`TMPDIR=/home/hatch/workspace/.tmp`, `--basetemp=/home/hatch/workspace/.tmp/pytest`). A TMPDIR/basetemp INSIDE a worktree breaks 2 tests; `~` in `--basetemp=` is unreliable. Never `rm -rf /tmp/pytest-of-root` while a suite is live.
- **Bare-venv verification is the only reliable check for the dependency class.** The local dev `.venv` has api/mcp extras and full git history, so it masks failures CI (only `.[dev]`, depth-1 checkout) hits. For any dependency change, verify in a bare venv (`pip install -e ".[dev]"` in a fresh venv). Quote claims figures with their environment.
- **Validate EVERY new action pin against its upstream repo** (`gh api repos/<owner>/<repo>/commits/<sha>`). For a Docker digest, resolve from Docker Hub. **Paginate every `gh api` list read** (`--paginate`) — the code-scanning count error (30 vs 92) came from reading only the first page.
- **SBOM `--check` MUST run in a fresh canonical venv** (Python 3.12.3, pip 24.0, `pip install -r requirements-pinned.txt`, TMPDIR inside the repo + `PIP_NO_CACHE_DIR=1`, venv on workspace disk, never `/tmp`); in the main `.venv` it exits 1 spuriously. **Any worker changing `pyproject.toml` must regenerate the SBOM.** If `requirements-pinned.txt` changes, regenerate `requirements-hashed.txt` with the in-repo generator `scripts/generate_hashed_lock.py` (NOT `~/workspace/gen_hashed_lock.py` — that path is the redundant out-of-repo copy, see §3 item R9) AND the SBOM.
- `scripts/check_claims.py` rewrites `docs/evidence/report-card.md` as a side effect — revert it (`git checkout -- docs/evidence/report-card.md`) if a failing run dirties it.
- Update `.secrets.baseline` SURGICALLY only.
- Never trust `mutation-results/summary.json` blindly — the real proof is the cosmic-ray dump + runner parse. After a union merge, re-derive EVERY count from the resolved baseline via tomllib and diff the FULL computed operator Counter against the test file's literal. Merge the branch HEAD, never an earlier hash. Rebase onto the LOCAL `main` ref, not `origin/main`. Baseline TOML entries live under the `equivalent` key as a LIST.
- Never trust a bare `pgrep -f` liveness check — use `ps aux | grep "[c]osmic-ray exec"`. Verify class identity (`is`), not just importability.
- **Coverage is exact per run, not stable to the line** (±1–2 missed lines with zero `src/` changes) — not a regression signal.
- **Coordinators ending early / going idle is a RECURRING failure pattern** (W2, W3, W5). Every coordinator/finisher brief must explicitly say: do NOT end with a progress report; if a worker is interrupted, spawn a recovery worker on the same branch/worktree; verify "running"/"alive" claims yourself (ps + git status + branch head). Subagent status labels are UNRELIABLE.
- VM reboots happen often (~every 2 h); `/tmp` is wiped on reboot — keep evidence in goal `hidden_files/`, never `/tmp`. Committed work survives restarts; in-flight processes do not. Commit early and often.

### 2.3 What "done" means for each item in §3

Each item is done only when ALL of these hold:
1. The fix/change is merged into main (fast-forward of the exact verified commits), pushed, and read back (remote main SHA matches the local head).
2. The parent verification gates in §2.2 all pass on a fresh checkout of the exact merged head.
3. CI on the merged head is green for every workflow the change triggers (CI workflow + any path-filtered workflow: Container, Fuzz, Mutation, etc.), except by-design Sigstore.
4. The wave report is written in `~/workspace/goals/textforensics-complete-revamp/hidden_files/` with 0 DRAFT/TODO, and `~/MEMORY.md` is updated with the outcome.
5. Only `main` exists locally and remotely; all worker branches + worktrees are deleted; 0 open PRs.

---

## 3. Remaining work (one item at a time)

Ordered by a sensible execution sequence, not by priority alone. Items R1–R3 and R6–R8 are independent of each other and may run in parallel (separate workers, separate branches, integrated one at a time). R4 and R5 touch shared mutation infrastructure — run them after R1–R3, or on their own branches with care around the baseline. R10–R12 are ongoing maintenance rules, not one-time waves. R13 is a research program, not a bug fix — do not start it as a wave without Greg's explicit direction.

### R1. Flake-fix wave (tests-only) — 3 known flakes

**Priority:** Medium. These are the only known non-deterministic tests in the suite. They do not fail CI on a clean run, but they fail intermittently under load and they poison the "0 failures" signal — a flake that fails under load makes every future wave's verification ambiguous.

**Exact locations (verified 2026-11-17):**
| Test | File:line | Mechanism |
|---|---|---|
| `TestEdgeCases::test_config_mismatch_with_no_current_config` | `tests/test_detection_cache.py:557` | Fixture TTL is 0.1 s (`CachePolicy(ttl_seconds=0.1, ...)` at line 44). Fails 8/8 at load 11–13, passes at load ~1.4, passes in isolation. Mechanism: a >100 ms put→get gap can only come from OS preemption under load; no shared state, no clock jump. |
| `TestDiagnosticsEngine::test_memory_check` | `tests/test_diagnostics.py:214` | Memory measurement under load (exact mechanism not yet isolated — the wave must reproduce it first). |
| `TestPolicyProperties::test_policy_engine_add_multiple` | `tests/test_capability_policy_properties.py:56` | Property-based test; fails intermittently under load (exact mechanism not yet isolated — the wave must reproduce it first). |

**Implementation steps:**
1. **Reproduce before fixing** (standing rule). For each flake, run the single test file in a loop under load (e.g. `for i in $(seq 1 20); do pytest <file>::<test> -q; done` while the machine is loaded, or run the full suite 3× and record which flakes appear). Record the failure rate and the exact error for each. Do not guess the mechanism — the cache flake's mechanism (OS preemption, >100 ms gap) is already known; the other two must be reproduced and their mechanisms identified from the failure output.
2. **Fix the cache flake** by raising the fixture TTL from 0.1 s to a value that cannot be crossed by OS preemption under load (e.g. 1.0 s), OR by making the test tolerant (e.g. assert on the config-mismatch behavior without depending on the TTL expiring within a tight window). Prefer raising the TTL — it is a test fixture, not production behavior, and the test's purpose (config mismatch fails closed) is preserved either way. Do NOT change production `CachePolicy` defaults.
3. **Fix the diagnostics flake** (`test_memory_check`): reproduce first. Likely causes are a memory measurement that depends on allocator state under load, or a threshold that is too tight. Fix by loosening the assertion to what the test actually proves (memory check runs and reports), or by making the measurement deterministic (e.g. mock the allocator query). Do NOT disable the test.
4. **Fix the policy-properties flake** (`test_policy_engine_add_multiple`): reproduce first. Likely causes are a Hypothesis-generated input that is timing-sensitive, or shared state between property cases. Fix by isolating the state per case or by constraining the generated input to the deterministic range. Do NOT reduce the property's coverage.
5. **Verify:** run each fixed test file 20× in a loop under load (full suite running in parallel is the most realistic load). All 20 runs must pass. Then run the full suite 3× (the parent verification gates in §2.2). The flakes must not appear in any of the 3 runs.
6. **Scope guard:** tests-only. No `src/` change. No baseline change (no new mutants, no re-anchoring). No threshold change in production code. If a fix requires a `src/` change, stop and escalate — it is not a flake fix, it is a production bug, and it needs its own wave with a mutation proof.

**Verification criteria:** each of the 3 tests passes 20/20 under load; full suite green 3×; claims 33/33 ×3; schemas 14 OK; pre-commit 13/13; baseline unchanged (7034/7034/1341/46, 0 stale).

**Dependencies:** none. May run in parallel with R2, R3, R6, R7, R8.

### R2. Tools lockfile gap — `colorama==0.4.6` on win32 missing

**Priority:** Low. No current job is red because of it — no job installs the tools lockfile on Windows/3.11. But it is a latent install failure: the first job that does will fail the same way the main lockfile failed on 3.11.

**Exact location (verified 2026-11-17):**
- Generator: `scripts/generate_tools_lock.py` (single-platform resolution — line 181 comments "same lockfile works across platforms and Python versions", which is the defect: it is not a grid).
- Lockfile: `requirements-tools-hashed.txt` (contains alabaster, arrow, attrs, babel, boolean.py, build, certifi, chardet, charset-normalizer, cyclonedx-bom, cyclonedx-python-lib, defusedxml, … — **no `colorama` entry**; confirmed by grep).
- Missing: `colorama==0.4.6` on `win32` (a transitive of the tools set on Windows).

**Implementation steps:**
1. Read `scripts/generate_tools_lock.py` fully. Understand how it resolves (it reads direct pins, resolves via PyPI, writes `--require-hashes` lines). Understand how the main generator `scripts/generate_hashed_lock.py` does its grid closure (3.11–3.15 × Linux/Windows/macOS) — that is the pattern to copy.
2. Extend `scripts/generate_tools_lock.py` to resolve the tools set across the same grid (5 Pythons × 3 platforms), collecting every marker-gated transitive (including `colorama` on win32). The generator must fail closed (exit non-zero if any grid environment is unresolved) and must have a `--check` mode (like the main generator) that verifies the lockfile covers the grid without rewriting it.
3. Regenerate `requirements-tools-hashed.txt` with the extended generator. Verify the new file contains `colorama==0.4.6` with a win32 marker and a hash. Verify all pre-existing entries are byte-identical (same versions, same hashes) — only additions are allowed, no version changes, unless a version change is forced by the grid (in which case document it explicitly and justify it).
4. Add a CI gate (or extend an existing one) that runs the tools-lockfile `--check` mode, so a future tools-set change that breaks the grid is caught in CI rather than at install time. (The main lockfile's `--check` is the model.)
5. **Verify:** grid closure `--check` exits 0; a bare-venv install of the tools lockfile succeeds on the grid (at minimum: Linux/3.12 and Windows/3.11 — the two environments the gap affects); full suite green; claims 33/33; schemas 14 OK; pre-commit 13/13; SBOM regenerated if `pyproject.toml` changed (it should not need to change for this item).

**Verification criteria:** `scripts/generate_tools_lock.py --check` exits 0 ("tools pins cover every grid environment"); `colorama==0.4.6` present in `requirements-tools-hashed.txt` with a win32 marker and hash; no pre-existing entry changed version or hash; full suite green; claims 33/33.

**Dependencies:** none. May run in parallel with R1, R3, R6, R7, R8. Do NOT change `requirements-pinned.txt` or `requirements-hashed.txt` in this item.

### R3. Latent 3.15 mutant kills — 300-based `is not` kill tests

**Priority:** Low. These tests pass on 3.15 today, but their mutant kills are latent there — the kill depends on CPython's small-int cache, and CPython 3.15 interns integers up to 1025 (gh-133059), so a `300 is not 300` assertion that kills a mutant on 3.12 may not kill it on 3.15. The mutation proof is therefore weaker on 3.15 than the baseline claims. This does not fail CI; it is a proof-strength issue.

**Exact locations (verified 2026-11-17 — grep for `is not 300` / `300 is not` in `tests/`):**
- `tests/test_audit_w5_worker_f_ollama.py:21` — comment: "CPython caches only -5..256, so `len(...) is not 300` is …"
- `tests/test_audit_w5_worker_f_rich_output.py:50` and `:505` — comment: "`300 is not len(...)` is True on this Python (ints above …"
- The CI-FIX-2 coordinator's flag also named W3-ledger and observatory kill tests with the same pattern. **My grep found only ollama and rich_output.** The wave must search for ALL of them — do not assume the list above is complete. Search for every `is not <int>` and `<int> is not` kill-test assertion in `tests/` where the literal is in the range 257–1025 (the range CPython 3.15 interns). The W3-ledger and observatory tests may use a different literal or a different construction (e.g. a length comparison rather than a bare literal).

**Background (why 300 is the wrong literal):** CPython caches small integers -5..256. A test that asserts `x is not 300` relies on 300 NOT being cached, so that two separately-computed 300s are distinct objects. CPython 3.15 changed the interning range: it interns integers up to 1025 (gh-133059). On 3.15, `300 is not 300` may be False (both sides are the same cached object), so the assertion no longer distinguishes the mutant from the original — the kill goes latent. The CI-FIX wave already applied the same treatment to the identity-test premises (257/300 → 2000). This item applies the same treatment to the remaining kill tests.

**Implementation steps:**
1. **Find all of them.** Search `tests/` for every kill test that depends on integer identity with a literal in 257–1025. The pattern is `is not <literal>` / `<literal> is not` / `is <literal>` where the literal is an int that must NOT be interned. Record every file and line. Do not rely on the two files above — the wave must prove the list is complete by searching the whole `tests/` tree and by checking the mutation baseline for entries whose kill tests use identity assertions.
2. **Change the literal 300 → 2000** in each kill test (2000 is above CPython 3.15's interning ceiling of 1025, with margin; it is the same value CI-FIX used for the identity-test premises). Update the accompanying comments to state the 3.15 interning range (gh-133059) and why 2000 is safe. Do NOT change what the test proves — only the literal.
3. **Re-prove each kill.** For each changed test, verify it still kills its mutant: run the mutant (or the relevant kill test) and confirm the test fails on the mutant and passes on the original. If a test no longer kills its mutant after the literal change, the test's logic (not just its literal) needs attention — stop and analyze rather than weakening the test.
4. **Verify:** full suite green; `tests/test_mutation.py` green (65 passed); baseline re-derived (7034/7034/1341/46, 0 stale, Counter 0 diffs). If any kill test's change shifts line numbers or removes operators, a baseline refresh is needed (same pattern as CI-FIX-2's A-refresh/B-refresh: re-anchor by line-text matching, 0 dropped, kill new live mutants, update test literals to a 0-diff Counter).

**Verification criteria:** no `is not <literal>` / `<literal> is not` kill-test assertion remains with a literal in 257–1025 anywhere in `tests/`; every changed kill test still kills its mutant (re-proven); full suite green; baseline 0 stale, Counter 0 diffs.

**Dependencies:** none. May run in parallel with R1, R2, R6, R7, R8. If a baseline refresh is needed, follow the refresh pattern (re-anchor, 0 dropped, kill new live mutants) and record it in the wave report.

### R4. Two manifest formats — post-release unification

**Priority:** Low (post-release). There are two manifest formats in the repo: the W10 shipped record format and the verifier format. They describe the same thing (a release candidate) in two shapes. This is confusing but not incorrect — both are validated, both are tested, and the release path uses them consistently. Unifying them is a cleanup, not a fix.

**Exact locations:**
- Schema: `src/textforensics/schema.py` — `"candidate-manifest": "candidate-manifest.schema.json"` (line 63), `validate_candidate_manifest` (line 229).
- Tests: `tests/test_audit_w10_a_candidate_manifest.py`, `tests/test_verify_candidate_second.py`, `tests/test_schema.py`, `tests/test_audit_w2_worker_f_schema.py`, `tests/test_precommit.py`.
- The two formats: the W10 shipped record (the candidate dossier's manifest, written by the upload/rehearsal path) vs the verifier format (the format `test_verify_candidate_second.py` and the standalone verifier consume). The wave must read both formats fully and document their exact differences before changing either.

**Implementation steps:**
1. **Document the two formats first.** Read the W10 shipped record format and the verifier format end to end. Write down, field by field: which fields each has, which fields are named differently, which fields are present in one but not the other, and which validation rules differ. Do not change anything until this document exists and is reviewed (it goes in the wave report).
2. **Decide the unified format.** The unified format must be a superset that preserves every field both formats need (no data loss), and it must keep the signed/hash preimage meanings intact (the manifest is part of the candidate's integrity story — changing a field name changes what is signed/hashed). Prefer the verifier format as the base if it is the stricter one; prefer the shipped record format if it carries fields the verifier needs. Record the decision and its justification.
3. **Migrate one side at a time.** First migrate the writer (or the reader) to the unified format, keeping the other side working (shim if needed). Then migrate the other side and remove the shim. At no point may a test be dropped or a validation weakened to make the migration pass.
4. **Update the schema.** The unified format is a public contract (`textforensics.candidate-manifest/v1` is the 14th packaged schema). If the unified format changes the schema, bump the schema version explicitly and record the migration (old manifests must either still validate or be explicitly rejected with a clear error — never silently accepted as the wrong shape).
5. **Verify:** all manifest tests pass; the standalone verifier (no package installed, 30/30 checks from W9) still passes; the no-publication rehearsal (9/9 planted-defect demos exit 1, 0 remote writes) still passes; full suite green; claims 33/33; schemas 14 OK (or 15 if a new schema version is added — record it); pre-commit 13/13; baseline re-derived (0 stale).

**Verification criteria:** exactly one manifest format remains in the codebase (grep for the old format's distinctive field names returns 0); the standalone verifier still passes 30/30; the rehearsal still rejects 9/9 planted defects; full suite green; baseline 0 stale.

**Dependencies:** run AFTER R1–R3 (it touches shared schema/verification code). Do NOT do this before a release unless Greg explicitly asks — it is marked post-release for a reason (it changes a public contract, and a contract change immediately before a release is risk without benefit).

### R5. `validate_baseline_entry` occurrence-blindness — runner fix

**Priority:** Medium. The mutation baseline refresh method has a known defect: `validate_baseline_entry` is occurrence-blind for runtime entries. This means a refresh can validate the wrong occurrence of a repeated code pattern, and a stale entry can be re-anchored to the wrong line. It has not caused a wrong baseline yet (every refresh so far has been verified by re-deriving the full Counter), but it is a correctness hole in the tooling that every future refresh depends on.

**Exact location (verified 2026-11-17):**
- `scripts/run_mutation.py:1554` — `def validate_baseline_entry(entry, project_root) -> tuple[bool, str]`. It dispatches on kind: annotation kinds go through `_validate_annotation_entry`, runtime kinds (`"unreachable-condition"`, `"unobservable-value"`, `"domain-equivalent"`, `"ulp-equivalent"`) go through `_validate_runtime_entry` (with `_validate_ulp_fields` first for `"ulp-equivalent"`). The occurrence-blindness is in `_validate_runtime_entry` (and/or in how the refresh matches entries to source spans): when the same code pattern occurs multiple times in a module, the validator does not distinguish which occurrence the entry refers to — it validates against the first (or any) matching span rather than the entry's recorded occurrence.

**Implementation steps:**
1. **Reproduce the defect first.** Construct a minimal case: a module with the same runtime-equivalent pattern at two different positions, and a baseline entry anchored to the second occurrence. Run `validate_baseline_entry` on it and show that it validates against the wrong occurrence (or that it cannot distinguish them). Record the reproduction in the wave report. Do not fix what you have not reproduced.
2. **Fix the validator to be occurrence-aware.** The entry carries a `start_pos` (line, column) and an occurrence identifier (the `id` ends with `:<occurrence>` — e.g. `NotEq_IsNot:7`). The fix must make `_validate_runtime_entry` (and the refresh path that calls it) use the entry's recorded position/occurrence to select the correct span, rather than matching on source text alone. The exact mechanism depends on the code: either pass the entry's `start_pos` through to the span lookup, or compare the entry's recorded `source_text` AND its position against the candidate spans and require both to match. Choose the minimal change that makes the validator occurrence-aware without changing its interface for callers that do not need occurrence information.
3. **Add a regression test** that constructs the two-occurrence case and asserts the validator distinguishes them (validates the correct occurrence, rejects the wrong one). The test must fail on the old code and pass on the new code (red-test-first).
4. **Re-run the full baseline validation** on the current baseline (7034 entries) with the fixed validator. It must report 0 stale (the current baseline is valid — if the fixed validator now reports entries as stale that the old validator passed, those entries must be investigated individually: either the entry is genuinely stale (fix the entry) or the validator is too strict (fix the validator). Do not bulk-drop entries.
5. **Verify:** the regression test passes; the full baseline validates 0 stale with the fixed validator; full suite green; claims 33/33; schemas 14 OK; pre-commit 13/13; baseline re-derived (7034/7034/1341/46, 0 stale, Counter 0 diffs — the total must not change unless a genuinely stale entry is found and fixed, in which case record it explicitly).

**Verification criteria:** the two-occurrence reproduction now distinguishes occurrences (regression test passes, fails on old code); full baseline validates 0 stale with the fixed validator; full suite green; baseline total unchanged (7034) unless a genuinely stale entry is documented.

**Dependencies:** run AFTER R1–R3 (it touches the mutation runner, which every wave depends on). Do NOT run it concurrently with any other wave that changes the baseline.

### R6. Benchmark bootstrap — dispatch `benchmark.yml` once with empty `baseline-ref`

**Priority:** Medium. The benchmark workflow has never run on main with a baseline, so there is no performance baseline to compare future runs against. Without a baseline, the benchmark gate cannot detect a performance regression. This is a one-time operational step, not a code change.

**Exact location (verified 2026-11-17):**
- Workflow: `.github/workflows/benchmark.yml`. `workflow_dispatch` inputs: `python-version` (default `"3.12"`, choices 3.11–3.15), `iterations`, and `baseline-ref` (description: "Git ref for performance baseline comparison (e.g., main, HEAD~1)", required false, default `"main"`). The workflow's own comment (lines 96–100) states: "the only legitimate skip is a workflow_dispatch whose `baseline-ref` input is explicitly empty, and that is reported as `status=skipped` with a reason — never as a pass. The baseline is the latest successful benchmark run on the resolved ref; its run id AND head SHA are recorded so the comparison is against one [specific run]."

**Implementation steps:**
1. Dispatch the `benchmark.yml` workflow on main **once**, with `baseline-ref` explicitly empty (and `python-version` `"3.12"`, the default). This is done via the GitHub UI (Actions → benchmark → Run workflow → set `baseline-ref` to empty) or via `gh workflow run benchmark.yml --ref main -f baseline-ref=""` (verify the exact `gh` syntax against the workflow's inputs before running it — do not guess the flag format).
2. Wait for the run to complete. Record the run id, the head SHA it ran against, and its conclusion. The run should complete with a baseline recorded (not a skip, not a failure). If it reports `status=skipped`, that means the empty `baseline-ref` was not passed correctly — re-dispatch with the input explicitly empty and verify the workflow received it.
3. Confirm the baseline is stored where the next run will find it (the workflow records the run id AND head SHA — verify both are recorded by reading the run's output/artifacts).
4. **Verify:** the bootstrap run completed successfully; a subsequent dispatch with `baseline-ref` set to `main` (the default) now has a baseline to compare against and does not skip. (Running the second dispatch is optional if the first run's output already proves the baseline is recorded — do not run extra CI jobs without a reason.)

**Verification criteria:** one successful benchmark run on main with an empty `baseline-ref`; the baseline (run id + head SHA) is recorded; a follow-up run with `baseline-ref=main` finds the baseline.

**Dependencies:** none. This is an operational step (a workflow dispatch), not a code wave. It needs no branch, no merge, and no parent verification of a code change. Record the run id + head SHA in `~/MEMORY.md` and in the goal `hidden_files/` (a short note, not a full wave report).

### R7. Code-scanning alert #1 (polynomial-redos) — currently open

**Priority:** Medium. Alert #1 is a `py/polynomial-redos` (regular-expression denial of service) finding. Its state has flip-flopped across scans. It is currently **open** (confirmed via the GitHub API 2026-11-17: `1: open — py/polynomial-redos`). A CodeQL scan runs on every push to main, so the next push will re-scan it — but "it might flip to fixed on the next scan" is not a plan. The finding must be investigated on its merits.

**Implementation steps:**
1. **Read the alert.** Fetch alert #1 via the API (`gh api repos/strmt7/TextForensics/code-scanning/alerts/1`) and read its full detail: the rule, the file and line, the data-flow path, and the CodeQL message. Record all of it in the wave report.
2. **Determine whether it is real.** Read the flagged regular expression and the code that uses it. Ask: can an attacker (or an untrusted input) supply a string that makes this regex exhibit polynomial (or exponential) backtracking? Consider: is the input attacker-controlled, or is it only ever applied to trusted/internal strings? Is there a length bound on the input before the regex runs? Is the regex anchored? A ReDoS finding on a regex that only ever sees short, internally-generated strings is a false positive; a ReDoS finding on a regex applied to untrusted user input is real.
3. **If it is real, fix it.** Fix by rewriting the regex to avoid catastrophic backtracking (e.g. possessive quantifiers / atomic groups where the engine supports them, or a non-regex parser for the pattern), or by bounding the input length before the regex runs (and failing closed on over-length input). Do NOT suppress the alert with a dismissal or a `noqa` — the code-scanning fix wave's rule stands: findings are fixed by code changes, not dismissed. Add a regression test with the adversarial input that previously caused the blowup (or a timing test that asserts the regex completes quickly on it).
4. **If it is a false positive, prove it.** Write down the exact reason it cannot be triggered (input source, length bound, anchoring) with file/line references. Do NOT dismiss it in the GitHub UI without Greg's explicit permission — the standing rule from the code-scanning fix wave is that alerts are left open and documented, not dismissed. (The 20 alerts left open by that wave were documented as "cannot be fixed by a code change" — if alert #1 belongs in that set, add it to that documentation with the same rigor.)
5. **Verify:** the next CodeQL scan on main reflects the outcome (fixed → the alert flips to `fixed`; false positive → the alert remains open but is documented as unfixable-by-code with the proof in the wave report and in the repo's alert documentation). Full suite green; claims 33/33; schemas 14 OK; pre-commit 13/13; baseline re-derived (0 stale — only if a `src/` change was made; if the fix touches decision-logic code, a mutation-proof extension is needed).

**Verification criteria:** alert #1 is either fixed by a code change (and flips to `fixed` on the next CodeQL scan) or proven a false positive with a written, file-referenced proof and added to the documented unfixable set. It is NOT silently dismissed and NOT left uninvestigated.

**Dependencies:** none. May run in parallel with R1, R2, R3, R6, R8. If the fix touches `src/`, it triggers the Container and Fuzz workflows (path filter `src/**`) — read their verdicts on the merged head.

### R8. Bare `json.loads` in other fuzz targets — depth-bound them

**Priority:** Medium. CI-FIX-3 bounded JSON parsing in `src/textforensics/probe_metrics.py` (`MAX_JSON_DEPTH = 100`, `strict_json_loads`). But the fuzz targets themselves still call bare `json.loads` in many places. Those calls are in test/harness code, not in `src/`, so a RecursionError there crashes the fuzzer rather than the production code — but a crash in the harness is still a fuzz failure, and it masks whether the production code is robust. More importantly, if any of those bare `json.loads` calls mirrors a production code path (i.e. the fuzzer is testing a production parser through a bare `json.loads`), the production path may still be unbounded.

**Exact locations (verified 2026-11-17 — bare `json.loads` in `tests/fuzz/`):**
- `tests/fuzz/fuzz_api_validation.py:28` — `json.loads(text) if text.strip() else None`
- `tests/fuzz/fuzz_calibration.py:44` — `row = json.loads(raw_line)`
- `tests/fuzz/fuzz_ledger_parsing.py:56` — `record = json.loads(line)`
- `tests/fuzz/fuzz_mcp.py:45, 151, 222` — `params = json.loads(text)`, `ledger_data = json.loads(text)`, `cf = json.loads(text)`
- `tests/fuzz/fuzz_schema_validation.py:69, 81` — `json.loads(corrupted)`, `json.loads(text[:5000] if len(text) > 5000 else text)` (note: line 81 already truncates to 5000 chars, but truncation bounds length, not nesting depth)
- `tests/fuzz/fuzz_web_ui.py:88, 138, 284, 293, 312` — `message = json.loads(text)`, `json.loads(text[:cut])`, `parsed = json.loads(serialized)`, `json.loads(json.dumps(nested))`, `msg = json.loads(decoded)`
- `tests/fuzz/fuzz_enterprise_policy.py:43` — `policy_json = json.loads(text)`

**Implementation steps:**
1. **For each bare `json.loads`, determine what it is testing.** Read the surrounding fuzz target. Ask: is this call parsing fuzzer-controlled input through a production code path, or is it parsing a harness-constructed string? If it is fuzzer-controlled input, it must go through the bounded `strict_json_loads` (or an equivalent depth-bounded parse) — otherwise the fuzzer can crash the harness with a deeply-nested input and the crash tells us nothing about production robustness. If it is a harness-constructed string (e.g. `json.loads(json.dumps(nested))` where `nested` is built by the harness), determine whether `nested` can be deeply nested from fuzzer input — if yes, bound it too.
2. **Replace each fuzzer-controlled bare `json.loads` with the bounded parse** (`strict_json_loads` from `src/textforensics/probe_metrics.py`, or the appropriate bounded parser for that target's production code path). Where the target is testing a *different* production parser (not `probe_metrics.py`'s), check whether that production parser has its own depth bound — if it does not, that is a production robustness gap of the same class as the one CI-FIX-3 fixed, and it needs the same treatment (a fail-closed depth bound in `src/`, with a regression test). Do not just bound the harness and leave the production path unbounded.
3. **Add a regression test per target** (or per production parser) with a deeply-nested input (e.g. 1000 levels of `[` or `{`) that asserts the input is rejected cleanly (a `ValueError` or the parser's documented rejection) rather than a `RecursionError`. The test must fail on the old code and pass on the new code.
4. **Verify:** all fuzz targets pass locally (run the fuzz test files); run the atheris fuzz targets briefly (the CI-FIX-3 Worker B pattern: a scratch venv with atheris, a bounded run, crash dir empty) to confirm no RecursionError remains; full suite green; claims 33/33; schemas 14 OK; pre-commit 13/13; baseline re-derived (0 stale — if a `src/` change was made, a mutation-proof extension is needed for the touched modules).

**Verification criteria:** no bare `json.loads` remains on fuzzer-controlled input anywhere in `tests/fuzz/` (grep returns 0 for fuzzer-controlled calls; harness-constructed calls are documented as such with a comment); every production parser reachable from a fuzz target has a fail-closed depth bound; a deeply-nested input is rejected cleanly (no `RecursionError`) in each target; full suite green; baseline 0 stale.

**Dependencies:** none for the harness-side changes. May run in parallel with R1, R2, R3, R6, R7. If a production parser needs a depth bound, that part is a `src/` change — it triggers Container and Fuzz in CI, and it needs a mutation proof if it touches decision-logic code.

### R9. Remove the redundant out-of-repo `gen_hashed_lock.py`

**Priority:** Trivial (housekeeping). The in-repo generator `scripts/generate_hashed_lock.py` is now canonical (added by CI-FIX Worker A). The out-of-repo copy at `~/workspace/gen_hashed_lock.py` (4007 bytes, 2026-11-15) is redundant and a confusion risk — a future implementer might edit the wrong copy.

**Implementation steps:**
1. Confirm the in-repo generator is the canonical one: `scripts/generate_hashed_lock.py` exists in the repo, has `--check` mode, fails closed, and is the one referenced by CI and by this plan. (Confirmed 2026-11-17.)
2. Confirm nothing references the out-of-repo copy: grep the repo, the goal files, and `~/MEMORY.md` for `~/workspace/gen_hashed_lock.py` and `/home/hatch/workspace/gen_hashed_lock.py`. Any reference must be updated to the in-repo path first.
3. Delete `~/workspace/gen_hashed_lock.py` (move it to trash, not permanent deletion, so it is recoverable — `trash` the file rather than `rm`).
4. Record the deletion in `~/MEMORY.md` (one line: the out-of-repo copy was removed, the in-repo generator is canonical).

**Verification criteria:** `~/workspace/gen_hashed_lock.py` no longer exists; no reference to it remains in the repo or in `~/MEMORY.md`; `scripts/generate_hashed_lock.py --check` still exits 0.

**Dependencies:** none. Do this first (it takes minutes) or fold it into any other wave — it touches no repo code.

### R10. SBOM version-table literals (125/122/121) — ongoing maintenance rule

**Priority:** Ongoing (not a one-time wave). The SBOM-count test derives its expected count from the lockfile markers (`test_expected_sbom_count_by_python_version`, added by CI-FIX-2 Worker C). The derivation reproduces the CI-observed totals: 3.11 → 125 (123+2), 3.12–3.14 → 122 (120+2), 3.15 → 121 (119+2). If the lockfile's version-gated set ever changes (a new marker-gated package is added, or a package's marker changes), the derived counts change and the test's literals must be updated.

**Rule (not a wave):** whenever `requirements-pinned.txt` or `requirements-hashed.txt` changes, run the SBOM-count derivation and update the test literals if the counts changed. The derivation is in the test itself (via the generator's `requirement_applies` + vendored assets) — the wave that changes the lockfile must run the test on the grid (or at minimum verify the derived counts) and update the literals in the same commit. Never hardcode a new count without deriving it from the lockfile.

**Verification criteria (for any lockfile-changing wave):** the SBOM-count test passes on all five Pythons in CI; the derived counts match the lockfile's version-gated set.

### R11. `GOAL.md` final status update (record-keeping)

**Priority:** Trivial (record-keeping). The goal file `~/workspace/goals/textforensics-complete-revamp/GOAL.md` has a stale status section (last updated 2026-11-16, W7 — it still says W7 is "staged, NOT merged" and W8–W10 are "next"). The actual state is: W0–W10 complete and merged, CI-FIX / CI-FIX-2 / CI-FIX-3 complete and merged, CI fully green except Sigstore by design, §11 definition of done met, release decision Greg's.

**Implementation steps:**
1. Update the status section of `GOAL.md` to record the final state: main `3fff202`, CI fully green except Sigstore by design, §11 met, the report-card lead `unknown` caveat, and a pointer to this plan (`docs/REMAINING_WORK_PLAN.md`) for the remaining work.
2. This file lives in the goal workspace, not in the repo — it is not committed to GitHub. Update it in place.

**Verification criteria:** `GOAL.md` status section matches the state in §1 of this plan.

### R12. Dependabot hygiene (ongoing)

**Priority:** Ongoing (not a wave). Dependabot will keep opening PRs. The standing rules from the 2026-11-14 Dependabot merge are:
- Verify each Dependabot PR (code-safe? does it break the tools lockfile? does CI pass on it?).
- **PR #65 was CLOSED, not merged** — it downgrades setuptools/wheel and breaks the deliberately-pinned tools lockfile. If Dependabot recreates this grouping, exclude the setuptools/wheel downgrade before any merge.
- After any `requirements-pinned.txt` change, regenerate the SBOM + `requirements-hashed.txt` (in-repo generator `scripts/generate_hashed_lock.py`) + the tools lockfile if the tools set changed.
- 0 open PRs is the steady state. Do not let Dependabot PRs linger.

### R13. Detection-power research (NOT a bug fix — do not start as a wave)

**Priority:** Research program, Greg's direction required. The report-card lead stays `unknown` because human FPR is bounded low only at near-zero detection power (§1.5). Improving detection power — building a detector (or a detector ensemble, or a calibration) that achieves a supported worst-slice FPR (n≥100 per slice, Wilson upper ≤0.05) **with non-trivial detection power** (native TPR meaningfully above 0, abstention well below ~50%) — is the only way the lead ever becomes `supported`.

**Why this is not in the wave list:** it is not a code fix. It requires: choosing or building a detector with real discriminative power on the benchmark corpora; qualifying it under the W8 scientific protocol (predeclared gate, disjoint final holdout, no tuning contamination); and accepting that the current evidence says the built-in heuristic has no utility. It also touches the audit's scope boundary (the plan's human-only decisions, corpus licensing, and the "no detector-bypass" rule). **Do not start this as an autonomous wave.** If Greg wants it, he must direct it explicitly, including which detector approach to pursue and what evidence would count as success. Until then, the `unknown` lead stands and the release ships with the limitation stated.

---

## 4. Decisions only Greg can make (flagged, never decided here)

These are not work items. They are decisions. The agent must not decide them, must not change the relevant behavior silently, and must not work around them. Each one lists what the decision is, what is currently true, and what happens if it is not made.

### 4.1 Final release authorization (the release decision)

- **Decision:** whether and when to authorize a stable release (tag, GitHub release, container image, PyPI publication — each is a separate publication act; Greg must authorize each one he wants).
- **Current state:** §11 definition of done is met (§1.4). Nothing has been released, tagged, or published. The repo is ready; the decision is Greg's alone.
- **If not made:** nothing is released. The repo stays ready. There is no deadline and no penalty for waiting.
- **What the release path looks like once authorized:** see §5.

### 4.2 Sectigo bare-`rsaEncryption` acceptance

- **Decision:** whether the TSA client should accept Sectigo's bare `rsaEncryption` signature algorithm (OID 1.2.840.113549.1.1.1).
- **Current state:** Sectigo signs with the bare `rsaEncryption` OID. The client rejects it (`TimestampError: unsupported_signature_algorithm:1.2.840.113549.1.1.1`). This is a deliberate client limitation, not a bug — the client only accepts the algorithms it explicitly supports. Documented in `docs/TSA_INTEROP.md` (§3, the Sectigo row). freeTSA works (valid=True round-trip).
- **If not made:** Sectigo timestamps continue to be rejected. freeTSA remains the working TSA. No code change.
- **If Greg says accept:** implement the acceptance explicitly (add the OID to the supported set with a test that verifies a real Sectigo token end to end), and record the decision (who authorized it, when, and why) in `docs/TSA_INTEROP.md` and in the wave report. Do not change acceptance silently.

### 4.3 Standalone-verifier sha256-imprint limitation

- **Decision:** whether to extend the standalone verifier to accept non-sha256 imprints (SHA-384/SHA-512 for P-384 tokens).
- **Current state:** `_verify_timestamp_token` requires a sha256 imprint, so a P-384 token (SHA-384/SHA-512 digest) cannot reach its ECDSA path. Pre-existing limitation, flagged in `docs/TSA_INTEROP.md` ("Note on the standalone verifier"), not changed by any wave.
- **If not made:** P-384 tokens continue to be rejected by the standalone verifier. The main client is unaffected (it handles them).
- **If Greg says extend:** implement the imprint handling (accept sha384/sha512 imprints, route them to the ECDSA path, add tests with real P-384 tokens), and record the decision.

### 4.4 Keyless signing identity (CI-only, open)

- **Decision:** the identity (and credential policy) for keyless signing (cosign keyless / Rekor). Keyless *signing* is CI-only today — Rekor/TSA POSTs time out from this VM, so keyless signing has never been exercised outside CI.
- **Current state:** keyless *verification* is covered (real cosign v3.1.4 `verify-blob`, local-key 6/6, keyless bundle Verified OK — W10). Keyless *signing* is not exercised locally.
- **If not made:** keyless signing stays CI-only. Local-key signing is the exercised path.
- **If Greg decides:** record the identity and the credential policy explicitly; implement and verify the signing path.

### 4.5 IF-05 token vs authenticated session (deployment choice)

- **Decision:** whether the web/API deployment uses a token or an authenticated session (IF-05).
- **Current state:** the implementable part is closed; the deployment choice is open. The code supports both; the deployment must choose one.
- **If not made:** the deployment cannot be finalized. This does not block a release of the library/CLI, but it blocks a hosted deployment decision.

### 4.6 CodeReviewID + CIIBestPracticesID (OpenSSF registration)

- **Decision:** whether to register for an OpenSSF CodeReviewID and a CII Best Practices ID (repository governance).
- **Current state:** not registered. The OpenSSF Scorecard workflow passes in CI; the IDs are a separate registration step.
- **If not made:** no registration. No code impact.

### 4.7 Corpus licensing beyond existing permission

- **Decision:** whether to widen corpus licensing beyond the permission already held (for any new dataset used in qualification or benchmarking).
- **Current state:** licence-before-download is the standing rule. No corpus beyond existing permission is used.
- **If not made:** no new corpora. Any future qualification work must use only licence-cleared datasets.

### 4.8 Widening scope to paid/remote providers

- **Decision:** whether to widen the detector scope to paid or remote providers (e.g. a hosted detection API).
- **Current state:** the core is local-first (house rule). No paid/remote provider is integrated.
- **If not made:** the core stays local-first.

### 4.9 Historical privacy cleanup that rewrites public history

- **Decision:** whether to rewrite public history to remove personal-path occurrences (the W0 disposition recorded this as a decision, and no history was rewritten — the 26 occurrences were fixed by a forward fix).
- **Current state:** no history rewritten. The privacy gate is resolved by the forward fix.
- **If not made:** history stays as it is. No action.

### 4.10 PAN 2025 TIRA registration (Greg-side action)

- **Decision/action:** register at tira.io as `strmt7`, then request Zenodo record 14962653 with the same email. Guide: `~/workspace/goals/textforensics-complete-revamp/hidden_files/pan-tira-registration.md` (written 2026-11-06).
- **Current state:** approved 2026-11-06 (research-only). **Not yet confirmed done.** Greg has said he will not do anything manually — do not push it. It is listed here so it is not forgotten, not so it can be forced.
- **If not done:** the PAN 2025 evidence gap remains open (it was already an explicit gap in W8). It does not block a release — it is a research-registration item, not a release condition.

---

## 5. The release path (only after Greg authorizes §4.1)

Do not execute any step in this section until Greg explicitly authorizes a release. Each step is listed so the release, when authorized, is mechanical rather than improvised.

1. **Confirm the head.** The release is cut from the current main head (whatever it is at authorization time — re-verify it with the §2.2 gates on a fresh checkout, and read the CI verdict on that exact head). Do not release from a stale head.
2. **Re-run the W10 no-publication rehearsal** on the release head (the `upload --dry-run` mode, control exit 0, planted-defect demos exit 1, 0 remote writes) to confirm the release machinery still works on the current tree.
3. **Create the tag and the GitHub release** (the exact tag name and release notes are Greg's to specify — do not invent a version number). The release notes must state the report-card lead (`unknown`) and the near-zero-detection-power limitation (§1.5) plainly.
4. **Publish the container image** (if Greg authorizes it) — the Container workflow's "Promote candidate image (push tags)" job, which is skipped on non-release runs, runs on the release.
5. **Publish to PyPI** (if Greg authorizes it) — the package is the installed wheel/sdist qualified in W9.
6. **Verify Sigstore flips green.** Sigstore Verification fails by design until the first signed release exists. After the release, confirm the Sigstore check passes on the release head. If it does not, investigate before calling the release complete.
7. **Record the release** in `~/MEMORY.md` (tag, release URL, date, head SHA) and in the goal `hidden_files/` (a short release note, not a wave report).
8. **Do not create a second release, a patch, or a follow-up publication** without a separate authorization. One authorization covers one release.

---

## 6. Standing verification gates (summary — see §2.2 for the exact commands)

| Gate | Expected on the merged head |
|---|---|
| Full suite (local, fresh checkout, Python 3.12.3) | 0 failures (7137 passed / 6 skipped / 8597 subtests on `3fff202`; the counts will grow as tests are added — record the new counts, do not assume the old ones) |
| Claims | 33/33 local (×3) and 33/33 in CI |
| Schemas | 14 OK |
| Pre-commit | 13/13 Passed |
| Mutation baseline | Re-derived via tomllib; 0 stale; FULL operator Counter 0 diffs vs `test_mutation.py` literal; 0 unexplained (current total 7034 — it grows only by proven-equivalent entries, never by dropping unexplained mutants) |
| CI | Fully green except by-design Sigstore (and skipped weekly/scheduled jobs) |

---

## 7. Distilled lessons (so the next implementer does not re-learn them)

- **Local-vs-CI blind spot (the recurring one).** The local dev `.venv` has api/mcp extras and full git history; CI has only `.[dev]` and a depth-1 checkout. This masked failures four separate times (fastapi, pydantic, the W0 wrong-repo pin, the claims gate 26/33 vs 32/33). Always verify in a bare core-only venv for dependency-class changes, and always quote claims figures with their environment.
- **Validate every new action pin upstream.** The W0 wrong-repo pin (an `upload-artifact` SHA that existed only in `download-artifact`) was caught by CI, not locally. `gh api repos/<owner>/<repo>/commits/<sha>` for every new pin.
- **Paginate every `gh api` list read.** The code-scanning count error (30 vs 92) came from reading only the first page.
- **After ANY branch merge, delete the remote branch too.** Greg corrected this angrily on 2026-11-16 (two CI quick-fix branches were merged but their remote branches lingered). The remote must have only `main`.
- **Never delete a worktree until its gitignored working files are committed or copied.** A casefile Phase-1 dump (2118 lines) was lost this way.
- **Parent verification MUST include `pre-commit run --all-files` every time.** The wave-1 CI miss happened because pre-commit was not run locally. After any pre-commit run that modifies files, check `git status` and commit the fixes.
- **`/tmp` is a 512 MB tmpfs.** Never run claims concurrently with the suite (ENOSPC, 32/33). Always use absolute TMPDIR/basetemp paths outside any repo.
- **Coordinators go idle.** W2, W3, W5 all had coordinators end early. Every brief must say: do NOT end with a progress report; spawn a recovery worker if one is interrupted; verify "alive" claims yourself.
- **SBOM `--check` must run in a fresh canonical venv.** In the main `.venv` it exits 1 spuriously. Any `pyproject.toml` change must regenerate the SBOM.
- **Coverage is exact per run, not stable to the line.** ±1–2 missed lines with zero `src/` changes is not a regression.
- **A score is not a probability. Never invent benchmark results. Never lower thresholds to make a demo look better.** (House rules, `AGENTS.md`.)
- **The report-card lead stays `unknown` until a worst-slice aggregation meets the bar.** Do not relabel it, do not tune thresholds to move it, and do not hide the near-zero-detection-power limitation.

---

## 8. Appendix — evidence (all verified 2026-11-17)

- **Main head:** `3fff202` — "CI-FIX-3 refresh: ruff-format fix in new dict dumps kill test". Remote main SHA `3fff202`. Only `main` locally and remotely. 0 open PRs. 0 tags.
- **Full suite (local, fresh checkout, exact head):** 7137 passed / 0 failed / 6 skipped / 8597 subtests (864.28 s).
- **Claims:** 33/33 ×3 (local). **33/33 in CI** (Claims-to-evidence gate on `3fff202`).
- **Schemas:** 14 OK. **Pre-commit:** 13/13.
- **Baseline (re-derived via tomllib):** 7034 total / 7034 unique / 1341 positions / 46 modules / 0 stale. Kinds: return 885 / arg 5007 / unreachable 23 / unobservable 254 / domain 815 / ulp 6 / annassign 44. dsse 24, ed25519 49. W4 twin occ 7 absent.
- **CI on `3fff202` (36 check runs):** everything passes except Sigstore Verification (by design). Core 3.11–3.15 all pass. Container verified on `8446546` (`Build candidate image (no push): success`). Fuzz verified on `9a8b9ab` (`Fuzz Summary: success`; Regression 3.11/3.12/3.13 success).
- **Lockfiles:** `requirements-hashed.txt` 127 packages (120 → 127 in CI-FIX). `requirements-tools-hashed.txt` (tools set; `colorama` on win32 missing — see R2). SBOM 122 components (120 pins + 2 vendored: Chart.js v4.4.1 + @kurkle/color v0.3.2).
- **Report-card lead:** `unknown` (worst slice MAGE testbed:dialogsum 0/3, Wilson 95% upper 0.5615).
- **Code-scanning alert #1:** open — `py/polynomial-redos` (confirmed via API 2026-11-17). See R7.
- **Key reports (goal `hidden_files/`):** `audit-w10-report.md` (W10 + merge record), `audit-cifix-report.md` (CI-FIX), `audit-cifix2-report.md` (CI-FIX-2), `audit-cifix3-report.md` (CI-FIX-3), `RELEASE_PLAN.md` (goal `files/`, the plan to a stable release, §11 definition of done).
- **This plan:** `docs/REMAINING_WORK_PLAN.md` (this file), committed to main at the head recorded in the commit message.

---

*End of plan. Nothing in this document authorizes a release, a tag, or a publication. Greg alone decides the release (§4.1).*
