# TextForensics — Continuation Plan for Next AI Agent

## 📍 Current State (Commit `efc198c`, 2026-11-06)

**Repository:** https://github.com/strmt7/TextForensics
**Branch:** `main`
**History:** rewritten 2026-11-06 with the canonical identity
`Stratos <28989754+strmt7@users.noreply.github.com>` (245 commits on the
remote; junk purged; original history kept as a bundle in the goal
workspace). **Do not rewrite history again without explicit permission.**

**Phase 0** (audit / research / leakage scan) and **Phase 1** (make the
documented claims true) are done. See `docs/VERIFICATION.md` for the
measured evidence and `~/workspace/goals/textforensics-complete-revamp/
hidden_files/phase1-fixes.md` for the per-item Phase 1 record.

---

## ✅ Measured Baseline (2026-11-06, bare venv, Python 3.12.3)

```bash
pip install -e ".[dev]"        # + .[security] for bandit/pip-audit
python -m pytest tests/ -q -p no:cacheprovider \
  --cov=src/textforensics --cov-report=term -o addopts=''
# 2210 passed, 147 skipped, 0 failed in 116.59s
# Coverage: 78% (12420 stmts, 2491 missed, 4016 branches, 525 partial)

ruff check src/ tests/ scripts/            # All checks passed (0 errors)
ruff format --check src/ tests/ scripts/   # 225 files formatted
python -m bandit -r src/ -lll              # exit 0; 16 Low, 0 Medium, 0 High
python -m pip_audit --format json          # 25 findings in 3 packages (see below)
python scripts/check_claims.py             # All claims verified (exit 0)
python scripts/validate_schemas.py         # 5 OK
```

Notes:

- The 147 skips are tests for optional extras not installed by `.[dev]`
  (typer/fastapi-gated CLI and web-UI tests). The `textforensics`
  console script is only resolvable when the venv's `bin/` is on `PATH`;
  without it the 5 `SchemaCLITests` fail with `FileNotFoundError` — a
  harness artifact, not a repo defect.
- pip-audit findings: cryptography 42.0.8 (11), pip 24.0 (12), pytest
  8.4.2 (2). All have fixed versions. The `cryptography<43` cap is
  widened by Dependabot #27 in Phase 4. `pip` is the venv installer,
  not a shipped dependency.
- Lowest-coverage core modules: `typer_cli.py` 0% and `web_ui/main.py`
  2% (their extras were not installed, so their tests skip — not 0%
  because the code is untested, but because the modules were never
  imported); `ollama.py` 62%, `casefile.py` 70%, `_build_info.py` 70%,
  `cli.py` 72%, `workspace_integrity.py` 73%, `model_card.py` 79%.

---

## 🎯 Remaining Work for 100% Release-Ready

### Phase 2: Consolidation (per `hidden_files/roadmap.md`)

Reduce the ~30% over-built codebase (~68 modules / 28.8k LOC) toward
~35 modules / ~18k LOC. Candidates are listed in audit §8
(`hidden_files/audit-code.md`); do not delete anything without
checking its dependents and tests first. `pipeline.py` (802-line no-op
orchestrator) was already deleted in Phase 1 — do not reintroduce it
as a placeholder; a real DAG executor is a separate, tested feature.

### Phase 3: Uniqueness (U1–U5, U7)

- Validation-evidence registry + regime-conditioned Trust Map.
- Sealed replayable text-free case file as a legal-process artifact.
- Drift observatory over a frozen probe corpus.
- Mixed-origin / co-authorship report.
- Claim-to-evidence CI gate (the gate itself now exists and passes;
  the work is wiring new claims to real evidence).
- **Real RAID / DetectRL / M4 integration.** Only placeholder READMEs
  exist under `benchmarks/` today; the old `partially_verified`
  claims were deleted, not restated. Do not copy leaderboard numbers
  into the README; run the exact committed version and archive the
  run manifest (AGENTS.md benchmark discipline).

### Phase 4: Dependabot merges (after the rewrite lands + CI green)

Merge order (all verified clean via `git merge-tree`): #30 → #26 →
#28 → #31 → #29 → #32 → #34 (before #33) → #33 → #27 → #25 last
(#25 needs its stale `# v1.4.4 (v1)` SHA comment and `@v1` echo
fixed first). Also fix remaining Node 20 actions and pick Dependabot
over Renovate. `requirements-pinned.txt` now mirrors `pyproject.toml`
exactly and CI has a `pinned` job installing from it.

### Phase 5: Release-readiness gate

- Human false-positive rate evidence (AGENTS.md rule 10 — a release
  gate; no human-FPR evidence exists yet).
- Live-host Docker / API / web verification (not run in Phase 1).
- Docs consistency audit (README / CHANGELOG / SECURITY / RELEASE).
- pip-audit failing gate + SBOM (SBOM generation already exists in
  `.github/workflows/container.yml` via CycloneDX; CodeQL, DeepSource,
  dependency-review, dependency-audit, supply-chain, scorecard and
  codecov are all already wired — do not re-add them).
- **Explicit user permission to release. NEVER tag, release, or
  publish without it.**

---

## 🔑 Key Context for Next Agent

### AGENTS.md Hard Rules (Non-Negotiable)
1. **Score ≠ Probability** — Never present uncalibrated scores as probabilities
2. **Abstention Preserved** — Unsupported language/length/domain → abstain
3. **Provenance First** — Every detector output includes version/config/runtime
4. **No Raw Text in Case Files** — Hashes + derived evidence only (opt-in for raw)
5. **Qualitative Trust Map** — supported/partial/unknown/out_of_scope only
6. **No Detector-Bypass Features** — Editing assistance = quality, not concealment
7. **Local-First Core** — No mandatory GPU/network dependencies
8. **Tests accompany behavior changes; never weaken tests to make them pass**

### Test Patterns Established
- `test_detector_health.py` — Sync + async, frozen dataclass mutation patterns
- `test_calibration.py` — All curve methods, persistence, validation
- `test_workspace_integrity.py` — Audit chains, emergency stop, fingerprinting
- `test_detection_cache.py` — Async fixtures, LRU/TTL, compression, disk persistence
- `test_bundle.py::DecompressionCapTests` — Real 11 MB zero-filled zip/tar.gz bombs
- `test_ollama.py` — SSRF guard (loopback-only default) + response caps

### Fuzz Suite
- 16 targets in `tests/fuzz/fuzz_*.py`
- Run with: `pytest tests/fuzz/test_fuzz_pytest.py -q`
- All import cleanly without `atheris` (lazy import pattern)

---

## 🚀 Quick Start for Next Agent

```bash
# 1. Clone & setup
git clone https://github.com/strmt7/TextForensics
cd TextForensics
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# 2. Verify baseline (venv bin/ MUST be on PATH for the schema CLI tests)
PATH=$PWD/.venv/bin:$PATH .venv/bin/python -m pytest tests/ -q -p no:cacheprovider
# Should show: 2210 passed, 147 skipped, 0 failed

# 3. Check coverage
PATH=$PWD/.venv/bin:$PATH .venv/bin/python -m pytest tests/ \
  --cov=src/textforensics --cov-report=term -q -p no:cacheprovider -o addopts=''
# Should show: 78% overall

# 4. Lint + claims gate
.venv/bin/ruff check src/ tests/ scripts/
.venv/bin/python scripts/check_claims.py
```

> `/tmp` is a 512 MB tmpfs on this VM — for pip installs set
> `TMPDIR=<repo>/.tmp PIP_NO_CACHE_DIR=1`. Only `python3` exists; there
> is no bare `python` binary.

---

## 📋 Decision Log (Don't Re-Debate)

| Decision | Rationale |
|----------|-----------|
| Work only in `main` (rewritten history) | User instruction; other branches merged after conflict/dependency checks |
| No history rewriting | History rewrite done once, 2026-11-06, with user go-ahead |
| No heavyweight mandatory deps | AGENTS.md rule 14 |
| Fuzz targets lazy-import atheris | Tests run in CI without atheris installed |
| `filterwarnings: ignore::ResourceWarning` | pytest-benchmark Windows teardown race |
| Async tests use `@pytest.mark.asyncio` | `pytest-asyncio` in dev deps |
| Frozen dataclasses for evidence classes | Immutability = audit integrity |
| Ollama loopback-only by default | SSRF guard; remote hosts need explicit `allow_remote_host=True` |
| Docker image binds 0.0.0.0 *inside* the container | Required for Docker `-p` publishing; host publishing stays loopback-only (`-p 127.0.0.1:8765:8765`); port is 8765 everywhere |
| Bundle/cache decompression caps | 100 MB archive / 10 MB per member / 100 MB total / 10 MB cached result |

---

## ⚠️ Do Not

- Release/tag/publish without explicit user permission
- Push, merge, or tag from an agent checkout without being told to
- Add detector-bypass or "undetectability" features
- Present uncalibrated scores as probabilities
- Hide detector disagreement or abstention
- Commit secrets or raw text to case files
- Weaken tests to make them pass
- Re-state a claim the evidence does not support — delete it instead (see `docs/CLAIMS.yaml` header rules)

---

## 📞 Handoff Notes

Phase 1 closed the gap between what the docs claimed and what the code
does. The remaining work is **not** bug-fixing the core — it is
consolidation (Phase 2), genuinely new capability (Phase 3: real
benchmark integration, drift observatory, uniqueness features),
dependency updates (Phase 4), and the release gate (Phase 5: human-FPR
evidence, live-host verification, docs consistency).

Do not re-litigate the Phase 0 audit findings that Phase 1 fixed; they
are recorded in `hidden_files/phase1-fixes.md` with the exact commits.
