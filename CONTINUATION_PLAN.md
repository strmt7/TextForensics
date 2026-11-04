# TextForensics — Continuation Plan for Next AI Agent

## 📍 Current State (Commit `d389277`)

**Repository:** https://github.com/strmt7/TextForensics  
**Branch:** `main`  
**Last Commit:** `feat: comprehensive enterprise-grade revamp - 2235 tests passing, 86% coverage`

---

## ✅ Verified Baseline

```bash
pytest tests -q -p no:cacheprovider
# 2235 passed, 0 failed, 4 skipped (jinja2/Python 3.15 compat)

# Coverage: 86% overall (10913 stmts, 1343 miss)
# ruff check src/ tests/  →  CLEAN
```

---

## 🎯 Remaining Work for 100% Release-Ready

### Phase 1: Close Coverage Gaps (Target: ≥95% overall)

| Module | Current | Target | Strategy |
|--------|---------|--------|----------|
| `typer_cli.py` | 31% | 85%+ | Add CLI integration tests using `typer.testing.CliRunner` |
| `ollama.py` | 54% | 85%+ | Mock `aiohttp.ClientSession` for all HTTP paths |
| `cli.py` | 73% | 85%+ | Test all command entry points via `CliRunner` |
| `web_ui/main.py` | 82% | 90%+ | Test FastAPI routes with `TestClient` |
| `model_card.py` | 79% | 90%+ | Test EU AI Act card generation paths |
| `_build_info.py` | 69% | 90%+ | Test build metadata generation |
| `pipeline.py` | 87% | 95%+ | Test orchestrator DAG execution paths |
| `workspace_integrity.py` | 71% | 85%+ | Test fingerprint/git/config paths |

### Phase 2: Security & CI Hardening

| Task | Status | Notes |
|------|--------|-------|
| CodeQL analysis (Python + Actions) | ❌ | Add `.github/workflows/codeql.yml` matching user's other repos |
| DeepSource configuration | ❌ | Add `.deepsource.toml` matching patterns |
| Secret scanning / push protection | ❌ | Enable in repo settings + gitleaks workflow |
| SBOM generation | ❌ | Add to release workflow (`cyclonedx-bom`) |
| Dependency review | ❌ | Add to PR workflow |
| Scheduled dependency audit | ❌ | Weekly `pip-audit` / `dependabot` |

### Phase 3: Packaging & Release Validation

| Task | Status |
|------|--------|
| Clean wheel/sdist build (`python -m build`) | ✅ Verified |
| `twine check dist/*` | ✅ Verified |
| Docker image build + healthcheck | ❌ |
| README/CHANGELOG/SECURITY/RELEASE docs consistent | ⚠️ Needs audit |
| Codecov integration (matching user's other repos) | ❌ |

### Phase 4: Final Gate

- [ ] All CI gates green on PR branch
- [ ] Self-review against AGENTS.md PR checklist
- [ ] **Explicit user permission to release** (NEVER auto-release)

---

## 🔑 Key Context for Next Agent

### AGENTS.md Hard Rules (Non-Negotiable)
1. **Score ≠ Probability** — Never present uncalibrated scores as probabilities
2. **Abstention Preserved** — Unsupported language/length/domain → abstain
3. **Provenance First** — Every detector output includes version/config/runtime
4. **No Raw Text in Case Files** — Hashes + derived evidence only (opt-in for raw)
5. **Qualitative Trust Map** — supported/partial/unknown/out_of_scope only
6. **No Detector-Bypass Features** — Editing assistance = quality, not concealment
6. **Local-First Core** — No mandatory GPU/network dependencies

### Test Patterns Established
- `test_detector_health.py` — Sync + async, frozen dataclass mutation patterns
- `test_calibration.py` — All curve methods, persistence, validation
- `test_workspace_integrity.py` — Audit chains, emergency stop, fingerprinting
- `test_detection_cache.py` — Async fixtures, LRU/TTL, compression, disk persistence

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
python -m venv .venv && .venv\Scripts\activate  # Windows
pip install -e ".[dev]"

# 2. Verify baseline
pytest tests -q -p no:cacheprovider
# Should show: 2235 passed, 0 failed, 4 skipped

# 3. Check coverage
pytest tests --cov=textforensics --cov-report=term -q -p no:cacheprovider

# 4. Lint
ruff check src/ tests/
```

---

## 📋 Decision Log (Don't Re-Debate)

| Decision | Rationale |
|----------|-----------|
| Work on dedicated branch off main | No history rewriting |
| No heavyweight mandatory deps | AGENTS.md rule 14 |
| Fuzz targets lazy-import atheris | 122 tests now run in CI |
| `filterwarnings: ignore::ResourceWarning` | pytest-benchmark Windows teardown race |
| Async tests use `@pytest.mark.asyncio` | `pytest-asyncio` in dev deps |
| Frozen dataclasses for evidence classes | Immutability = audit integrity |

---

## ⚠️ Do Not

- Release/tag/publish without explicit user permission
- Add detector-bypass or "undetectability" features
- Present uncalibrated scores as probabilities
- Hide detector disagreement or abstention
- Commit secrets or raw text to case files
- Weaken tests to make them pass

---

## 📞 Handoff Notes

The repo is **technically solid** for core forensic functionality. The remaining work is:
1. **CLI/UI test coverage** (straightforward but verbose)
2. **CI/CD wiring** (copy patterns from user's other repos)
3. **Documentation consistency audit**

All core modules have comprehensive tests and ≥85% coverage. The architecture is clean, bugs are fixed at root cause, and the test suite catches regressions.

**Next agent should start with Phase 1 (typer_cli + ollama coverage) and Phase 2 (CI hardening) in parallel.**

---

*Generated at commit `d389277` — ready for seamless continuation.*