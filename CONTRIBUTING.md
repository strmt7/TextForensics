# Contributing

Contributions are welcome, especially detector adapters, calibration/benchmark infrastructure, false-positive analyses, Trust Map evidence, drift monitoring and reproducibility work.

## Read first

Before changing architecture or score semantics, read:
- [AGENTS.md](AGENTS.md) — hard development contract
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — living architecture documentation
- [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md) — trust boundaries and abstention
- [docs/CALIBRATION.md](docs/CALIBRATION.md) — calibration methodology and artifacts
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — monitoring, backup, incident response
- [docs/PRODUCT.md](docs/PRODUCT.md)
- [docs/BENCHMARKING.md](docs/BENCHMARKING.md)
- [docs/QUALITY_GATES.md](docs/QUALITY_GATES.md)

---

## Ground rules

- Every detector adapter states its model/version/family, license, supported regime and network behavior.
- Raw detector scores are not called probabilities unless calibrated.
- Detector-local calibration is not ensemble calibration.
- Benchmark claims include dataset/split identity, sample count, threshold policy and human false-positive rate.
- Final evaluation remains disjoint from threshold selection and calibration.
- Unsupported inputs preserve abstention/limitations.
- New analyzers/adapters include tests and documented failure modes.
- Core remains local-first; remote calls require explicit configuration.
- Do not put private raw text into logs or portable case files by default.
- Avoid adding correlated detectors solely to inflate detector count.
- Do not publish synthetic/demo fixture results as product accuracy.

---

## Development

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

pip install -e .[dev]
python -m unittest discover -s tests -v
```

Before a PR, work through the applicable checks in [docs/QUALITY_GATES.md](docs/QUALITY_GATES.md).

---

## Detector PRs

A detector adapter should include:
- stable detector ID/version/family,
- native score semantics,
- model/checkpoint/provider identity,
- dependency and hardware requirements,
- language/length/domain limitations,
- structured timeout/error behavior,
- license notes,
- tests,
- benchmark manifest/results before it becomes eligible for calibrated fusion.

A detector can land experimentally before full validation if it is unmistakably marked experimental and cannot silently influence calibrated top-level outputs.

---

## Performance claims

Do not add README accuracy claims from external papers. Run TextForensics against the declared benchmark and archive the run provenance first.

---

## Review Checklist

Every PR should be self-reviewed against the questions below **before** it is marked ready. These are derived from the AGENTS.md self-review section.

### Score and Probability Semantics

- [ ] Did I change score semantics? If so, is every display/serialization/CLI output updated?
- [ ] Did I accidentally call an uncalibrated score a probability?
- [ ] Did I average calibrated probabilities from different detectors? (This does not produce a calibrated average.)
- [ ] Did I emit `calibrated_ai_probability` without a corresponding `calibration_id`?

### Reliability and False Positives

- [ ] Could this change increase false positives for human-authored text?
- [ ] Is the input regime supported? (language, length, domain)
- [ ] Are calibration and test sets disjoint? (`validate_no_contamination`)
- [ ] Did I preserve abstention and warnings for out-of-scope inputs?
- [ ] Could the report be misread as proof of authorship?

### Testing and Evidence

- [ ] Did I add or update tests for the changed behavior?
- [ ] Are there tests for the failure/timeout paths?
- [ ] Do existing tests still pass?
- [ ] Is network behavior explicit? (No network by default.)

### Provenance and Reproducibility

- [ ] Are model/data licenses compatible with the project license?
- [ ] Did I record detector/model/version for any new artifacts?
- [ ] Does the change require a schema version bump?

### Architecture Consistency

- [ ] Did I keep detector observation, validation evidence, Trust Map, consensus, and provenance separate?
- [ ] Does this duplicate an existing project rather than advance TextForensics' reliability-audit identity?

**If any answer is unclear, stop and document the issue before merging.**

---

## Testing Requirements

### 2.1 Unit Tests

**Scope:** Individual functions and classes in isolation.

**Requirements:**
- Every public function has at least one happy-path test
- Every `DetectorContractError` path has a test
- Every verdict/abstention boundary has tests on both sides
- Dataclass serialization (`to_dict`, `from_dict`) is round-trip tested
- Schema validation catches all declared invariants

**Location:** `tests/test_<module>.py`

**Example patterns:**
```python
# Verify detector prediction validation
def test_prediction_requires_calibration_id_with_probability(self):
    pred = DetectorPrediction(
        schema="textforensics.detector-result/v1",
        detector_id="test",
        detector_version="1.0",
        detector_family="test",
        execution="local",
        score=0.5,
        score_semantics="test",
        verdict="ai_like",
        threshold=None,
        calibrated_ai_probability=0.7,  # Has probability
        # Missing calibration_id → should raise
    )
    with self.assertRaises(DetectorContractError):
        validate_prediction(pred)
```

### 2.2 Integration Tests

**Scope:** Multi-component workflows (engine → detectors → trust map → consensus → bundle).

**Requirements:**
- Full analysis pipeline produces valid `ForensicBundle`
- Case file seal/verify round-trip
- Drift observatory snapshot → comparison → report
- Calibration selection → contamination check → evaluation
- Provenance ledger snapshot → verify
- Multiple detectors with mixed success/failure produce valid bundle
- Robustness probes execute and produce stability scores

**Example patterns:**
```python
def test_full_analysis_pipeline(self):
    text = "This is a sufficiently long sample text for analysis..." * 20
    bundle = build_forensic_bundle(text)
    self.assertEqual(bundle.schema, "textforensics.forensic-bundle/v1")
    self.assertIn(bundle.overall, {"strong", "mixed", "insufficient"})
    self.assertFalse(bundle.input["raw_text_included"])
```

### 2.3 Mutation Testing

**Scope:** Detects insufficient test coverage by injecting faults and checking whether tests catch them.

**Tool:** Cosmic Ray 8.x (`.cosmic-ray.toml`) or Hypothesis for property-based mutation.

**Requirements:**
- All critical paths (verdict logic, threshold selection, contamination detection) must have mutations killed
- Kill rate target: ≥ 70% for new code
- Mutation results archived in `mutation-results/`

**Equivalent mutants:** a mutant that survives only because it changes text that is never evaluated — e.g. `|` inside a function annotation of a module using `from __future__ import annotations` (PEP 563) — cannot be killed by any test. Such mutants are recorded one-by-one in `mutation-baseline.toml`, each with its reason and proof (see that file's header for the design rationale and the verification). Four further kinds are accepted there too: `unreachable-condition` mutants, where a branch condition is provably dead for every replacement the operator can produce at that position, pinned to the enclosing function's source fingerprint; `unobservable-value` mutants, where a replacement value is provably unobservable for any input, pinned the same way; `domain-equivalent` mutants, where the replacement coincides with the original on every value the mutated expression can take within its enclosing function (restricted value domains, branch-established facts, zero-valued terms, a dead tiebreak, dead code, a redundant guard, or a dead `except` handler — the entry's reason must name the proof shape), pinned the same way; and `ulp-equivalent` mutants, where the replacement differs from the original only in the last few units in the last place (ULPs) of a floating-point result, pinned the same way and additionally recording `ulp_bound_ulps` (the maximum ULPs observed, a non-negative integer) and `swept_domain` (the swept domain) — both required, and an entry missing either, or with a non-integer or negative bound, is rejected. The runner re-validates every entry against the current source on each run; a stale entry fails loudly (exit 1), and the gate still fails on any unexplained survivor (exit 2). Equivalent mutants are reported separately in the summary (`equivalent`, `unexplained_surviving`) and are never counted as killed: the raw kill rate stays killed/total. The ≥ 70% target above is unchanged by this mechanism. Never add a runtime mutant to the baseline except as `unreachable-condition`, `unobservable-value`, `domain-equivalent` or `ulp-equivalent` with its proof — only mutants verified equivalent per the baseline file's proof.

**Exec timeout and resuming an interrupted session:** a full session (`--budget 0`) takes ~20 h, so it has NO wall-clock cap in the runner — the old 3600 s exec timeout killed the run mid-mutant, left a mutant baked into the source file, and produced no dump and no summary. A budgeted run keeps the scaled cap (`budget * (per-test timeout + 15)`, floored at 600 s). Pass `--exec-timeout SECONDS` only to chunk a run deliberately (`0` = no cap); on expiry the runner dumps the partial session, exits 1, and prints the resume procedure. Every run persists its generated config as the resume TOML, `mutation-results/<session>.toml`, next to `<session>.sqlite` in the repo root, before exec starts. Resume procedure, in order:

1. Restore the source. A killed exec leaves the mutant it was running baked into the module file. Check with `git status -- src/textforensics/` and restore any modified module with `git checkout -- <module file>`, then re-check that the tree is clean. Do NOT resume against a modified source: it shifts occurrence numbering and produces bogus kills / `no-test` records (measured twice, 2026-11-08 — once with 11 bogus kills in a 73-item resume, once with 15 `no-test` records).
2. Remove a stale git lock only when no git process is running: if git reports `fatal: Unable to create '.git/index.lock': File exists`, run `rm .git/index.lock` and retry. Never remove the lock while a git process is alive.
3. Resume — with the runner (preferred; it refuses to exec against a modified target module, dumps, and gates on the result exactly like a fresh run):
   `python scripts/run_mutation.py --resume cosmic-ray-full.sqlite`
   or, when the runner itself is unavailable, directly with cosmic-ray from the repo root:
   `cosmic-ray exec mutation-results/cosmic-ray-full.toml cosmic-ray-full.sqlite`
   `cosmic-ray exec` only runs the session's remaining work items: completed items are neither lost nor re-run. Sessions started before the resume TOML existed use `--resume-toml .cosmic-ray.toml` (checked-in config: same per-mutant timeout, full-suite test command — correct, just slower).
4. After the resumed exec finishes, confirm no mutant is left behind (`git status -- src/textforensics/` clean) and gate on the fresh summary (`mutation-results/summary.json`). A direct `cosmic-ray exec` resume writes no summary, so run `python scripts/run_mutation.py --resume <session>.sqlite` once afterwards — with nothing pending it just dumps and gates. A partial summary never passes: the gate fails (exit 1) while `pending > 0`, so a resumed-then-finished run is the only way to a pass.

Note the outer bound: the scheduled full run in `.github/workflows/mutation.yml` still has a 60-minute CI job timeout, so a ~20 h full session cannot complete inside CI — run it from a long-lived shell (or in `--exec-timeout` chunks with `--resume` between them) and gate on the finished summary.

### 2.4 Fuzz Testing

**Scope:** Input boundary testing for text parsing, JSON deserialization, and protocol validation.

**Tool:** Hypothesis (`@given`) or `aflfast` for C-extensions.

**Requirements:**
- Detector `detect()` must not crash on adversarial input
- `seal_case_file()` must validate input structure
- JSON schema validators must reject malformed input
- Evidence key filtering must catch all forbidden raw-text patterns

**Example patterns:**
```python
from hypothesis import given, strategies as st


@given(st.text(min_size=0, max_size=10000))
def test_analyze_text_does_not_crash(self, text):
    if not text.strip():
        with self.assertRaises(ValueError):
            analyze_text(text)
        return
    # Should not raise on any non-empty input
    result = analyze_text(text)
    self.assertIsInstance(result, AnalysisResult)
```

### 2.5 Performance Tests

**Scope:** Ensure analysis latency and memory usage remain acceptable.

**Requirements:**
- Analysis of 500-word text completes in < 5 seconds (CPU-only baseline)
- No unbounded memory growth over sequential analyses
- Performance results archived in `pytest-performance.json`

### 2.6 Merge verification (parent)

**Scope:** the parent's final verification of a rebased branch before it is
merged into `main`. The branch author's own runs do not count: the branch
must be re-verified on the exact tree that will be merged.

**Rule: verify on a tree whose bytecode state is known-fresh.** Do one of
the two:

1. **Preferred — fresh checkout:** create a new linked worktree from the
   exact rebased head *after* the branch is final
   (`git worktree add <dir> <head>`), and run the gates there. A fresh
   checkout has no `__pycache__` at all, so no stale bytecode can exist,
   and it contains only committed content, so a transient on-disk edit
   cannot survive into it either.
2. **If verifying in the same worktree:** delete every `__pycache__`
   directory first
   (`find . -name __pycache__ -type d -exec rm -rf {} +`)
   and run with `PYTHONDONTWRITEBYTECODE=1`. This removes the stale-`.pyc`
   channel entirely (no `.pyc` to be stale) regardless of runner.

Then run the **full** `tests/test_mutation.py` (not just the count test)
plus the claims gate, the schema check, and `pre-commit run --all-files`
on that tree, and check `git status` clean afterwards.

**Why:** during the policy-298 merge (2026-11-09) the coordinator's
in-worktree runs on the rebased tree all passed, but a fresh checkout at
`32e9bd1` failed `test_baseline_file_loads_with_1697_entries` — the test
asserted `Eq_LtE: 19` while the union baseline has 23. Both parents had
19, so the literal was correct for each parent and wrong only for the
union (same-number trap), and the line was untouched context in the rebase
diff, so nothing prompted the resolver to update it. The passing
in-worktree run was never explained with certainty (a stale timestamp-based
`.pyc` under a plain-import runner, or a transient on-disk 23 reverted
without a re-run — both remain possible; default pytest 9.2.0 cannot go
stale on the test file itself, since its assertion-rewrite `.pyc` is a
PEP 552 checked-hash cache). The fresh-checkout rule closes the gap under
either candidate: there is no `.pyc` to be stale, and the file on disk is
the committed file. The fresh checkout is what caught it.

**Standing lesson from the same merge:** after a union merge, diff the FULL
computed operator Counter against the file's literal, never just the
conflicted lines — counts both sides updated to the same value can still be
wrong for the union.

**Record the provenance:** the merge record should note where the
verification ran (fresh-checkout worktree path + commit hash), so it is
auditable. Save gate outputs with the command and head hash recorded in the
log itself, not just in the filename.

---

## Benchmark Discipline

### 3.1 Contamination Prevention

**Rule (AGENTS.md §12):** Training, threshold selection, calibration, and final evaluation must be disjoint.

**Before any benchmark run:**
```python
from textforensics import validate_no_contamination, fingerprint_dataset

# 1. Verify disjointness
report = validate_no_contamination(calibration_path, evaluation_path)
assert report["contamination_detected"] is False, report

# 2. Commit dataset fingerprints
cal_fp = fingerprint_dataset(calibration_path)
eval_fp = fingerprint_dataset(evaluation_path)
cal_fp.save("artifacts/benchmark/cal_fingerprint.json")
eval_fp.save("artifacts/benchmark/eval_fingerprint.json")
```

### 3.2 Evidence Requirements

Every benchmark result claim requires:

| Evidence | Where |
|---|---|
| TextForensics git SHA | Run manifest |
| Detector/model versions | Run manifest |
| Dependency lock | `requirements.txt` or `pip freeze` |
| Dataset name/version/fingerprint | Committed fingerprint file |
| Split and filters | Run manifest |
| Threshold/calibration IDs | Calibration artifact |
| Random seeds | Run manifest |
| Hardware | Run manifest |
| Runtime | Evaluation result |
| Per-slice metrics and confidence intervals | Evaluation result |

### 3.3 Run Manifest Format

```json
{
  "schema": "textforensics.benchmark-run/v1",
  "git_sha": "abc123...",
  "textforensics_version": "0.1.0",
  "detector": {
    "id": "textforensics/builtin-heuristic",
    "version": "0.1.0",
    "family": "stylometric-heuristic"
  },
  "dataset": {
    "name": "RAID-English",
    "version": "v1.0",
    "fingerprint_sha256": "def456..."
  },
  "splits": {
    "calibration": {"path": "data/cal_en.jsonl", "samples": 250},
    "evaluation": {"path": "data/eval_en.jsonl", "samples": 250}
  },
  "threshold": {
    "target_fpr": 0.01,
    "selected_threshold": 0.68,
    "calibration_id": "cal-en-v0-1-0-20261102"
  },
  "hardware": "CPU-only, Intel i7",
  "runtime_seconds": 12.5,
  "generated_at_utc": "2026-11-02T12:00:00+00:00"
}
```

---

## Release Checklist

### 4.1 Evidence Gates

Before any release (including pre-releases):

- [ ] All unit tests pass (`python -m unittest discover -s tests -v`)
- [ ] All integration tests pass
- [ ] Mutation kill rate ≥ 70% for changed code
- [ ] Benchmark results are reproducible from committed artifacts
- [ ] Calibration artifacts are valid and not expired
- [ ] Drift observatory has no critical findings for the release window
- [ ] No contamination between calibration and evaluation sets
- [ ] Human false-positive rate meets quality gate for each detector

### 4.2 Versioning (Semver)

| Change | Bump |
|---|---|
| Schema version change, calibration invalidation, threshold change, new detector family | MAJOR |
| New detector (compatible), new Trust Map dimension, new CLI command, calibration artifact update | MINOR |
| Bug fix in non-semantic code, documentation, test improvements | PATCH |

**Schema versions:** Use `/vN` suffix in schema strings. A schema change that alters field meaning requires a version bump.

### 4.3 Provenance

Every release must:

- [ ] Update `CHANGELOG.md` with version-specific entries
- [ ] Record the git SHA and version in release notes
- [ ] Archive calibration artifacts for the release
- [ ] Archive benchmark run manifests for the release
- [ ] Include detector version inventory

### 4.4 Post-Release

- [ ] Verify case files from the release validate (`verify_case_file`)
- [ ] Take a drift observatory snapshot with the release version
- [ ] Register new capability claims with `valid_until` dates
- [ ] Update Trust Map documentation with new evidence
