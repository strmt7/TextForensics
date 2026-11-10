# Development handover

## Read first

1. [AGENTS.md](../AGENTS.md): scientific/product doctrine.
2. [Repository audit](audits/2026-11-10/README.md): measured state and limits.
3. [Release-readiness plan](RELEASE_READINESS_PLAN.md): ordered work packages.
4. The five linked subsystem reports and [finding
   register](audits/2026-11-10/findings.json): source locations, reproductions,
   preconditions and acceptance tests.

**The audit is complete; implementation is not started. Do not release.** The
examined source is `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` . The later audit
commit adds documentation/evidence and navigation only. No production source,
tests, schemas, dependencies or workflow behavior were modified. Read current
main before acting; do not assume line numbers survive future commits.

## Verified state

Checked 2026-11-10; detailed results and environment scope are in [audit
evidence](audits/2026-11-10/evidence.json).

- **Full Windows extras run**
  Baseline observation: 3,961 passed, 21 failed, 4 errors, 1 skipped; 1,985
  passing subtests; exit 1

- **Existing claims gate**
  Baseline observation: Canonical Git bytes: 33/33; normal Windows converted
  checkout: 0/33

- **Installed wheel**
  Baseline observation: Core/schema import works; web assets absent and
  application construction fails

- **Sdist-derived wheel**
  Baseline observation: Source identity unknown/unverified and root contract
  metadata absent

- **Reproducibility artifacts**
  Baseline observation: Same-SHA CI wheel hashes differ in build metadata and
  RECORD

- **Exact baseline GitHub checks**
  Baseline observation: 37 records: 35 successful, 2 skipped; not all required
  work executed

- **Current analyzer inventory**
  Baseline observation: 89 open: 86 Scorecard, 3 CodeQL; matched current SARIF;
  no dismissals

- **Dependabot alerts**
  Baseline observation: 0 open at retrieval, not a universal vulnerability-free
  assertion

- **Audit scope**
  Baseline observation: All 405 tracked files inventoried; 58 runtime Python
  files; 231 Python ASTs parsed

- **Findings**
  Baseline observation: 91 numbered records plus bounded residual gaps; overlaps
  are not separate vulnerabilities

The Ubuntu/Python-3.12 lock is not a supported all-platform development lock;
Atheris has no supported wheel in the measured Windows profile. The full suite
used applicable pinned-version constraints and extras, not a successful
wholesale canonical-lock install. Red-run coverage is not release evidence. The
333-test interface and 60-test state selections are narrow green baselines, not
a replacement for the red complete suite.

## Root causes to fix first

- **Eligibility versus metadata:** records/status labels, best-slice metrics,
  incomplete observations or stale calibration can authorize stronger claims
  than the evidence permits. Fix shared decisions, not only presentation.
- **Inconsistent trust boundaries:** installed/offline verification, signing
  payloads, nested metadata and ZIP members do not cover the same assertions.
- **Wrapper-only controls:** remote consent, stop, bounds and redaction must
  protect the actual operation loops across every transport.
- **Unproven package/gate claims:** source-checkout tests hide missing package
  resources; release verification/publishing inputs are not the actual complete
  tested candidate; some success paths do not perform the work they name.
- **Nontransactional state:** stale snapshots, cached heads and failed writes
  can change rollback floors, erase independent demotions or corrupt history.

Start with W0/W1, then follow the dependency order. Every report supplies
negative cases that existing passing tests do not cover. Do not launch a broad
rewrite or inflate test counts instead of pinning these invariants.

## Reproduction and snapshot metadata

The committed evidence's `reproduction_metadata` holds the minimized
119-package profile and exact targeted-test selections; each finding links to
resolving `evidence_json_pointers`. The profile was captured from the audit
interpreter after the run, not sealed per test, so it must not be presented as
retroactive proof of environment identity. Public remote-baseline metadata
preserves saved retrieval times, endpoint/page counts and exact check/run IDs.
No new external measurement is implied by exporting those existing records.

## Operating recipes

### Re-establish a bounded baseline

Use a disposable checkout/environment and output directory, not user data.
Select a supported interpreter and set `PY` to that environment's Python; set
`OUT` to a writable disposable directory outside the source tree. Do not
hardcode a home path, drive, device or global environment. Record the exact
resolved environment and which optional tests cannot execute.

The existing Linux/Python-3.12 exact-lock path is:

```bash
"$PY" -m pip install -r requirements-pinned.txt
"$PY" -m pip install --no-deps -e .
"$PY" -m pytest tests/ -q --junitxml="$OUT/junit.xml"
"$PY" -m ruff check src tests scripts
"$PY" -m ruff format --check src tests scripts
"$PY" scripts/validate_schemas.py
"$PY" scripts/validate_agents_rules.py
"$PY" scripts/validate_pyproject_deps.py
"$PY" scripts/check_claims.py
"$PY" scripts/generate_sbom.py --check
"$PY" scripts/check_pip_audit.py
```

These are existing commands, **not** a claim that they form a complete or
currently passing release gate. Check each script's current arguments first. Do
not run evidence-seeding/measurement builders merely to make a gate green: they
can write/reseal historical evidence and may fetch external data. Use the
repository's documented platform profile when the exact lock is not applicable.
W0 must create a real consolidated verification contract, and W9 must exercise
all supported profiles and installed workflows.

### Regression and evidence discipline

- Derive the expected result independently; first observe a meaningful red
  regression at the current source boundary, then implement the fix.
- Pin selected/attempted/succeeded/failed/abstained and actual comparator
  counts. Require nonempty, correctly shaped controls before asserting equality.
- Run gates after the last edit; read exit codes and complete result counts.
  Never allow `tee` /filter pipeline status to hide the real command verdict.
- Keep artifact IDs, source SHA, tool/profile versions and raw data linkage.
  Changing a hashed or signed representation needs deliberate versioning and
  migration; do not rehash old artifacts to disguise mutation or CRLF drift.
- Build/install wheels and sdist-derived wheels outside the repository and
  outside unrelated Git worktrees. Request actual resources/entry points.
- No real user text, credentials, signing seeds, mailbox/account identifiers,
  local paths or raw environment/JUnit logs go into Git. Publish minimized
  aggregates and synthetic fixtures. Existing historical privacy candidates
  require controlled provenance-preserving cleanup, not a casual rewrite.
- No static-analysis suppressions, false-positive dismissals, weakened gates or
  new baseline exceptions. Keep genuinely unresolved findings open with their
  exact evidence.

### GitHub publication and verification

All work stays on the authorized main-only process. Use the authenticated GitHub
API through `gh` ; let it assign author and committer. Never override identity
or change global Git settings. For multi-file commits use Git Data
blobs/tree/commit, with no author/committer fields and a nonempty message;
advance the expected main parent by a normal non-force ref update. Re-read main
immediately before update so concurrent work is not overwritten.

Normalize new text blobs to the intended committed LF representation before API
upload; API blobs bypass Git clean filters. Verify the remote commit's parent,
changed-path list, file bytes, message, author and committer, then
fetch/synchronize the disposable checkout without losing unrelated work.

Read every exact-SHA check, including skipped/failed/pending conclusions:

```bash
gh api --paginate \
  "repos/strmt7/TextForensics/commits/$SHA/check-runs?per_page=100"
gh api --paginate \
  "repos/strmt7/TextForensics/actions/runs?head_sha=$SHA&per_page=100"
gh api --paginate \
  "repos/strmt7/TextForensics/code-scanning/alerts?state=open&per_page=100"
gh api --paginate \
  "repos/strmt7/TextForensics/dependabot/alerts?state=open&per_page=100"
```

Count all returned pages programmatically. Do not infer green from a tail or
from no runs immediately after push. Check-run success describes that executed
scope only; quota skips, no-op comparisons and placeholders remain open audit
work. After a write, read back the exact target before claiming it landed.

Do not dispatch release/container publishing as a verification shortcut. The
documentation-only audit change does not match the container workflow's
source/build path filters, and release publication is manually dispatched. A
future runtime change can trigger automatic container publication; W0 must
address that policy before implementation promotion, with any required owner
approval for repository/publication settings.

## Human-only versus self-completing work

Human/external decisions are limited to genuinely missing licence rights,
provider consent/credentials, external signing/trust policy, governance or
history-rewrite authorization, and eventual release authorization. Ask those in
one batch when they become prerequisites; do not invent permission.

All source fixes, synthetic tests, complete automation surfaces, packaging,
local no-publication rehearsals, supported CI, analyzer inventory, privacy
checks and cold-start documentation are autonomous implementation work. Do not
ask the owner to perform routine UI setup or manually verify features.

## Copyable continuation instruction

> Continue TextForensics development from current main. Read AGENTS.md,
> docs/HANDOVER.md, docs/RELEASE_READINESS_PLAN.md and the complete
> docs/audits/2026-11-10/ audit, inventory, evidence and finding register. The
> audit baseline is 5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb; the audit commit
> implements no fixes. Reproduce current failures, then execute W0-W10 in
> dependency order with meaningful red-green regression tests. Fix root causes
> without suppressing findings, lowering thresholds, hiding failures,
> fabricating metrics or silently changing signed/schema semantics. Preserve
> local-first consent, stop controls, privacy, abstention and exact-version
> evidence. Work on main, commit coherent verified waves through the
> authenticated GitHub API with service-assigned identity, and read back every
> remote write plus the complete exact-head check matrix. Keep all work
> background and bounded; publish no personal data. Do not create tags,
> releases, package uploads or container publications. Finish with a fully
> exercised unpublished candidate and an evidence-backed handover, not a promise
> of perfection.
