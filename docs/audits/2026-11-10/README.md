# Repository audit and release-readiness assessment

**Decision: not release-ready.** This commit contains review evidence and a
concrete implementation plan only. It does not fix product behavior, upgrade
dependencies, change workflow policy, create a tag or publish a release.

- Audited main snapshot: `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` .
- Audit date: 2026-11-10.
- [Implementation plan](../../RELEASE_READINESS_PLAN.md).
- [Successor handover](../../HANDOVER.md).
- [Machine-readable findings](findings.json), [review
  inventory](inventory.json), and [measured evidence](evidence.json).

## Executive assessment

The repository has substantial useful engineering: a dependency-light core,
explicit detector protocols, qualitative trust states, versioned case formats,
content hashes, an independent offline verifier, dataset licence refusals and
large tests. The stated scientific contract in `AGENTS.md` is stronger than
several implemented boundaries. More tests and green badges have not prevented
fail-open state transitions, unsupported scientific certainty or broken
installed-package workflows.

The principal problem is **inconsistent enforcement between layers**:

1. Evidence metadata is mistaken for eligibility: best-slice FPR, old or
   inapplicable evidence, incomplete probe runs and calibration declarations can
   become supported/validated output.
2. Independent verification paths disagree: signatures can authenticate only
   part of the displayed assertions, offline verification misses installed
   checks, and mutable/container state can escape the intended integrity scope.
3. Execution policy lives in wrappers: default plugin discovery can invoke
   remote adapters without request consent; WebSockets and observatory loops
   bypass stop checks; redirects escape an initial loopback-only policy.
4. Interfaces do not consume their own canonical data: the UI fabricates
   probabilities, throws on actual bundles and downloads JSON as CSV/HTML.
5. Release gates test narrower properties than their labels: missing package
   assets, lost sdist identity, non-identical wheels and placeholder integrity
   checks coexist with a successful exact-SHA Actions overview.

This requires prioritized boundary repairs and fresh scientific qualification,
not another broad rewrite or a cosmetic documentation-only declaration of
stability. No finite scan can promise perfection or enumerate every bug.

## What was actually covered

The audit inventories **all 405 tracked files**, including **58 runtime Python
files**, **28 scripts**, **17 workflow files**, all **12 packaged JSON
schemas**, frontend assets, packaging/configuration, evidence/validation
registries, corpus manifests, SBOM, tests and documentation. All **231 tracked
Python files** were structurally parsed. See `inventory.json` for canonical Git
blob IDs, SHA-256 values, sizes, physical line counts and per-file review modes.

All first-party runtime Python files received source review across disjoint
primary partitions, with cross-boundary follow-up. First-party JS/HTML/CSS
received source review; the minified third-party Chart.js asset received a
complete-byte structural/sink scan and syntax check, **not** an exhaustive
independent third-party semantic audit. Matching tests were reviewed in full or
in explicit risk-focused slices; unreviewed bodies were not quietly counted as
manual review. Large docs/baselines received structural/claim/link or aggregate
scans plus targeted reading, not a claim of manually proving every historic
assertion.

### Detailed reports

- **Scientific core and data**
  Report: [CORE.md](CORE.md)
  Numbered records: 11

- **Crypto/artifact/provenance**
  Report: [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md)
  Numbered records: 23

- **Interfaces/integrations**
  Report: [INTERFACES.md](INTERFACES.md)
  Numbered records: 19

- **Stateful reliability/policy**
  Report: [STATEFUL_RELIABILITY.md](STATEFUL_RELIABILITY.md)
  Numbered records: 22

- **Engineering/supply chain**
  Report: [ENGINEERING.md](ENGINEERING.md)
  Numbered records: 16

There are **91 numbered finding records**, plus explicitly bounded residual
risks and scientific limitations. These are not 91 independent vulnerabilities:
reports intentionally cross-reference overlapping root causes. IDs are stable
work identifiers, not CVE assignments or measured exploitability scores. Every
finding gives source locations, observed versus expected behavior, preconditions
and concrete fix/acceptance requirements.

## Fresh execution evidence

- **Full Windows extras pytest run**
  Actual result: **3,961 passed; 21 failed; 4 errors; 1 skipped; 1,985 passing
  subtests**, exit 1
  What it does not prove: Not a green release suite; subtests are not additional
  ordinary tests

- **Claims on canonical Git bytes**
  Actual result: **33/33 passed; 34/34 registry hashes valid**
  What it does not prove: Existing claim checks do not prove all the underlying
  properties

- **Claims in ordinary autocrlf Windows checkout**
  Actual result: **0/33 passed; 34 hash failures**
  What it does not prove: Conversion is not evidence tampering

- **Bandit runtime scan**
  Actual result: **26 Low, 0 Medium, 0 High**, exit 1
  What it does not prove: No proof of application-level correctness/privacy

- **Bounded interface selection**
  Actual result: **333 passed**, no failed/error/skipped
  What it does not prove: Not full UI execution or full-suite acceptance

- **Bounded state selection**
  Actual result: **60 passed**
  What it does not prove: Existing tests miss demonstrated failure modes

- **Wheel/sdist build and Twine**
  Actual result: Build/metadata checks succeeded
  What it does not prove: Not package completeness or preserved source identity

- **Clean installed wheel outside checkout**
  Actual result: Core/schema import worked; web factory **failed**,
  static/templates absent
  What it does not prove: Checkout-only tests cannot qualify the installed web
  product

- **Sdist-derived wheel outside Git**
  Actual result: Source identity **unknown/unverified**; root contracts absent
  What it does not prove: Direct-wheel success does not qualify sdist users

- **Independent parent recheck**
  Actual result: Eight bounded subsystem probe batches completed, plus fresh
  core probes
  What it does not prove: Probe exit 0 records observations, including broken
  behavior; it is not test green

The full suite used Python 3.12.10 with applicable pinned-version constraints
and extras. The canonical lock is explicitly Ubuntu/Python-3.12 oriented and
contains Linux-only Atheris; it was **not** successfully installed wholesale on
Windows. Do not call this a canonical-lock Windows pass. The one full-suite skip
is recorded, not removed. A first test-launch wrapper was interrupted before the
completed run; only the final completed run above is the baseline. Coverage
collected from the red run is diagnostic, not accepted as a passing release
measurement. Historical 82%/78.49% coverage discussions remain history, not
substituted current measurements.

Reproduction uses small synthetic inputs, temporary data and bounded
protocol-faithful loopback servers. No real detector provider/model/GPU call,
live TSA revalidation, raw external corpus download, browser rendering,
container execution or release-publication rehearsal was performed. Existing
network/dataset/TSA records were assessed as dated provenance, not rerun
results.

## Highest-priority demonstrated blockers

- **Scientific certainty**
  Reproduced behavior: UI invents 85%, 15%, 50% authorship probabilities
  Finding IDs: IF-04

- **Remote consent/stop**
  Reproduced behavior: Default API report invokes recording remote adapter four
  times; stopped WebSocket still executes
  Finding IDs: IF-01/03, S08

- **Endpoint policy**
  Reproduced behavior: A 307 forwards a synthetic prompt beyond the initially
  allowed loopback host
  Finding IDs: IF-02

- **Complete revalidation**
  Reproduced behavior: 399 of 400 attempts fail, yet two runs clear demotion and
  establish temporal support
  Finding IDs: S01

- **Anti-rollback**
  Reproduced behavior: Stale policy objects persist a floor change from 10 to 1
  Finding IDs: S02

- **FPR coverage**
  Reproduced behavior: An applicable CI upper bound 0.9 is hidden by selecting
  0.01
  Finding IDs: CORE-02

- **Calibration integrity**
  Reproduced behavior: Mutable parameters change a probability while eligibility
  and stored hash remain unchanged
  Finding IDs: CORE-04/05

- **Signature binding**
  Reproduced behavior: Watermark verifier accepts changed payload fields under
  the old signed digest
  Finding IDs: C01

- **Offline parity**
  Reproduced behavior: A production-packed signed case can pass offline while
  combined installed verification rejects it
  Finding IDs: C04

- **Container completeness**
  Reproduced behavior: Duplicate ZIP members are accepted while original
  manifest signature remains verified
  Finding IDs: C05

- **Provenance**
  Reproduced behavior: Public audit-log wrapper returns valid after class
  verifier detects missing genesis
  Finding IDs: C07

- **Platform/install**
  Reproduced behavior: Windows key save raises and leaks a descriptor; installed
  wheel cannot start the web app
  Finding IDs: C11, ENG-01/09

- **Build proof**
  Reproduced behavior: Exact-SHA CI wheels differ, yet reproducibility is
  non-gating and summary says deterministic
  Finding IDs: ENG-03

- **Publication**
  Reproduced behavior: Confirmed release dispatch need not satisfy the complete
  exact-SHA acceptance surface
  Finding IDs: ENG-04/05/06/14

Severity is conditional on the actual feature/deployment and trust anchor. For
example, C05 is an archive/manifest completeness defect, not a SHA-256
collision; an independently pinned whole-archive digest detects that modified
archive. Local Python plugins are not claimed to be sandboxed. Test-only scanner
observations are not described as production exploits.

## Exact-SHA GitHub state at the audit baseline

The paginated baseline query returned **37 completed check-run records**: **35
successful and 2 skipped**, across 36 unique names. DeepSource was skipped
because its quota was exhausted, and the full mutation job was skipped for the
push event. Neither is a passing execution of that work. Historical failed
workflows are distinguished from the successful Linux-centric baseline matrix.

The paginated code-scanning inventory contained **89 open observations**: **86
Scorecard and 3 CodeQL**. All 89 rule/path/line tuples matched current-SHA
SARIF. They are not automatically stale, but they are also not 89 confirmed
exploits: many concern permissions/governance/pinning, and two CodeQL findings
are in fixtures. There were **0 open Dependabot alerts** in that retrieval. See
ENG-07/10/11/13 and the governance section for precise limitations. No alert was
dismissed, no suppression added and no repository setting changed.

The report describes the audited SHA, not a future promise that every external
service will stay green. Check the eventual documentation commit's exact SHA
separately. Green checks on that later docs-only commit still do not fix these
runtime findings.

## What remains sound or intentionally limited

- Core runtime dependencies remain optional; the minimal core imports and
  analyses can run without a GPU stack.
- Detector observations preserve native semantics, abstention and failures in
  several main paths; consensus correctly withholds an unvalidated top-level
  ensemble probability. The UI contradicts that good core behavior.
- Licence-blocked dataset loaders refuse access; retain those refusals.
- U1 evidence is currently preliminary/partial where required. Do not improve
  labels without independent evidence.
- Clean hash/signature controls verify in the bounded tests. No break of Ed25519
  against a genuine generated trusted key or of SHA-256 is claimed.
- RFC 3161 verification explicitly does not establish PKI trust/qualification. A
  synthetic self-signed token is not newly discovered evidence of a missing
  trust store when that is the documented limited contract.
- Finite KS, Wilson, PSI, ECE/Brier and Holm calculations checked against
  independent definitions matched for the tested cases. Nonfinite and
  denominator/eligibility handling still fail at surrounding boundaries.

## Privacy and evidence handling

### Digest data representation

Public Git/object and artifact digest literals are stored unchanged in
[digests.tsv](digests.tsv), an explicit unquoted golden-data table. JSON values
use `digest-ref:D00001` tokens into that table. Resolve each token to its exact
`literal` value before comparing source identities or hashes; embedded JSON
strings use the same substitution. A lossless round-trip of all three JSON
documents to the original observations was verified. This is not encryption,
redaction, a secret allowlist or a scanner-baseline exception. No digest was
split or encoded; the original values remain directly reviewable data.

Published material includes repository-relative paths, code/artifact hashes,
aggregate counts and synthetic canary observations only. It excludes raw test
logs/JUnit host fields, private signing material, personal accounts/mailboxes,
local usernames/home paths and source document contents. Existing tracked
host-path candidates are referenced by location only, not copied.

Audit probes stayed outside tracked product files; their generated keys and
scratch scripts are not shipped. `evidence.json` is a minimized observation
record, not a cryptographically authenticated issuer statement or an executable
regression suite. The detailed constructions/expected results are the work
specification for the next agent's real regression tests.

## Next action

Start W0 and W1 of [the implementation plan](../../RELEASE_READINESS_PLAN.md),
then proceed in dependency order. Close findings only with a source fix,
meaningful regression tests, preserved compatibility/privacy and current
exact-head verification. **Do not release.**
