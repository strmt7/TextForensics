# Release-readiness implementation plan

Baseline: `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` . Prepared and checked
2026-11-10. **Nothing below has been implemented by the audit commit. Do not
tag, publish, create a release, push a container, or promote a package while
executing this plan.**

Read [the audit](audits/2026-11-10/README.md), its five detailed reports, [the
finding register](audits/2026-11-10/findings.json), and [the
handover](HANDOVER.md) first. Earlier roadmaps remain historical context; this
plan governs the newly demonstrated release blockers.

## Definition of the target

A stable candidate means the advertised workflows are correct, bounded,
privacy-preserving, portable, reproducibly packaged and backed by independently
checkable scientific and engineering evidence for the exact candidate SHA. It
does not mean a perfect detector, proof of authorship, zero possible bugs, or a
mathematically guaranteed absence of false positives.

Keep the product an **independent reliability-audit layer**, not a confident
wrapper around an unvalidated classifier. Optional features may stay
experimental only if the public contract, packaging, transports and visible
outputs consistently say so. Experimental status does not excuse incorrect
signatures, raw-text leakage, unsafe dispatch or fabricated probabilities.

## Non-negotiable execution rules

1. Re-read current main and reproduce a finding before fixing it. References
   below point at the baseline; later source lines and statuses will change.
2. Develop on main under the owner's existing publication policy. Commit small,
   coherent source-fix waves; do not create feature branches or a release.
3. First add meaningful red regression tests from the stated expected result;
   then fix the source and run the complete applicable gates. Expected numbers
   come from specifications/independent engines, not current product output.
4. Never suppress/dismiss findings, grow baselines to hide failures, lower
   thresholds, remove warnings, drop failing tests, silently average missing
   terms, or relabel unknown evidence as supported.
5. Preserve public schema and signed/hash preimage meanings. Version changed
   contracts, provide explicit legacy verification/migration behavior, and test
   old genuine fixtures. Never silently rehash history as if unchanged.
6. No real user text/accounts/keys in fixtures, reports or commits. Tests use
   reserved example domains, ephemeral keys and disposable data directories.
7. No foreground applications or automatic browser opens. Keep workloads
   bounded; do not access user caches, secret stores or external providers
   without the necessary explicit authorization and supported capability.
8. After the last edit, run gates, read their actual verdicts, then publish the
   commit separately through the authenticated GitHub API without manually
   setting author/committer. Read back SHA, identity, contents and all checks.
9. A green documentation commit does not close a baseline runtime finding. Only
   a reproduced regression test plus source fix and exact-head evidence may
   change a finding to resolved.

## Dependency order

```text
W0 scope and honest gates
  -> W1 shared execution/privacy policy
  -> W2 scientific evidence and calibration boundaries
  -> W3 artifact/signature/offline verification
  -> W4 durable state, policy and observatory
  -> W5 interfaces and actual frontend contracts
  -> W6 package/build/input provenance
  -> W7 complete security/dependency/integrity gates
  -> W8 independent scientific validation
  -> W9 cross-platform installed-system qualification
  -> W10 no-publication rehearsal and candidate dossier
```

Work within a wave can overlap only with explicit disjoint ownership and a
stable shared contract. There must be one integrator for registry/schema,
report-policy and signed-artifact changes; parallel independent reviews are
safer than concurrent edits to those shared boundaries. W6 can begin once the
relevant contracts are fixed, but cannot be accepted before runtime repairs.

## W0 — Freeze scope and make verification honest

**Owner role:** integrator/release engineer. No product promotion.

- Record the current SHA, dirty status, interpreter, exact environment and all
  gate commands. Preserve the audit baseline as history.
- Define supported OS/interpreter/extra/deployment profiles and an exact
  operation inventory: CLI, both HTTP surfaces, MCP and UI actions. Declare
  local-only versus remotely accessible deployment policy explicitly.
- Specify the candidate's immutable evidence manifest: source tree/SHA, package
  inputs, schema versions, tests, scientific run IDs, artifacts and their
  digests. Required gates must distinguish pass, failure, skipped, unavailable,
  not-applicable and zero executed work.
- Add a canonical local verification command that mirrors the complete CI
  surface. The repository currently has no trustworthy single command proving
  all the release criteria; do not document an invented existing command.
- Repair obviously vacuous/ignored verification paths first (ENG-07/13/16),
  without claiming runtime defects are fixed. Put publication behind an explicit
  candidate-promotion boundary (ENG-04/05/06/14).

**Acceptance:** inject one synthetic defect per gate class and observe failure;
zero tests, missing tools, absent baseline/artifacts, child exit 2, stale SHA,
and required skipped work cannot yield pass. Clean controls execute positive
work. A no-publication test proves every publishing function is untouched.

## W1 — Centralize execution, consent, stop and privacy boundaries

**Findings:** IF-01/02/03/05/07/08/09/11; S08; C03/C06/C12; CORE-07/09 and
input-budget residuals.

- Define one execution-policy object and validated command boundary carrying
  allowed local/remote adapters, explicit outbound consent, input/output byte
  limits, deadlines, cancellation and retention choices.
- Enforce it in report construction and detector loops, not just transport
  middleware. Check stop before each new operation and between detector/probe
  calls. A stopped/incomplete operation cannot become evidence of a clean run.
- Validate every redirect or disable redirects; stream successful and error
  bodies under byte caps before buffering. Keep prompt/response text out of
  public exceptions and request-validation output.
- For the local web console, establish exact Host/Origin policy and an
  unpredictable same-origin/session credential for mutating operations as
  appropriate. Apply bounded schemas to WebSocket frames, shared results and
  retained history; render imported data as literal text.
- Separate ephemeral reviewer text from portable evidence. Apply the default
  raw-text exclusion to the whole completed case and explanation exports,
  including nested process metadata and summary/top lists.
- Scan adapter source without importing it. Absence of heuristic findings is not
  proof of network isolation; uninspectable/transitive/native code is unknown.
  Installed Python plugins remain trusted code, not a sandbox.

**Acceptance:** every default transport makes zero calls to a recording remote
adapter; explicit consent authorizes only selected IDs. Stop before/after
connect prevents subsequent work. Disallowed redirect receivers get zero
requests. Over-budget readers close early. Canary text is absent from default
exports/errors/logs; permitted raw-text opt-in is explicit and accurately
labelled. Rejected archives never reach a less-restricted second reader.

## W2 — Repair evidence selection, calibration and abstention

**Findings:** CORE-01 through CORE-07, CORE-10/11; C10/C19/C23; IF-04/12/19;
S04/S07/S09/S10/S21/S22.

- Specify and enforce one support-eligibility model across V2 evidence, U1/V3
  and capability-ledger views. Make the default report's selected registry
  version explicit; do not leave new validation invisible to normal surfaces.
- Require applicable held-out evidence, exact detector/provider/model/config
  epoch, freshness, sufficient samples, artifact integrity and contamination
  proof. Record unverified declarations without promoting them to support.
- Use relevant/worst-required human-FPR slices, never best-slice `min` .
  Preserve operating point, native direction, sample/coverage denominators, and
  conflicting or missing evidence.
- Version temperature input semantics; independently test logit/probability
  transformations. Make calibration content deeply immutable and exact-identity
  bound. Do not retain old metrics after changing the mathematical map.
- Require document/group-level split disjointness in every evaluation entry;
  unknown checks fail release eligibility, and diagnostics remain diagnostic.
- Validate finite numeric domains/counts, strict JSON, unique complete Trust Map
  dimensions and nested schemas at every import/use boundary.
- Keep missing ensemble/family probabilities null. Short/unsupported/failed
  analysis abstains or reports unknown, never decorative certainty. Preserve
  attempted/succeeded/failed/abstained counts in explanations and robustness.
- Separate weak segment observations, operation hypotheses, HART terminology and
  actual validated authorship conclusions. Partial/expired/wrong-detector
  segment records cannot lift withholding.

**Acceptance:** all core synthetic failures become meaningful failing-then-
passing tests. Temperature matches an independent oracle; mutated artifacts
cannot remain eligible. Reordering evaluation rows cannot defeat contamination.
Adverse matching FPR evidence cannot be hidden by a better slice. Equivalent
higher/lower-tail detectors produce equivalent ROC/TPR/FPR. Nonfinite values
fail boundedly and no unsupported probability reaches any output surface.

## W3 — Unify artifact authenticity and independent offline decisions

**Findings:** C01 through C14, C18 through C23; CORE-10.

- Bind watermark payload to the signed digest in both verifiers; enforce a
  defined trusted-key validity policy using authenticated fields.
- Bind case signer assertions/fingerprint and signed-custody successor semantics
  under a deliberate contract version. A self-asserted identity is not an
  externally authenticated identity, and a signed time is not a TSA.
- Require combined validation before packaging. Maintain an independently
  implemented stdlib standalone verifier, but test the same acceptance/rejection
  corpus through installed, packed and truly no-install paths.
- Reject duplicate/ambiguous ZIP members and manifests before reading; require a
  one-to-one manifest/container relationship. Apply caps once and never
  decompress after rejection. Validate even empty legacy containers globally.
- Fix Windows private-key creation and descriptor cleanup without weakening
  ownership/access controls. Constrain watermark key IDs to the configured key
  store and make no-clobber publication atomic.
- Correct RFC 3161 grammar/error parity and independent EC curve/hash selection;
  use externally generated/independently verified valid and invalid fixtures.
  Preserve the documented distinction between signature math and PKI trust.

**Acceptance:** intact genuine controls verify across all entry points; mutated
authenticated fields, invalid semantics, duplicate names, malformed
shapes/times, expired-key policy violations and oversized members reject
consistently. Exact 0/1/2 exit semantics remain. Native Windows and POSIX key
lifecycle tests prove cleanup, permissions and no overwrite. Independent engines
validate supported curve/hash combinations; live TSA results, if collected,
remain separately dated observations with a declared trust policy.

## W4 — Make provenance and reliability state transactional

**Findings:** C07/08/09/15/16/17; S01 through S22 and the state report's
additional contract problems; CORE-04/08.

- Version an unambiguous directory manifest/hash preimage and explicit anchored
  state transitions binding calibration, benchmark and detector identities. A
  copied/equal chain cannot authorize changed roots.
- Lock reload/check/advance/persist transactions for audit logs, policy floors
  and registry/run updates. Do not advance in-memory heads before persistence;
  validate loaded genesis, indices, cached roots/heads and required-file states.
- Make U3 run completeness an invariant against the selected item set. Retain
  failed/missing/abstained observations, keep manual demotions independent, and
  permit revalidation/temporal support only from genuinely complete runs.
- Treat adapter/provider/model/config/corpus changes as evidence epochs;
  evaluate chronology before filtering, including intervening partial breaches.
  Enforce sample floors on actual paired observations.
- Validate imported snapshots and run manifests against per-item corpus links,
  strict schemas, finite values and immutable append-only run identities.
- Repair cache admission/replacement accounting, age/config invalidation,
  deep-copy/immutability, locking, lifecycle persistence and atomic validated
  loads. Budget resident state, not only a compressed serialization.
- Repair retry readiness/backoff/Retry-After and single half-open ownership;
  waiting must not consume a call attempt. Repair health threshold direction,
  staleness, unknown data, persisted enum types and bounded alert retention.
- Enforce enterprise/capability policies through the real command surface;
  validating a policy document alone does not apply it to inference.

**Acceptance:** the verified 400-item/399-failure run never clears demotions or
advances temporal support. Independent stale policy instances cannot lower
revision 10 to revision 1. Deterministic stale-writer/cache interleavings stay
coherent; a failed write leaves the prior durable state recoverable. Failures
between registry and run publication recover without dangling references. Use
tiny budgets, fake clocks and explicit interleavings before bounded
cross-process tests.

## W5 — Restore complete, truthful interfaces

**Findings:** IF-04/05/06/10/13/14/15/16/17/18/19; state transport limits.

- Route all public operations through the shared policy/command channel. Decide
  supported API/CLI/MCP equivalents for every UI action; pin OpenAPI, MCP tool
  names/schemas and the operation inventory together.
- Repair real frontend bundle keys, DOM IDs, streaming function wiring and HTTPS
  WebSocket selection. Reuse collected observations instead of running the
  detector again to construct the complete response.
- Repair application-scoped collaboration lifecycle and bounded history.
- Make downloads actual JSON/CSV/HTML with consistent MIME/extension/content;
  validate escaping and spreadsheet formula handling.
- Use the supported Ollama embed endpoint and explicit booleans. Share a
  bounded, status-aware session/stream lifecycle for chat and generation,
  including fresh-client setup, cancellation and response closure.
- Replace positive diagnostics placeholders with actual configured checks or
  unknown; preserve optional criticality, real version and valid metric
  exposition. Render Rich/user text literally.

**Acceptance:** run the actual JavaScript against real server-produced bundles;
no schema/DOM/function exceptions, invented probabilities or missing warnings.
Every download parses independently. Real MCP discovery/dispatch and loopback
wire tests match the intended surface. Reconnect/disconnect releases sockets and
users; cancellation leaves no worker/session leak. A browser/rendering
acceptance run must occur only in a healthy authorized background environment,
not by opening windows on the owner's PC.

## W6 — Repair installed artifacts and build identity

**Findings:** ENG-01/02/03/08/09/10/15; CORE-08.

- Ship templates/static resources, schemas and exact third-party licence notices
  as package data; load resources independently of checkout layout.
- Capture immutable source/contract/build-input provenance in the sdist and
  preserve it in derived wheels outside every Git worktree. Bind Git queries to
  the actual source root. Failed required identity checks mean invalid.
- Build reproducibly from independent clean source copies, with outputs outside
  source trees and an exact audited build profile. Compare bytes fatally and
  explain member diffs. Do not diagnose every difference as timestamps.
- Establish one repository-controlled representation for hash-covered text;
  generate hashes from persisted bytes. Do not reseal to host-specific CRLF.
- Separate portable runtime profiles from Linux-only development/fuzz tooling.
  Produce tested environment-specific locks where necessary; broad library
  compatibility ranges and exact release build inputs serve different roles.

**Acceptance:** fresh wheel and sdist-derived installs outside the repo exercise
all entry points and request real web resources. Source identity/contract fields
are correct outside Git and inside an unrelated repository. Two clean builds
match byte-for-byte. Windows autocrlf and archive extraction preserve hash
contracts. Every redistributed third-party asset has its full notices.

## W7 — Close security and supply-chain coverage gaps

**Findings:** ENG-04 through ENG-07, ENG-10 through ENG-16; current analyzer
inventory and residual boundary tests across all detailed reports.

- Retrieve every active finding for the exact head with pagination. Fix at
  source; retain genuinely unresolved findings open with precise evidence. No
  ignore additions, false-positive dismissals or baseline expansion.
- Upgrade fixable bootstrap/build dependencies, remove avoidable accepted
  installer debt only after measured clean audits, and require complete audited
  package coverage. Skipped/private/editable/unresolved packages are visible
  coverage states, not zero vulnerabilities.
- Generate the SBOM from the actual selected platform/extras closure using full
  PEP 508 marker semantics; fail missing mandatory transitives. Record installed
  package and build/image identities, not an ambient developer environment.
- Validate action pins against the correct upstream repository/commit, quote
  shell requirement ranges, declare every tool and make subprocess failures
  fatal. Full pytest collection replaces accidental unittest-only subsets.
- Replace signature/attestation placeholders with actual verification. Full
  fuzz/mutation evidence states executed scope, counts, tool versions and
  unresolved survivors; fix assertion swallowing and failed-start detection.
- Test production regex/resource boundaries and fixture analyzer findings
  professionally, without conflating test-only observations with exploits.

**Acceptance:** no new unresolved security failures in required scope, complete
counts reconcile, missing mandatory transitive/scan coverage fails, known bad
signatures fail, every action ref resolves, and planted defects prove every
scanner/gate remains sensitive. No required error is hidden by `|| true` ,
`continue-on-error` , an empty comparison or a zero-work success summary.

## W8 — Independently qualify scientific claims

**Depends on:** stable W1/W2/W4 inference and provenance contracts.

- Choose only explicitly licensed datasets and ethically sourced human slices.
  Record immutable raw-source/version/hash and normalization/label provenance;
  independently inspect representative records and all inclusion/drop counts.
- Partition by source document/author/generator/near-duplicate group before
  selecting thresholds or calibration. Freeze train/development/selection/fit/
  validation/final-test manifests. Keep final evaluation inaccessible to tuning.
- Predeclare claims, operating points, minimum samples, uncertainty methods,
  slice list and failure/abstention handling. Include language/domain/length,
  human population/style, generator/version, edited/paraphrased/mixed text and
  benign transformations. Missing licensed slices remain explicit gaps.
- Report worst-required-slice human FPR upper bounds, TPR at that fixed point,
  AUROC/AUPRC, coverage/abstention and confidence intervals. Use appropriate
  rare-event bounds and cluster-aware uncertainty; never pool away harms.
- Calibrate only where supported by disjoint fit and evaluation artifacts;
  validate calibration and any ensemble separately. Evaluate detector-family
  correlation/ablation rather than counting labels as independent evidence.
- Run independent reproduction of published claim artifacts and explicit
  out-of-domain/short-text/refusal tests. Temporal claims require genuine
  complete repeated runs at one immutable identity, not copied histories.

**Acceptance:** a fresh reviewer can reconstruct every claimed metric from
licensed data and pinned code/environment with no tuning on the final holdout.
Every supported claim meets its predeclared gate; everything else is visibly
partial/unknown/experimental. A no-utility or below-chance result stays a
negative result, not a threshold-change invitation. No detector-parity or
zero-FPR promise is required or justified by this plan.

## W9 — Qualify supported systems end to end

Run the full intended pytest suite, lint/format/type/security/claims/schema/
SBOM/golden/contract checks on the declared OS/interpreter/profile matrix.
Include installed wheel and sdist users, not only editable source checkouts.
Exercise the following actual workflows:

- local scan, report, explicit remote selection/refusal and emergency stop;
- calibration admission/application and held-out benchmark refusal/success;
- case export T1/T2, custody successor, packing, installed verification and a
  standalone verification process with no package installed;
- registry import, drift snapshot/compare/run, demotion/recovery and reload;
- cache/retry/health faults, bounded cancellation and recoverable restart;
- CLI/API/MCP/UI equivalents, exports and same-origin collaboration lifecycle;
- no-network core import/use and absent-optional-dependency failure contracts;
- non-root/read-only candidate container health, resources and image-specific
  SBOM/attestation, without pushing it to a registry.

**Acceptance:** zero unexplained failing tests/errors or missing required work.
Intentional profile-specific omissions have a tested refusal and explicit
supported-scope statement. Preserve raw local test/coverage data privately;
commit only minimized privacy-clean summaries. A red run's coverage is
engineering diagnostic data, not accepted release evidence. Target uncovered
risk branches meaningfully rather than adding count-inflation tests.

## W10 — Rehearse release assembly without publication

**Findings:** ENG-04/05/06/14 and all remaining acceptance dependencies.

- Build the exact final candidate from its immutable source; generate a typed
  asset manifest containing required wheel/sdist/source artifact, licences, SBOM
  payloads, checksums, provenance, notes and verification material.
- Require exact confirmation at the final publishing boundary, but in this
  rehearsal route it to a tested no-publication mode. Do not invoke
  `gh release create` , create a tag, contact package upload endpoints or push
  images.
- Verify every mandatory asset's version, source SHA, content digest,
  signature/attestation and signer identity policy independently. Notes and SBOM
  payloads must actually accompany their detached verification material.
- Prove removal/tampering/mismatched SHA/tag/version/missing confirmation or a
  failed/skipped/stale required check prevents promotion before remote writes.
- Prepare a candidate dossier: all gate verdicts and exact run IDs/SHAs,
  supported profiles, measured scientific claims/limitations, open findings,
  migration/rollback/incident recipes and a cold-start handover.

**Acceptance:** a second clean verifier reproduces the complete unpublished
asset set and rejects every deliberately bad candidate. No unresolved P1 finding
within advertised scope remains. P2 findings affecting advertised correctness
must also be fixed, not silently accepted. Any intentionally unavailable
experimental scope is explicit and safely refused. The owner, not the
implementation agent, decides whether and when to authorize release.

## Privacy disposition gate across W0, W7 and W10

W0 must classify all four disclosed historical path-candidate files and their
seven occurrences using local evidence, without copying the matched values.
A candidate is not automatically a verified personal-data leak: distinguish
hosted-runner output, intentional test fixtures and actual personal paths.
W7 must replace raw current-tree operational logs/evidence with minimized,
provenance-linked successors where needed, migrate live references explicitly,
and make fixtures host-neutral. Keep the old source commit/digest as lineage;
do not pretend a sanitized successor is the original signed artifact.

W10 must scan the candidate source archive, wheel/sdist, image contents and
published evidence for personal paths/accounts/text/keys. Unresolved actual
personal data or unexamined candidates block qualification. Do not add scanner
ignores or merely hide a finding. Removing old material from public Git history
is a separate owner-authorized operation with a recovery/provenance plan; this
audit authorizes no rewrite. No existing candidate was edited by this task.

## Human-only decisions versus autonomous work

**Needs a genuine owner/external decision:** widening scope to paid/remote
providers, corpus licensing beyond existing permission, external signing/TSA
trust identity/credential policy, repository governance changes, historical
privacy cleanup that rewrites public history, and final release authorization.
Batch such questions only when the work truly depends on them; do not invent
consent or credentials. Use licensed alternatives while blocked where valid.

**Autonomous:** all source fixes, synthetic regression tests, package/resource
repairs, local no-publication builds, bounded protocol fakes, current alert
inventory, scientific refusal behavior, supported-platform CI, documentation,
privacy-clean evidence and exact-commit verification. Do not hand these back as
manual user setup steps.

## Finding closure record

For each finding, preserve ID, root cause, regression test/node IDs, fixed
source commit, schema/migration decision, exact gate/run evidence and reviewer
verdict. Deduplicate overlapping root causes (for example C11/ENG-09 or
IF-01/core report dispatch) without dropping either feature's acceptance test.
Do not mark a whole wave complete because only its easiest subset is green.

The audit commit deliberately leaves every implementation finding open.

## Audit-delivery checks versus product readiness

The audit's new Markdown, strict JSON, digest round-trip, local links,
privacy/secret scan, pre-commit hooks, source Ruff lint/format, packaged schema
checks and golden-case check were exercised. The existing root AGENTS and
CHANGELOG Markdown style debt remains: 62 diagnostics after the small navigation
addition versus 64 in their original snapshots; no rule was disabled. Those
inherited prose-format findings are not an excuse to claim a clean whole-tree
Markdown gate or a stable product. The full runtime suite remains the red
baseline reported above; this documentation-only task does not fix it.
