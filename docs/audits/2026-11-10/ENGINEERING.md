# Engineering, packaging and supply-chain audit

**Audited commit:** `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` (`main`).
**Disposition:** hold release publication. A green Actions overview does not
establish package completeness, reproducible wheels, validated release inputs,
working Windows provenance, or completed integrity verification.

This is a read-only audit. No product files, workflow settings, branches, tags,
releases, alerts or dependencies were changed. All helpers, API snapshots,
downloaded artifacts and probes were written outside the checkout.
Recommendations below are implementation/test work for a subsequent authorized
change, not changes made by this audit.

## Coverage and evidence boundaries

- The tracked inventory contains 405 files. This lane covered all 17 workflow
  files, the other `.github` configuration/templates, root manifests and
  Markdown, all 28 scripts at engineering/packaging level, `_build_info.py` ,
  documentation/evidence registries, run-manifest metadata and the checked-in
  SBOM.
- Engineering scripts and workflows received manual source review. Scientific
  measurement/validation-generation scripts received import, invocation,
  dependency and packaging review only; their scientific correctness belongs to
  the parent audit. Remaining documentation received full-text
  structural/claim/link scanning and targeted manual follow-up; the review
  manifest distinguishes this from full manual reading.
- Offline negative-path probes extracted selected functions with `ast` ,
  supplied controlled inputs/mocks, and executed only those definitions. The
  release probe **mocked** `subprocess.run` ; it did not invoke
  `gh release create` . No package installation, container execution,
  mutation/fuzz campaign, GPU operation or UI activity was performed by this
  lane.
- The parent independently built wheel/sdist with isolated setuptools 84.2.1 and
  wheel 0.48.0, ran twine checks, installed the wheel outside the checkout,
  rebuilt a wheel from the sdist, and ran the Windows extras suite. Those
  results are explicitly identified as parent evidence, not this lane's own test
  run.

### Evidence catalog

- **EV-ENG-GH:** paginated, GET-only `gh api` snapshots:
  `engineering-github-*.json` ; latest per-workflow histories; current SARIF
  snapshots; selected job-log extracts. The collector records source endpoint,
  retrieval time, page count and minimized data.
- **EV-ENG-PACKAGE:** downloaded `build-artifacts` from exact-SHA run
  [42794427815](https://github.com/strmt7/TextForensics/actions/runs/42794427815);
  `engineering-remote-wheel-diff.json` records wheel hashes, differing members
  and embedded identities. Parent packaging corroborates the outside-checkout
  failure and sdist identity loss.
- **EV-ENG-PROBES:** `probe_engineering.py` and `engineering-probes.json` ,
  successfully executed. Probes cover incomplete identity, release upload
  selection/confirmation, skipped audit dependencies, missing SBOM transitives,
  non-overlapping benchmarks, shell range interpretation and unsuccessful fuzz
  subprocesses.
- **EV-ENG-STATIC:** `engineering-static-summary.json` , action-reference
  inventory/validation, documentation scan and review manifest. Registry hashes
  were separately computed from checkout bytes and `git show HEAD:<path>`
  canonical bytes.
- **EV-ENG-PARENT:** parent-reported tool output: Windows extras suite **21
  failed, 3961 passed, 1 skipped, 4 errors, 1985 subtests passed in 198.64s**.
  The 5972 JUnit aggregate includes subtests and must not be called 5972
  ordinary tests. The suite is red; its coverage is not accepted as a passing
  gate. Parent also confirmed outside-checkout wheel UI failure, sdist
  provenance loss and the canonical lock's Windows install limitation.

## Current GitHub evidence, not a badge interpretation

The exact-SHA snapshot returned **37 completed check-run records: 35 success and
2 skipped**, with 36 unique names because CodeQL has multiple records.
DeepSource was skipped because its analysis quota was exhausted; the full
mutation job was skipped for the push event. A successful diff-mutation summary
is not a successful full mutation campaign.

The paginated open code-scanning inventory contains **89 open alerts: 86
Scorecard and 3 CodeQL**. All 89 rule/path/line tuples match the latest SARIF
analyses for the audited SHA. They are **not stale alerts left over only from
old source**. This establishes current analyzer observations, not automatic
exploitability:

- **Scorecard `PinnedDependenciesID`**
  Count: 59
  Interpretation: Mostly installation/download policy observations; not 59
  dependency CVEs. Source/action validation below distinguishes syntactic SHA
  pins from valid upstream commits.

- **Scorecard `TokenPermissionsID`**
  Count: 22
  Interpretation: Permission-hardening observations; review actual job scopes
  and publishing needs rather than dismissing the scanner.

- **Scorecard other rules**
  Count: 5
  Interpretation: Branch protection, code review, maintenance, security policy
  and best-practices observations. Some are heuristic/governance findings, not
  source vulnerabilities.

- **CodeQL `py/polynomial-redos`**
  Count: 1
  Interpretation: Production `features.py` observation; runtime/input-path
  auditor owns exploit validation. Keep open pending that review.

- **CodeQL `py/overly-permissive-file`**
  Count: 1
  Interpretation: Negative test deliberately makes a sealing key permissive.
  Current fixture observation, not a production key writer regression by itself.

- **CodeQL `py/insecure-protocol`**
  Count: 1
  Interpretation: Dataset test TLS-server fixture. Current source observation;
  do not portray it as a production weak-TLS endpoint without validating
  supported-runtime defaults.

There were **0 open Dependabot alerts** in the retrieved paginated inventory.
That is not proof that floating build tools, container base contents or every
optional environment are vulnerability-free. The analyses endpoint required 12
pages (1127 records); latest-by-tool/category/ref selection was used rather than
treating the first historic analysis as current. The older
enterprise-deep-verification failures and benchmark failures are historical
runs, **not failed checks on this SHA**; defects still present in their workflow
source are distinguished below. No release-dispatch run was available to
validate actual publication end to end.

## Findings

### ENG-01 — P1 / release blocker: the advertised installed web entry point

**Full finding:** P1 / release blocker: the advertised installed web entry point
lacks its resources

**Locations:** `pyproject.toml:102-114` ;
`src/textforensics/web_ui/main.py:211-223` ; `.github/workflows/ci.yml:175-196`
; `.github/workflows/release.yml:75-84` .

Package data includes only `schemas/*.json` and `_build_info.json` , while
`textforensics-web` requires `web_ui/static` and templates. Both downloaded
exact-SHA CI wheels contain only `textforensics/web_ui/main.py` under that
package: no templates or static assets. The parent independently installed the
locally built wheel with API dependencies, outside the checkout, and
`create_web_app()` raised `RuntimeError` for the absent static directory;
templates are absent too. Twine nevertheless passed. The current wheel gate
asserts three schemas and the top-level LICENSE, then exercises CLI/core schema
loading, not the installed web application.

**Impact:** the documented web console cannot start from a normal wheel
installation. Editable-checkout tests conceal the distribution defect.

**Fix/test:** explicitly package required template/static resources and
third-party notices; build both distribution formats, install each in a fresh
environment with the documented web dependencies, change CWD outside the
checkout, construct the application and request `/` , a static JS asset and a
template-rendered route. Enumerate expected archive resources; do not substitute
another editable install.

### ENG-02 — P1 / release blocker: sdist provenance is lost and failed

**Full finding:** P1 / release blocker: sdist provenance is lost and failed
identity checks still say valid

**Locations:** `setup.py:22-45,58-120,123-171` ;
`src/textforensics/_build_info.py:53-82,250-267,314-400` ;
`pyproject.toml:113-114` .

Only `build_py` embeds metadata; no sdist step captures an immutable source
identity/contract manifest. Building a wheel later from the sdist without `.git`
recomputes the source as `unknown` /unverified and loses contract hashes for
omitted root documents. Parent inspection of the sdist-derived wheel found
`source_commit="unknown"` , `source_commit_verified=false` , unavailable
API/adapter hashes and only schema fields in `contract_info` , whereas the
direct wheel had the correct verified SHA. Both setup/runtime Git queries also
lack a package-root-bound `cwd` , allowing an unrelated containing repository to
supply an identity in other invocation layouts.

Independently, the offline `verify_build_identity()` probe with an unknown
commit, false verification and unavailable dependency hash returned **`valid:
true`**, with two failed checks and two error strings. Only an explicitly
supplied, mismatching `expected_commit` changes the overall flag to false.

**Impact:** normal source-distribution rebuilds lose the project's promised
provenance; consumers can mistake an explicitly failed identity check for
successful verification. A dependency hash is currently the abstract pyproject
text, not a record of the installed closure.

**Fix/test:** capture and carry a versioned source/build manifest into the
sdist, bind source discovery to the intended tree, preserve required contract
bytes, and fail verification whenever a required check fails. Test direct-wheel
versus sdist-to-wheel builds outside all Git worktrees, inside an unrelated
worktree, with dirty source, missing metadata and malformed hashes. Release
acceptance must check the expected SHA and required contract fields, not merely
JSON presence.

### ENG-03 — P1 / release blocker: reproducibility is explicitly non-gating

**Full finding:** P1 / release blocker: reproducibility is explicitly
non-gating, and the downloaded wheels disprove the reported result

**Locations:** `.github/workflows/reproducibility.yml:47-74,267-297` ;
`setup.py:34-41,143-146` ; `docs/evidence/runs/EV-20261106-doc-repro.json:9-19`
.

The compare step prints a note instead of failing on different hashes; the
summary subsequently declares wheel builds deterministic whenever jobs return
success. For exact-SHA run 42794427815, the downloaded wheel hashes are:

- first: `eeb2072e82260c535532afa3b8c177b8157f275516b665c03a16a02101b7b9be`
- second: `a79c1928a8422484d467ae1f3ccce1d51f980cb9b614c4acecb243865dab1598`

The differing archive members are `_build_info.json` and its `RECORD` entry. The
first metadata says `source_commit_verified=true` ; the second says false. The
first output directory is now an untracked worktree artifact when
`git status --porcelain` is sampled for the next build. This is a reproduced
source/procedure defect, **not evidence for the workflow's blanket timestamp
explanation**. The older documentation evidence merely records that
`SOURCE_DATE_EPOCH` is set; that cannot establish byte-identical builds.

**Impact:** a green named reproducibility gate and its summary assert a property
the run's own artifacts fail.

**Fix/test:** build from independent clean, identical source snapshots with
build outputs outside the source tree; make comparison failure fatal; emit
archive-member diffs. Verify direct wheel and sdist-derived paths separately,
under fixed build tooling and differing temporary paths. Regenerate claims only
after actual hash equality is established.

### ENG-04 — P1 / release blocker: the publishing workflow does not enforce

**Full finding:** P1 / release blocker: the publishing workflow does not enforce
this repository's actual acceptance gates

**Locations:** `.github/workflows/release.yml:35-84,180-189` ;
`.github/workflows/ci.yml:51-70,92-107,126-139` ; `scripts/run_mutation.py` and
scientific release evidence are not prerequisites of release dispatch.

The manual workflow correctly checks its `RELEASE` input, but then independently
installs floating `.[dev,all]` , runs Ruff and **unittest discovery**, builds,
and publishes. It neither requires successful exact-SHA checks from the other
workflows nor runs the claims, pip-audit, locked-SBOM, full pytest,
installed-web or reproducibility acceptance checks itself. AST inventory found
**268 module-level pytest test functions**; unittest discovery does not collect
these functions, including packaging, SBOM and policy tests. This is not a claim
that unittest runs zero tests; it is a demonstrable collection gap. The parent
Windows suite is red even though the remote Linux-centric overview is green.

**Impact:** an explicitly confirmed release can publish with failing or
unexecuted security, scientific evidence, packaging and portability checks. A
manual confirmation is authorization to attempt release, not evidence that
release criteria passed.

**Fix/test:** release an immutable, fully evaluated SHA/artifact set and make
every required acceptance result a prerequisite. Use the canonical pytest
collection, not a smaller test runner accidentally chosen in the publisher. Add
offline orchestration tests proving that a missing, skipped, stale-SHA or failed
required result prevents signing/publication; exercise all artifact types
outside the source tree before promotion. Do not lower thresholds or ignore
failing tests to satisfy publication.

### ENG-05 — P1 / release blocker: upload is not fail-closed for

**Full finding:** P1 / release blocker: upload is not fail-closed for
confirmation, artifact identity, signatures or provenance

**Locations:** `scripts/publish_release.py:217-289` ;
`.github/workflows/release.yml:170-189` .

The helper rejects a nonempty wrong `RELEASE_CONFIRMATION` but accepts an
**unset/empty** value. Artifact checks require only some wheel, some
permissively named source tarball, notes and an existing directory. Checksums,
signatures, SBOMs and provenance are optional glob results; absence produces no
error. It does not validate wheel metadata/version/source SHA or require the
existing tag to resolve to the artifact's commit. `--verify-tag` establishes tag
existence, not that identity binding.

The offline mocked upload accepted no confirmation, a fake
`wrong-name-9.9.9-py3-none-any.whl` , a source tarball and notes, with no
signatures/checksums/provenance: return code 0 and a captured would-be
`gh release create` invocation. **No real publishing call was made.** The
workflow's separate confirmation step mitigates accidental normal dispatch; it
does not make the helper fail-closed.

**Impact:** local/alternate use or future workflow refactoring can publish
incomplete or misidentified assets; an old same-version tag can be paired with
different source content.

**Fix/test:** explicitly pass and require exact confirmation at the publishing
boundary; construct a typed mandatory asset manifest, validate file
contents/versions/digests, verify signatures and attestations, and bind tag,
source SHA and built artifact identity. Negative tests must remove each
mandatory item, change each version/SHA, unset confirmation and supply a
mismatching existing tag; all must fail before any remote-writing command is
launched.

### ENG-06 — P1 / release blocker: signed SBOMs and signed notes are not

**Full finding:** P1 / release blocker: signed SBOMs and signed notes are not
actually attached as promised

**Locations:** `.github/workflows/release.yml:98-101,109-156,170-197` ;
`scripts/publish_release.py:148-153,187-214,252-265` .

The uploader attaches wheels, tarballs, `SHA256SUMS` , `dist/*.sig` ,
`dist/*.bundle` and optional provenance files. It never selects `dist/*.json` ,
so both SBOM payloads are absent from the GitHub Release even though their
detached signatures/bundles are selected. Notes/signature/bundle/checksum live
outside `dist` , so the notes enter the release body but their verification
artifacts are not attached. The separate Actions SBOM upload is not a release
attachment and has different access/retention behavior. Checksums are created
before SBOMs/provenance, so the claim of checksums for every attached artifact
is also untrue. Finally `sign-notes` returns success when cosign is absent,
calling an unkeyed checksum a “checksum signature.”

**Impact:** consumers cannot reproduce the advertised signed-changelog/SBOM
verification from release assets. A checksum is not an authenticity signature.

**Fix/test:** explicitly enumerate payloads and their verification material,
generate a checksummed manifest after defining the complete payload set, and
require cryptographic signing in publication mode. Keep any local unsigned
preview mode clearly separate and ineligible for upload. Test the final captured
asset list and independently verify downloaded payloads/signatures/attestations
using documented identity constraints, including negative tamper cases.

### ENG-07 — P1: integrity and deep-verification greens can represent no

**Full finding:** P1: integrity and deep-verification greens can represent no
verification or suppressed execution errors

**Locations:** `.github/workflows/repository-integrity.yml:29-37` ;
`.github/workflows/enterprise-deep-verification.yml:48-62,98-102,161-166,221-227,344-378`
; `scripts/run_fuzz.py:174-204` and final exit logic;
`.github/workflows/mutation.yml` push/diff versus scheduled/full conditions.

Concrete gaps:

1. “Verify release signatures” and “Verify attestations” consist only of echo
   statements explicitly labelled placeholders. They perform no signature or
   attestation verification, yet succeed.
2. Deep verification permits the full-suite step to fail with
   `continue-on-error: true` , and ignores Sphinx build failures with `|| true`
   . The current suite/coverage commands request `--forked` , but the dev extra
   does not declare pytest-forked. The retained older run's test log contains
   `ERROR: ... unrecognized arguments: --forked` ; it is historical evidence of
   a source defect still present, not a current-SHA failed check.
3. Unquoted `pip-audit>=2,<3` , `bandit>=1.7,<2` and `httpx>=0.27,<1` are shell
   redirections, not requirement strings. An offline harmless `printf`
   substitution using the same range token returned 1,
   `3: No such file or directory` , and created `=2,` . `bash -n` alone
   misleadingly succeeds because the syntax is valid shell.
4. Deep schema validation installs jsonschema but later imports `textforensics`
   /a nonexistent `CaseFile` symbol without installing the project in that job.
5. The fuzz runner records an arbitrary nonzero child status as informational
   and leaves `error=null` when no crash artifact is created. The controlled
   child-exit-2 probe returned zero crashes/hangs and no error, concealing an
   instrumentation/startup failure. Current successful fuzz history is not
   evidence that every such failure is properly detected.
6. The full mutation job is skipped on this SHA's push; the diff log reported no
   relevant work. The tracked 1697-entry mutation baseline and its
   AST/domain/ULP rationale do not imply all mutants were executed in that
   successful push check.

**Impact:** labels such as integrity verified, full suite, fuzz clean or
mutation passed can materially overstate executed work.

**Fix/test:** replace placeholders with independent artifact verification;
propagate failed commands and required child exit statuses; install declared
tools, quote requirement specs, and make schema checks exercise the installed
package. Distinguish `not_applicable` , `not_executed` , `error` and `passed`
with measured work counts; required gates must not accept the first three as a
pass. Test import failure, no tests collected, zero fuzz executions, missing
artifacts and deliberate bad signatures. Repair coverage by running a passing
supported suite, not excluding test files or masking failure.

### ENG-08 — P1 for supported Windows evidence workflows: checkout

**Full finding:** P1 for supported Windows evidence workflows: checkout
conversion changes the bytes whose hashes are contractual

**Locations:** missing repository `.gitattributes` ;
`scripts/check_claims.py:175-193` ; `docs/evidence/registry.json` ;
`sbom/textforensics.cdx.json` ; `requirements-pinned.txt` ; parent-generated
cache-byte findings are separate runtime defects.

All **34** registry run artifacts match their declared digests when hashed as
canonical Git blobs; **all 34** mismatch as bytes in the fresh Windows checkout.
The host's existing `core.autocrlf=true` converts tracked JSON/text to CRLF; no
repository attributes protect the hashed bytes. Parent `git ls-files --eol`
confirmed `i/lf w/crlf` for evidence JSON and requirements, and the Windows
claims gate returned 0/33 claims with 34 registry hash failures. This is **a
reproducible portability defect, not evidence tampering**. SBOM properties
hashing these text files are similarly sensitive. The generated detection-cache
string/bytes mismatch independently reproduced by the parent is a different
write-path defect, not cured solely by checkout attributes.

**Impact:** an ordinary supported-platform checkout cannot verify the
repository's own evidence, and produces misleading tampering diagnostics and
staleness results.

**Fix/test:** establish repository-controlled byte policies for hash-covered
artifacts/manifests; generate and hash exactly the persisted bytes. Test clean
LF and autocrlf-enabled Windows clones and sdist/archive extraction. Do not
silence the check or refresh registry digests to host-specific CRLF bytes;
preserve a single well-defined signed/hashed representation and diagnose
conversion accurately.

### ENG-09 — P1 release acceptance gap: cross-platform green means two

**Full finding:** P1 release acceptance gap: cross-platform green means two
shallow CLI operations, not supported workflows

**Locations:** `.github/workflows/ci.yml:141-162` ;
`.github/workflows/ci.yml:11-13,51-70` ; platform claims in `README.md` and
`docs/INSTALLATION.md:24-29` .

Windows/macOS jobs install `.[enterprise]` , print the version and parse a
simple scan JSON. Full pytest/coverage, evidence/claims/SBOM, sealing, dataset
fixture handling and installed-distribution web tests run nowhere in those OS
lanes. The parent's actual Windows extras suite returned 21 failures and 4
errors, including sealing/CLI `os.fchmod` , byte-hash portability and dataset
fixture server-thread failures. These outcomes must not be laundered into green
coverage by dropping failing tests.

The canonical `requirements-pinned.txt` install also fails on Windows because
atheris 3.1.0 has manylinux-only wheels. **This latter limit is already
explicitly documented** at `SECURITY.md:282-287` : the lock is
Python-3.12/Ubuntu-specific. It is not evidence that the documented lightweight
Windows install itself cannot resolve. The parent's constrained-extras run is
therefore not a successful canonical-lock install.

**Impact:** current OS badges cannot substantiate the breadth of advertised
Windows functionality, and the maintenance lock cannot be reused as a portable
installer.

**Fix/test:** define platform-supported capability profiles, run actual workflow
tests and artifact installs on each supported OS, and separate Linux-only
development/fuzz tooling from a portable runtime installation. Create
per-environment locks only where supported and tested; retain explicit
limitations rather than ignoring atheris resolution errors.

### ENG-10 — P1 build-chain inconsistency: the “upgraded pin” security

**Full finding:** P1 build-chain inconsistency: the “upgraded pin” security
policy does not govern all build/release inputs

**Locations:** `pyproject.toml:1-4` ;
`.github/workflows/reproducibility.yml:38-41,296` ;
`.github/workflows/release.yml:64-79` ; `.github/workflows/ci.yml:43-44` ;
`pip-audit-baseline.toml:69-75` ; `SECURITY.md:218-248,282-287` .

The canonical Linux lock genuinely has exact package versions, and its
Ubuntu/Python scope plus deferred hash pinning are documented; those deliberate
limits should not be misreported as undisclosed defects. The problem is the
**other paths**: the release/main jobs install floating extras, isolated builds
use `setuptools>=75,<85` and unbounded-above wheel, and the reproducibility job
explicitly installs setuptools **79.0.1**. The repository's own baseline
evidence records three findings for that version and says the fix was to widen
the cap rather than baseline a fixable backend. That workflow still selects the
known-rejected version. Its exact selection is outside the currently upgraded
canonical lock. The pyproject comment “Pinned versions for reproducible builds”
describes ranges, not exact build pins.

**Impact:** evaluated locked inputs are not necessarily the released build's
inputs; unrelated upstream changes can change release/tool behavior, and one
workflow explicitly revives a backend version rejected by the project's own
security evidence.

**Fix/test:** use an audited build-tool/input profile consistently for every
release path, upgrading vulnerable versions rather than allowing findings.
Separate broad library compatibility ranges from exact build records and record
backend/frontend/wheel identities in provenance. Test clean isolated builds
against that profile and audit build tooling as well as runtime closure. A
future hash-pinning improvement is hardening, not an excuse to claim current
documented limits are hidden.

### ENG-11 — P2: unaudited/skipped packages can become a successful

**Full finding:** P2: unaudited/skipped packages can become a successful
zero-finding result; accepted findings are not zero findings

**Locations:** `scripts/check_pip_audit.py:196-225,230-257,260-280` ;
`pip-audit-baseline.toml:15-39` ; `SECURITY.md:35-48` .

The parser considers only dependency `vulns` ; missing/empty vulnerabilities are
treated as clean, with no handling of `skip_reason` . The subprocess does not
request strict audit coverage and accepts both status 0 and 1. A controlled JSON
dependency carrying a skip reason and no vulnerability list produced zero
raw/parsed findings with no error. An installed editable/private/unresolvable
dependency can therefore disappear from coverage while the gate reports success.

Separately, the baseline deliberately accepts six pip-24.0 findings. This is
**explicit repository policy**, not a newly discovered hidden `--ignore` flag or
proof of six current runtime vulnerabilities. It conflicts with any blanket
“zero vulnerabilities” interpretation and retains avoidable installer debt; it
is not a reason to add further exceptions under the user's no-suppression
remediation requirement.

**Impact:** a zero-new finding count does not imply a complete audit or a
zero-finding environment.

**Fix/test:** make audited/skipped/failed package counts explicit; fail required
coverage on skip reasons, malformed dependency entries and unexpected omissions.
Require a supported, patched bootstrap installer instead of adding/extending
allowlists; remove dormant exception debt only after measured zero findings.
Preserve raw findings and classify accepted findings visibly; never present them
as absent. Test skipped packages with both allowed pip-audit exit statuses and a
private/editable dependency.

### ENG-12 — P2: the SBOM closure algorithm mistakes missing required

**Full finding:** P2: the SBOM closure algorithm mistakes missing required
transitives for optional dependencies

**Locations:** `scripts/generate_sbom.py:303-339` ; dependency parsing/metadata
collection in the same script; `sbom/textforensics.cdx.json` .

The traversal reports an absent package as unresolved only when it was a root.
Its comment assumes every absent transitive is an optional/marker-false
dependency. A controlled installed root requiring a nonexistent mandatory
transitive yielded `included=[root]` , `unresolved=[]` . Metadata parsing also
reduces requirements to names without evaluating markers/extras: installed test
packages can become spurious production edges. For example keyring's installed
metadata declares pytest/pytest-cov only under its test extra, while the
generated closure treats installed names as sufficient to traverse such edges.
The checked-in SBOM has 120 components; stable regeneration proves consistency
with this algorithm, not correctness of every dependency edge.

**Impact:** compliance/security consumers can receive an apparently resolved
graph that hides broken mandatory dependencies or includes unselected optional
edges. A partial-environment SBOM is not a release bill of materials merely
because generation succeeds.

**Fix/test:** evaluate full PEP 508 requirements for the intended platform and
selected extras, distinguish mandatory missing transitives from false markers,
and make release generation require a fully resolved closure. Verify graph edges
independently against a clean install/report. Test missing required transitives,
false platform markers, selected/unselected extras and partial environments, not
just byte-for-byte staleness.

### ENG-13 — P2: benchmark comparison is broken or vacuous, despite full-SHA

**Full finding:** P2: benchmark comparison is broken or vacuous, despite
full-SHA action syntax

**Locations:** `.github/workflows/benchmark.yml:84-107` ;
`scripts/performance_baseline.py:76-103,113-116` .

The benchmark downloads with
`actions/download-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9` , which is
the upload-artifact commit, not a commit in download-artifact. Read-only
`gh api repos/actions/download-artifact/commits/<sha>` returned HTTP 422, “No
commit found for SHA”. All 135 `uses:` references are syntactically full SHAs;
validation of all 19 unique action-repository/SHA pairs found this one invalid
pair. Syntactic pin checking is therefore insufficient. `fail-on-error` is not
the download action's control for making a step optional. On push/schedule, the
comparison is conditioned on `github.event.inputs.baseline-ref != ''` , so its
environment default does not turn comparison on. Cross-run baseline identity is
not supplied to the downloader.

The standalone comparison helper also accepts wholly disjoint benchmark names:
the offline probe warned that the baseline test was absent, returned 0 and said
“No significant changes detected,” while printing a compared count of 1 despite
no shared measured benchmark.

**Impact:** regressions can escape comparison, and manual comparison can fail
before obtaining a baseline. A success label does not guarantee a matched
baseline was evaluated.

**Fix/test:** validate pins against the correct upstream repository; resolve an
immutable baseline artifact/run/ref, require matched workload identities and
positive comparable counts, and fail missing/renamed/invalid results when
comparison is required. Test push, schedule and dispatch event payloads plus
zero-overlap, missing means and failed artifact download cases.

### ENG-14 — P1 release-governance gap: container publication bypasses

**Full finding:** P1 release-governance gap: container publication bypasses
release acceptance and mutates version tags

**Locations:** `.github/workflows/container.yml:3-15,69-96` ; `Dockerfile` ;
`compose.yaml` .

A qualifying main push builds and immediately pushes multi-architecture images
with `latest` , the unchanged package version and a short-SHA tag. It has no
dependency on the test/claims/security/package/reproducibility jobs, and no
post-build running-image acceptance step before mutable tags are published.
Dockerfile health-check configuration is not evidence that the image
health/read-only behavior was tested. The SBOM scans `path: .` , not the built
image digest, so it does not establish the runtime OS-layer dependency
inventory. Buildx provenance generation is useful but does not prove application
tests passed or the release conditions were met.

**Impact:** a failing main commit can be published before its checks finish and
can overwrite the same version tag. Source-tree SBOM/provenance labels can be
mistaken for runtime-image verification.

**Fix/test:** separate candidate build from promotion, bind
evaluation/attestation/SBOM to the immutable image digest and tested source SHA,
then promote version tags only after required gates and explicit publication
policy. Exercise both architectures where feasible, health endpoints,
non-root/read-only execution and installed web resources. State clearly whether
automated main snapshots are intentionally public; do not call them governed
releases without those controls.

### ENG-15 — P1 distribution/compliance blocker: vendored JavaScript lacks

**Full finding:** P1 distribution/compliance blocker: vendored JavaScript lacks
its full third-party license notices

**Locations:** `src/textforensics/web_ui/static/chart.umd.min.js:1-13` ;
`docs/LICENSING.md` ; root `LICENSE` ; package-data declaration at
`pyproject.toml:113-114` .

The repository vendors Chart.js 4.4.1, with a bundled @kurkle/color notice. The
asset header names MIT licensing but does not contain the full
permission/disclaimer text. The tracked license-document search finds only the
project's AGPL `LICENSE` and `docs/LICENSING.md` ; neither supplies the upstream
MIT notices for these bundled components. The upstream tagged license texts
require preserving the copyright and permission notice. Missing wheel assets do
not solve the issue: the Git source tarball still redistributes the JS, and
packaging the UI must also package its notices.

**Impact:** source distributions and any corrected UI distribution are missing
required third-party notices; the project's own AGPL declaration does not
replace them.

**Fix/test:** retain the exact appropriate upstream license/copyright notices in
a tracked third-party-notices location and include them with each redistributed
asset format. Add an archive/license-inventory test covering source tarballs,
sdists, wheels and containers. No license text or product file was changed by
this audit.

Sources: [Chart.js v4.4.1
license](https://raw.githubusercontent.com/chartjs/Chart.js/v4.4.1/LICENSE.md),
[@kurkle/color v0.3.2
license](https://raw.githubusercontent.com/kurkle/color/v0.3.2/LICENSE.md).

### ENG-16 — P2: document evidence proves file existence, not the claimed

**Full finding:** P2: document evidence proves file existence, not the claimed
contents/current implementation

**Locations:** `scripts/check_claims.py:423-428,475-487,499-549` ;
`docs/CLAIMS.yaml` ; `docs/evidence/runs/EV-20261106-doc-repro.json` ;
`docs/evidence/report-card.md` ; root `CONTINUATION_PLAN.md` , `ROADMAP.md` and
`ARCHITECTURE.md` .

The `doc` evidence checker returns success for any existing path. Although
linkage verifies the run artifact's bytes and handles age/version fields, it
does not compare a recorded document digest to the current document or require
the current source SHA for these static assertions. A saved result such as
`cited_content_present=true` for a `SOURCE_DATE_EPOCH` assignment is not
execution evidence that wheels are reproducible; ENG-03 supplies an exact
counterexample. Historical suite/evidence records are dated/code-versioned
snapshots, not results for this commit. Maintain that distinction when
reconciling root plans with current implementation.

The report-card helper searches only `worst_slice_human_fpr` and
`human_fpr.worst_slice` , then says no human-FPR evidence is recorded and “No
FPR is claimed anywhere.” Existing measurement run formats include differently
named Wilson-upper-bound fields. Keeping an unqualified release metric
**unknown** can be correct, but the blanket absence explanation is not a
schema-aware assessment of existing evidence. The core audit owns the scientific
validity of those measurements and qualification rules; this finding does not
promote any value to a release claim.

**Impact:** green claims can establish that files and self-reported records
exist while leaving the asserted implementation/property untested; report-card
prose can contradict the evidence inventory.

**Fix/test:** bind doc assertions to current content digests and source/workload
identities; use executable property checks for executable claims. Give each
plan/status document an explicit as-of SHA and distinguish implemented, tested,
historical and blocked states. Make report-card aggregation understand supported
artifact schemas and eligibility, with fixtures for present-but-unqualified and
qualified evidence. Retain unknown where scientifically required, with an
accurate reason; never fill it from an ineligible best slice.

## Governance observations and limits

- The live main-branch protection read returned HTTP 404 and the ruleset list
  was empty. `docs/REPOSITORY_SETTINGS.md` describes recommended settings, not
  proof those settings are active. No settings were changed. Under the user's
  main-only policy, harden deletion/force-push/publication boundaries without
  inventing a requirement to merge PRs; any governance change requires explicit
  owner authorization.
- Scorecard success means the scan/upload ran, not that all 86 current
  observations were cleared. Its SecurityPolicy/Maintained heuristics must be
  compared with actual `SECURITY.md` and commit activity; do not delete
  documentation, change thresholds or dismiss alerts just to obtain a badge.
- The 1697-entry mutation baseline was structurally reviewed and counted by
  kind, including AST-only annotations and source-pinned runtime-equivalence
  categories. This audit does not assert every equivalence proof is valid or
  that all 1697 entries were executed on the audited push. Baselines must not be
  expanded to make new untested behavior green.
- `.secrets.baseline` was inspected as detector/hash metadata, not treated as a
  list of confirmed leaked secrets. Do not expose baseline values or infer real
  credential disclosure from synthetic/test detectors alone. No credential or
  personal author data is included here.
- Fresh outside-checkout packaging and Windows tests are stronger evidence for
  their exercised paths than checkout-only import smoke. Conversely Windows
  failures are not proof that the exact-SHA Linux suite failed; that remote
  suite succeeded under its own environment and collection.

## Prioritized implementation/test plan (not performed)

1. **Stop promotion until acceptance is real:** address ENG-04/05/06/07/14; fail
   closed on incomplete/stale/skipped evidence and prohibit publishing merely
   because an unrelated scan job is green. Keep all work on the authorized
   main-only/documented process; do not create releases as an audit experiment.
2. **Repair release artifacts:** ENG-01/02/03/15; require complete
   UI/resources/licenses, trustworthy sdist-to-wheel identity, byte-identical
   clean builds and independently verified final release attachments.
3. **Make supported environments verifiable:** ENG-08/09; repository-controlled
   byte policy plus byte-correct generated artifacts, supported Windows
   sealing/dataset tests, and honest Linux-only lock/tooling boundaries. Rerun
   the unmodified full intended suite; do not accept coverage while red.
4. **Align input and security evidence:** ENG-10/11/12; one audited release
   input profile, patched installers/backends, complete audit coverage, correct
   PEP 508 dependency graphs and build/image-specific SBOMs. No new ignore,
   suppression, dismissal, exception or lowered threshold is an acceptable
   substitute for a fix.
5. **Rebuild proof/claims after fixes:** ENG-13/16; real baseline comparisons,
   schema-aware report cards, exact-SHA/run/tool identity, and final
   outside-checkout wheel/sdist/container acceptance across documented
   platforms. Preserve historical evidence as history rather than rewriting it
   to imply a current pass.

A final release decision also depends on the parent
runtime/crypto/interface/scientific audit. This engineering report makes no
claim that those independent acceptance criteria are green.
