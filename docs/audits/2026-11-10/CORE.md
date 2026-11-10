# Scientific core and data-integrity audit

Audited snapshot: `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` . Checked
2026-11-10. This is a report and implementation specification, not an
implementation. Source references use that immutable snapshot.

## Scope and interpretation

Reviewed the scientific execution path: analyzers, features, conditions,
detector protocol, consensus, report orchestration, both evidence registries,
Trust Maps, calibration/thresholds, benchmark fingerprints, dataset adapters,
and mixed-origin inference. All 28 scripts received invocation/dependency
review; scientific measurement, corpus, seeding and patch builders also received
methodology/provenance review. The inventory records overlaps with the state and
artifact auditors rather than pretending those are separate independent
implementations.

`evidence.json.core` preserves fresh, bounded, synthetic observations.
Regression expectations below come from the declared contract and independent
mathematical definitions, not copied implementation outputs. Recreate them with
disposable JSONL/registry objects; no external corpus or user text is necessary.
Passing synthetic fixtures would establish boundary correctness, not real-world
detector accuracy.

## CORE-01 — V2 coverage accepts scientifically ineligible evidence

**Priority P1; reproduced.** `evidence.py:931-952,956-982,984-1199,1244-1299`
and `report.py:294-326,370-379` , under `src/textforensics/` .

A synthetic registry record with wildcard detector version, benchmark split
`train` , an editing regime incompatible with the input, and missing referenced
artifacts still produces **supported** language, length, domain, generator,
human-population and human-FPR dimensions. The editing dimension alone becomes
unknown; registry artifact verification separately returns false. Generic
metadata/sample/freshness checks do not enforce the claimed held-out,
exact-version, applicable-regime evidence contract.

Default verification is optional. That is not itself cryptographic forgery; the
defect is promoting unverified/inapplicable declarations to scientific support
without a distinct eligibility rule and provenance state.

**Implementation:** define one explicit eligibility predicate for evidence that
may establish support: exact detector/model/config identity, approved held-out
role, contamination state, applicable conditions, freshness, sufficient samples
and resolved artifact integrity. Decide the documented trust policy for
caller-supplied versus verified records. Preserve partial or unknown evidence
without allowing it to raise a supported dimension. Apply that policy across V2,
U1/V3 and the default reporting surfaces; do not silently convert old artifacts
into newer verified evidence.

**Acceptance:** separately vary split, version, editing, domain, absent/tampered
artifact and unknown contamination. None may establish unsupported scientific
support. Fully applicable, independently validated controls must still work.

## CORE-02 — Human-FPR support selects the most favorable slice

**Priority P1; reproduced.** `validation.py:1957-1969,2173-2213` ; V2 best-state
selection also occurs at `evidence.py:931-952` .

A correctly hash-sealed synthetic U1 record containing one FPR CI upper bound of
**0.01** and a worse applicable slice with upper bound **0.9** produces
`supported` human-FPR evidence and reports **0.01** against the 0.05 ceiling.
Both the blocker and displayed summary take `min` , without a
slice-applicability or worst-required-slice proof. This is not a new empirical
FPR measurement.

**Implementation:** select the exact relevant operating point and scientifically
applicable slices, preserve all conflicting evidence, and require the declared
worst-required-slice upper bound to meet the gate. A best-slice statistic must
never substitute for that quantity. Define aggregation across records and
incomparable populations explicitly; missing required slices remain unknown.

**Acceptance:** favorable pooled result plus adverse domain/population slice;
multiple records with conflicting applicable results; absent slice CIs;
threshold/direction mismatch; tie and ceiling boundaries. The adverse case must
not become supported by adding a favorable record or reordering metrics.

## CORE-03 — Temperature scaling is applied to the wrong input domain

**Priority P1; reproduced.** `calibration.py:177-192,289-295` .

The public curve accepts native scores in [0,1] and computes `sigmoid(x/T)` . At
`x=0.2,T=1` , the measured output is **0.549833997312478**, not 0.2. For a
binary probability input, temperature scaling is `sigmoid(logit(p)/T)` ; for
logits it is `sigmoid(z/T)` with a logit-domain contract. The current bounded
native-score interface cannot represent negative logits and has no method-level
input-domain declaration. Arbitrary native scores are not automatically
probabilities or logits.

**Implementation:** make the input semantics explicit and version the curve
contract. Either support actual logits with the appropriate domain, or require
probability inputs and use the logit transformation with documented endpoint
handling. Do not silently change existing artifact meaning. Refit/re-evaluate
affected artifacts rather than presenting old metrics as proof of the fix.

**Acceptance:** independent reference calculations for p=0.2/0.5/0.8 at T=1 and
other temperatures; logit/probability equivalence where both are supported;
endpoints, nonfinite values, native directions and unsupported semantics.

Reference checked 2026-11-10: [Guo et al., temperature
scaling](https://proceedings.mlr.press/v70/guo17a.html).

## CORE-04 — Frozen calibration artifacts remain mutable after hashing

**Priority P1; reproduced.** `calibration.py:177-230,435-490,660-699,835-846` .

Mutating the original `parameters` mapping after constructing a nominally frozen
curve changes the applied probability to **0.9999999979388463**, while the
artifact retains its original hash and still reports probability-eligible.
Recomputed content hash no longer matches. Nested validation/metric mappings are
similarly not made deeply immutable. Manager `store` also publishes to its
in-memory map before successful persistence (`:841-842`).

**Implementation:** copy and deeply freeze/hash canonical scientific content;
validate integrity at admission/use as appropriate; never expose writable
registry state. Publish memory only after durable storage succeeds. Define
identity and migration semantics instead of refreshing hashes silently.

**Acceptance:** mutation of constructor inputs, returned parameters/metrics,
manager results and nested lists either fails or cannot affect applied output;
tampered content cannot remain eligible under an old hash. Inject disk failures
and verify memory/disk remain consistent.

## CORE-05 — Calibration lookup cannot bind the current detector version

**Priority P1; reproduced API contract gap.** `calibration.py:848-852,908-936` .

A manager containing an eligible artifact for `old-version` returns a
probability-eligible result when queried by detector ID alone. Public result
methods accept only detector ID, raw score and a diagnostic override; they
cannot require the current version/config/model identity. Merely recording a
version in the stored artifact does not enforce it at the use boundary.

**Implementation:** require an exact inference identity at selection and
application; refuse absent/mismatched detector, provider/model, native-score
semantics, calibration ID and applicable regime. Latest-by-time must not cross
identity epochs. Propagate this binding through detector integration.

**Acceptance:** old/current versions under the same ID, changed provider/model
or configuration, missing current provenance, competing artifacts and explicit
diagnostic use. No mismatched artifact may emit a validated probability.

## CORE-06 — Held-out labels survive overlapping or unproven evaluations

**Priority P1; reproduced.** `benchmark.py:241-269` ;
`calibration.py:1121-1182,1278-1337,1460-1507` .

Reordering the same two JSONL rows changes the file hash but retains complete
sample overlap; `benchmark_with_calibration_jsonl` still calls the run
`held_out_evaluation` . `evaluate_threshold` with no calibration provenance
calls the run `held_out` . Explicit same-dataset diagnostic use also returns
`held_out` and `contamination_detected=false` . The existing sample-level
contamination helper correctly detects the two shared samples, but is not
mandatory in these entry points. The full convenience pipeline checks only
`contamination_detected` , not all validation failures.

**Implementation:** require a sample/group-level disjointness proof linking
training, selection, fit and final evaluation to immutable manifests. Reject
unknown/failed checks for release-quality evaluation. Diagnostic overrides must
serialize diagnostic status and actual overlap, never held-out status. Retain
source-document grouping so sentence/edited variants cannot cross splits.

**Acceptance:** reordered rows, relabeled rows, repeated IDs with changed text,
whitespace/near-duplicate groups, fit/selection/test overlap, missing
provenance, read failure and diagnostic override. A zero-overlap verified
control remains held out; every unknown or contaminated case is rejected or
honestly labelled.

## CORE-07 — Failed benign probes can yield supported stability

**Priority P1; reproduced.** `report.py:112-163,351-354` ; `trust.py:186-254` ;
V3 reuses this helper at `validation.py:2280-2303` .

A detector succeeds twice and fails on two benign variants. The report records
the two failures, but computes verdict stability **1.0** from survivors; the
Trust Map then says benign stability is **supported**. Failure accounting is
present but excluded from the decision. This is distinct from U3 full-run
failure loss in S01, although both violate the same completeness invariant.

**Implementation:** track selected, attempted, succeeded, abstained and failed
probes; require the prescribed complete set before support. Keep partial
measurements visible with their denominators. State policy in native units; a
universal raw drift limit is not empirically comparable across instruments.

**Acceptance:** one failed variant, one failed detector, missing score, all
abstentions and complete stable/unstable controls. Adding failures can never
increase support or improve the claimed completed-coverage denominator.

## CORE-08 — Dataset cache hashes describe strings, not persisted bytes

**Priority P1 for Windows evidence workflows; reproduced.**
`datasets.py:2002-2057` , especially `:2033-2036` .

On Windows, the cache writer persists CRLF through text-mode newline conversion
but hashes an LF-encoded in-memory string. The declared file digest therefore
does **not** match the file just written. This is independent of Git checkout
conversion in ENG-08; repository attributes cannot repair a runtime-generated
file's incorrect digest.

**Implementation:** define UTF-8/newline bytes once, atomically persist those
bytes and hash the exact committed representation. Write a linked manifest
transactionally; verify it before consuming cached scientific evidence.

**Acceptance:** byte-for-byte digest checks on Windows/POSIX, empty and Unicode
rows, failed writes and restart. Evidence record builders must consume the
persisted digest and cannot silently reseal host-dependent representations.

## CORE-09 — The streaming dataset parser accepts invalid JSON arrays

**Priority P2; reproduced.** `datasets.py:2159-2226` .

Small files with missing commas, leading/repeated/trailing commas, or garbage
after the closing array are accepted and yielded as rows. `_skip_ws_commas`
strips commas indiscriminately, and the closing bracket returns before EOF
validation. Trusted digest checks in the normal download route narrow the
production exposure; the parser itself does not meet its declared refusal
contract. Its rolling buffer is also not a maximum per-object budget.

**Implementation:** maintain a strict array grammar/state machine, require EOF
after closing whitespace, and cap object/buffer depth and bytes. Preserve
streaming; do not solve grammar by reading a production file into memory.

**Acceptance:** the three recorded invalid examples, extra arrays/objects,
truncation and malformed Unicode fail boundedly. Valid empty/multibuffer arrays
round-trip. Test tiny configurable object budgets instead of huge allocations.

## CORE-10 — Schema discovery and dispatch disagree

**Priority P2; reproduced.** `schema.py:13-24,150-196` .

Twelve JSON schemas ship, only ten are listed, and generic `validate` rejects
four advertised names: `evidence-registry` , `run-artifact` ,
`sealed-bundle-manifest` , and `validation-registry` . Probe-run and
mixed-origin schemas are absent from discovery. C23 separately demonstrates
incompatible nested version contracts, not merely a listing defect.

**Implementation:** one explicit, complete version-aware schema registry for
loading/discovery/validation and transport tooling; map each supported schema
name to the same published contract. Reject unknown versions deliberately.

**Acceptance:** every shipped public schema is listed and loadable, every listed
name dispatches, and generated artifacts validate through that generic surface.
Pin unsupported-version refusal and all nested version combinations.

## CORE-11 — Mixed-origin coverage ignores detector identity and eligibility

**Priority P1; reproduced.** `mixed_origin.py:100-139,412-468,471-594` .

A partial record for an unrelated detector with the same version, expired
revalidation date and manual demotion is admitted as segment coverage when it
copies a known slice ID. The helper checks stored status/version and language/
domain, not detector ID, effective status, length or eligibility. That boolean
removes the no-validation withholding reason and can permit a categorical
human/AI document verdict. The docstring intentionally skips freshness, but
using existence as an inference permission is still unsafe.

**Implementation:** distinguish record existence from scientifically eligible
coverage. Require the exact detector/method/segment operating point, effective
status, supported conditions and the declared validation bar before lifting
withholding. Keep partial/below-chance experimental segment evidence available
without turning it into an authorship or idea-provenance determination.

**Acceptance:** wrong ID/same version, stale, demoted, contaminated, thin,
partial-only and out-of-length records cannot authorize a categorical verdict.
Use the actual report path, not only the coverage helper. Keep operations and
HART labels explicitly hypothetical/unknown when evidence cannot identify them.

## Scientific release limitations, not implementation bugs to hide

- The built-in detector remains a heuristic baseline. The repository's existing
  preliminary datasets/segment results are not independent proof of production
  accuracy or commercial parity. This audit did not redownload those corpora or
  rerun external/model benchmarks.
- Current partial records, corpus proxies and null calibrated outputs are often
  **correct refusals**. Do not change their status to make a release look ready.
  Treat English/non-English, ESL, domain, length, generator vintage and editing
  regimes as separate declared claims, not one global accuracy promise.
- Human-only evidence can bound an FPR but cannot establish detection utility;
  near-total abstention is not evidence of useful discrimination. Report
  conditional and unconditional error, coverage, abstention and TPR together.
- Use predeclared held-out operating points and confidence procedures. A
  percentile bootstrap of zero events cannot substantiate a population zero-risk
  claim; Wilson/exact rare-event bounds and document-cluster-aware resampling
  answer different questions and must be named accurately.
- License-blocked datasets remain blocked. Do not infer a licence from an
  adjacent repository or redistribute raw text. Obtain clear rights or choose an
  independently licensed alternative.
- Trust Map V2, U1/V3 and capability-ledger views remain separate paths. Default
  `build_forensic_bundle` consumes the V2 evidence registry; adding U1 records
  does not automatically activate V3 for CLI/API/MCP/UI reports. Choose and test
  an explicit integration/migration contract before claiming parity.
- CodeQL's current `py/polynomial-redos` observation points at `features.py` .
  This audit did not demonstrate a production denial of service. Keep it open;
  characterize bounded worst cases, fix at source and prove input-budget and
  runtime behavior without suppression or speculative exploit claims.

## Privacy hygiene requiring follow-up

Existing tracked suite artifacts and `docs/live-host-api/fullsuite2.log` contain
machine-local home-directory paths. `evidence.json` records locations and counts
only, never the matched values. A path alone does not establish whether the
identity is a real person or a hosted runner. Sanitize newly captured
operational evidence automatically, minimize raw logs, and review existing
material without copying identifiers into another report.

Do not edit old hash-linked artifacts or rewrite public history casually:
removal/replacement requires a provenance-preserving migration and any needed
owner authorization. This audit publishes no raw logs, user documents, keys,
mailboxes, local home paths or account data.
