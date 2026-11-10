# Cryptography, forensic artifacts, and provenance: read-only audit

## Scope and evidence

- Snapshot: `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` .
- All **13 exclusively assigned runtime files** were read in full: **10,879
  lines**. Matching tests read: **24 files**; directly relevant public schemas
  read: **4 files**. The exact repository-relative paths, line counts, content
  SHA-256 values, and review coverage are in `inventory.json` .
- Read `AGENTS.md` , `docs/SEALING_KEYS.md` , `docs/TSA_INTEROP.md` ,
  `docs/VERIFICATION.md` , and `docs/THREAT_MODEL.md` . Cross-read only the
  report/validation dependencies necessary to construct legitimate offline
  controls.
- Executed bounded synthetic probes using the checkout's Python **3.12.10**
  environment and installed `cryptography` **50.0.2**. No runtime, test, schema,
  configuration, or git writes; no package installations, builds, full-suite
  invocation, provider requests, or live TSA calls by this auditor. Generated
  artifacts stay in the supplied audit scratch directory.
- Independently parsed the parent's `extras-junit.xml` to corroborate the
  Windows key-save failures. The full suite belongs to the parent; this report
  does not represent the probe script's exit status as a passing test suite.
- Source references below are repository-relative. Scratch evidence names are
  relative to the supplied audit directory. No real accounts, personal
  identities, or private document text were used.

### Reproducing findings

The named observations are preserved in `evidence.json` under `crypto_primary`
and `crypto_followup` . Each finding supplies the synthetic construction, exact
source boundary, observed result, expected result and regression-test contract.
Recreate those cases in disposable state; no user documents or keys are
required. Audit probe scripts and generated keys are deliberately not shipped. A
probe execution exit of zero records observations; it is not a product pass.

## Release decision

**Do not release the current cryptographic/provenance feature set as verified
across its advertised entry points.** There are demonstrated
signature/payload-binding failures, conflicting verification decisions, missing
provenance-failure propagation, a resource-limit bypass, and a directly
reproduced Windows key-generation failure. Severity below is conditional on the
stated use; none of the findings claims a generic break of Ed25519 or SHA-256.

The strongest immediate blockers are C01–C08 and C11. C09–C10 affect
integrity/coverage contracts under crafted input. The remaining findings close
concrete correctness, privacy, platform, and reliability gaps before the
corresponding features can be called release-ready. They are not reasons to
suppress findings, weaken assertions, or reinterpret an unverified result as a
pass.

## Verified findings

### C01 — Primary watermark verifier accepts a substituted detector result

**Severity:** High when a consumer relies on the documented primary
`verify_watermark` entry point for authenticity of detector outputs. An attacker
needs one genuine signature and its public key, not the private key.

**References:** `src/textforensics/watermarking.py:415-467` , especially
`:452-467` ; contrast the correctly implemented payload-hash recomputation at
`:401-409` .

**Root cause:** `verify_watermark` checks the signature over the supplied
`signature.payload_hash` , then compares the caller's expected detector fields
against the supplied `signature.payload` . It never establishes that this
payload hashes to the signed hash. Those are two independent attacker-controlled
inputs.

**Reproduction/evidence:** `crypto-probe.py` , observation
`watermark_payload_substitution` . Keep signature bytes and the signed hash
unchanged, change payload score `0.2` to `0.99` and verdict `human_like` to
`ai_like` , and verify the substituted output. Observed: primary verifier
**true**; independent recomputed-payload-hash equality **false**; manager
verifier **false**. Expected: both verification paths reject.

**Fix plan:** recompute the canonical payload digest before signature
verification and bind all expected fields to that authenticated payload. Share a
well-defined validation contract across both entry points without weakening the
cryptographic check; reject unsupported algorithms and malformed encodings with
structured failure.

**Acceptance tests/gap:** extend `tests/test_watermarking.py:300-424` beyond
wrong *expected* fields. Mutate the embedded payload and the expected fields
together while preserving the original signature/hash; mutate each authenticated
field and metadata independently. Both verifiers must reject, while the
untouched control succeeds. Existing manager tamper coverage at
`tests/test_watermarking.py:232` does not exercise the vulnerable consumer path.

### C02 — A valid bare-case signature does not bind its displayed

**Full finding:** A valid bare-case signature does not bind its displayed
signer/role/fingerprint

**Severity:** High for T2 bare-case users who interpret the case's signer label
or role as authenticated by a successful public-key verification. The actual
supplied public key and DSSE keyid remain cryptographically bound; this is not a
forgery against that public key.

**References:** `src/textforensics/sealing.py:203-221,229-269` ;
`src/textforensics/casefile.py:1488-1494,1575-1579` .

**Root cause:** `case_signing_payload` removes the entire `seal.signature`
mapping, not only the recursive DSSE envelope. `signer.identity` , `signer.role`
, and `key_fingerprint` are placed in the excluded mapping and never checked
against the supplied key. Recomputing the unkeyed case digest is sufficient to
edit them.

**Evidence:** observation `case_unsigned_signer_metadata` . Changed the signer
identity/role and replaced the recorded fingerprint with 64 zeroes, leaving the
DSSE signature untouched and recomputing only the public case hash. Observed:
`signed_payload_unchanged=true` , signature verification **true**, combined
verification **true**. Expected: mutation fails, or these fields are
unmistakably reported as unauthenticated and inconsistent fingerprint is
rejected.

**Fix plan:** put signer assertions and the derived fingerprint in the signed
body; exclude only the actual recursive envelope. Verify the recorded
fingerprint against the trusted supplied public key. Version the signing
contract deliberately and retain explicit legacy semantics. A signed
self-asserted identity still does not replace an external key-to-identity trust
policy.

**Acceptance tests/gap:** extend the body-tamper tests at
`tests/test_sealing.py:350-372` with individual identity, role, fingerprint, and
algorithm mutations; verify a signed case across primary/combined paths. Confirm
the production signed manifest already binds its signer record
(`src/textforensics/sealed_bundle.py:284-305`) and avoid regressing that
behavior.

### C03 — Process metadata can export literal source text while declaring

**Full finding:** Process metadata can export literal source text while
declaring raw text absent

**Severity:** High confidentiality/correctness risk when imported
process/reviewer metadata contains private source material. It requires that
such metadata is supplied to the sealer; there is no automatic exfiltration or
external-provider call in the reproduction.

**References:**
`src/textforensics/casefile.py:239-260,335-416,1319-1320,1373-1384,1533-1553` .

**Root cause:** the recursive forbidden-key policy is applied only to
`forensic_bundle` . Other case sections preserve nested mappings such as
`process.reviewer` without a whole-case privacy check, while the top-level
`raw_text_included` flag is always false.

**Evidence:** `case_top_level_raw_text` passes a synthetic `raw_text` field
within reviewer metadata to `seal_case_file` . Observed: literal text present
**true**, `raw_text_included=false` , combined verification **true**. Expected:
reject a forbidden source-text field throughout the complete portable case,
absent a separate explicit and accurately declared opt-in contract.

**Fix plan:** run a recursive portability/privacy check on the completed case
before sealing and on every imported case before verification. Define
allowlisted process metadata fields and an explicit opt-in if retaining raw
material is actually supported; never emit a contradictory absence flag. Do not
prohibit legitimate free-text reasoning merely by guessing its content.

**Acceptance tests/gap:** seed forbidden raw-text keys in reviewer, appeal,
custody metadata, validation references, limitations, and nested lists, not just
in the forensic bundle. Assert no canary appears in default exported JSON or
portable archives. Cover direct sealer, case writer, combined verifier, packer,
and standalone verifier.

### C04 — Sealed-bundle packaging and offline verification bypass the

**Full finding:** Sealed-bundle packaging and offline verification bypass the
required combined verifier

**Severity:** High artifact-correctness/privacy risk whenever portable/offline
verification is used as equivalent to installed case verification. No
private-key compromise is necessary for the unsigned parity cases; a legitimate
signer can also unknowingly package a semantically invalid case because the
packer skips the independent check.

**References:** `src/textforensics/sealed_bundle.py:227-236` ;
`src/textforensics/verify.py:311-338` ;
`src/textforensics/_standalone_verify.py:1024-1036,1369-1528` .

**Root cause:** the packer calls the primary case verifier, not
`verify_case_file_combined` . The standalone copy omits raw-text portability and
Trust Map overall replay, and checks checklist *consistency only for present
satisfied entries*, not the full required D1–D10 structure/template notice.

**Evidence:** `standalone_validation_parity` records three internally rehashed
cases: embedded raw text, an empty/altered checklist, and incorrect Trust Map
overall. All fail combined verification and all return offline exit **0**.
`production_pack_wrong_trust_map` additionally uses the real packer and signs
the resulting manifest: combined **false**, packer succeeds, standalone exit
**0**, signature **verified**.

**Expected:** equivalent structural/privacy/semantic checks across packaging and
all verification entry points; a signature authenticates bytes but does not make
invalid structure valid.

**Fix plan:** gate packing on combined validation. Implement independent offline
equivalents of portability, required checklist structure, manifest/tool
consistency, detector sanity, and Trust Map replay. Maintain the standalone
stdlib/no-install contract; do not solve parity by importing the package into
the portable verifier.

**Acceptance tests/gap:** expand `tests/test_verify_consolidation.py:72` into an
installed/packed/standalone cross-product and include
`tests/test_standalone_verify.py` and `tests/test_sealed_bundle.py` .
Mutate/re-hash each contract field; require every path to reject. Clean T1/T2
controls must continue to produce the documented 0/1/2 verification states.

### C05 — Duplicate ZIP member names hide unverified content behind a valid

**Full finding:** Duplicate ZIP member names hide unverified content behind a
valid manifest signature

**Severity:** High integrity ambiguity where the signed manifest/public key is
the trust anchor and downstream readers/extractors may use first-match rather
than last-match ZIP semantics. An externally pinned SHA-256 of the *entire
archive* would detect the modified archive and is an important limiting
precondition.

**References:**
`src/textforensics/_standalone_verify.py:1188-1192,1237-1245,1331-1354` .

**Root cause:** sorted names are required but duplicate names are not rejected.
Entries are opened by string name, so `zipfile` repeatedly returns the last
entry, and `contents[name]` overwrites prior values. Manifest checks operate on
the deduplicated mapping, not each actual archive member.

**Evidence:** `standalone_duplicate_name_shadow` accepts an archive with a wrong
first `case.json` . Stronger `signed_duplicate_shadow` starts with a real,
verifiably signed production bundle, prepends a second `case.json` , and
preserves the original manifest/signature and all genuine entries. Observed:
changed archive **true**, offline exit **0**, signature **verified**. The added
member has no authenticated digest.

**Fix plan:** reject duplicate member names before reading any content; also
validate manifest-path uniqueness and a one-to-one member/listing relationship.
Use specific validated ZIP member objects when reading rather than ambiguous
name lookup. Decide and test normalization/case-collision policy for any
consumers that extract on case-insensitive filesystems.

**Acceptance tests/gap:** duplicated `case.json` , `manifest.json` , `verify.py`
, and other names, including first/last malicious variants, must fail before
content checks. Reproduce with an unchanged valid manifest signature, not merely
an unsigned fixture. Preserve a separate expected-archive-digest control
demonstrating that external digest pinning catches modification.

### C06 — Optional seal-record cross-check decompresses entries after

**Full finding:** Optional seal-record cross-check decompresses entries after
container rejection

**Severity:** High availability risk if an application accepts untrusted
archives and supplies `seal_record` to the library verifier. The default
standalone path alone correctly rejects compression before reading; the
vulnerable deployment needs the optional cross-check path.

**References:** `src/textforensics/sealed_bundle.py:380-395,403-414` ; compare
early container gating in `src/textforensics/_standalone_verify.py:1194-1229` .

**Root cause:** after standalone verification has rejected the container, the
seal-record branch independently opens it and calls uncapped `ZipFile.read` for
every member. It discards the benefit of the STORED-only rule and entry/total
caps.

**Evidence:** `sealed_record_bypasses_container_rejection` builds a
**1,254-byte** DEFLATED ZIP containing one **1,048,576-byte** repeated-data
member. Standalone rejects it with exit **1**, but instrumented real ZIP reads
show the wrapper subsequently decompresses the entire member. The probe
intentionally stays at one MiB; no large allocation/DoS was attempted.

**Expected:** reject/gate without decompressing rejected content; no second,
less-restricted parser path.

**Fix plan:** return or mark the optional cross-check unavailable after
seal/container failure. Prefer passing already validated capped contents to
cross-checks. If rereading is unavoidable, use the same entry count,
compression, per-entry, aggregate, and sealed-results guards before and during
reads.

**Acceptance tests/gap:** extend seal-record tests at
`tests/test_sealed_bundle.py:141-181` with rejected compression, size/count
failures, malformed containers, and a spy that asserts **zero** untrusted member
reads after rejection. Test the guard with tiny limits rather than allocating
hundreds of MiB.

### C07 — Public audit-log verification returns valid after detecting

**Full finding:** Public audit-log verification returns valid after detecting
missing genesis

**Severity:** High for users relying on `verify_audit_log` to detect provenance
prefix deletion. The adversary needs to modify the local/imported log; no
rehashing is necessary.

**References:** `src/textforensics/ledger.py:354-379,478-494,503-547` .

**Root cause:** loading checks only links between surviving entries, not the
first entry's genesis. `verify_chain` correctly detects the non-genesis
predecessor, but `verify_audit_log` collects that failure at `:520-521` and then
unconditionally returns `valid=True, errors=[]` at `:541-546` .

**Evidence:** `audit_log_prefix_deletion` creates two valid records and removes
the first line. Observed: `AuditLog.verify_chain()` **false**; public wrapper
**valid true**, one record, no errors. Expected: false with a genesis/chain
error.

**Fix plan:** preserve the computed validity/errors, validate genesis and
contiguous indices on load/verification, and define missing-file versus
intentionally empty-log semantics. This does not eliminate the separate need for
an external trusted head to detect full-log replacement or suffix deletion.

**Acceptance tests/gap:** extend `tests/test_audit_log.py:187-217` to delete a
prefix, replace the first predecessor, alter starting index, and compare the
class/wrapper decisions. Include an empty valid log and intact multirecord
controls.

### C08 — An unchanged calibration chain authorizes unrelated artifact tampering

**Severity:** High when audit anchors plus `current_chain` are used as an
anti-rollback/integrity gate. The attacker can alter current
calibration/benchmark artifacts while preserving/copying the known chain; the
trusted anchor itself need not change.

**References:** `src/textforensics/ledger.py:1549-1561,1609-1622,1676-1694` .

**Root cause:** mismatched current calibration/benchmark roots are accepted if
`current_chain.extends_anchor` returns true. That predicate accepts an equal
nonempty chain and checks only list-prefix equality. It does not bind the chain
to either current directory root; benchmark changes are authorized by a
calibration-only list.

**Evidence:** `anchor_chain_masks_benchmark_tamper` exports an anchor, changes
only a benchmark file, and preserves the original chain. Without a chain:
`RollbackError` . With the unchanged chain: **`chain_valid`**. Expected: reject
the unrelated change.

**Fix plan:** anchor explicit, versioned state transitions binding the current
calibration root, benchmark root, and detector-version state. An unchanged chain
must never authorize changed roots; a longer arbitrary hash list must not
suffice either. Validate loaded chain entries and state lineage, not just hash
syntax/prefix.

**Acceptance tests/gap:** expand `tests/test_audit_anchor.py:200-280` : altered
benchmark + equal chain; calibration rollback + copied chain; arbitrary appended
digest; changed detector versions; verified legitimate transition; missing/empty
roots. Valid extension must be proved from bound artifact state, not asserted
solely by a copied list.

### C09 — Directory hashing has a structural preimage collision

**Severity:** Medium, potentially High for chosen-content artifact ingestion.
This is a framing defect, not a collision in SHA-256, and does **not** provide a
second preimage for an arbitrary pre-existing honest directory. The attacker
must control crafted artifact content/layout.

**References:** `src/textforensics/ledger.py:1432-1457` .

**Root cause:** the tree preimage is concatenated
`relative_path || NUL || raw_content || LF` records without length framing or
per-file hashes. Raw file content can contain the next record's delimiter/path
bytes.

**Evidence:** `directory_hash_framing_collision` compares:

- Tree A: `a.bin` contains `x\nb.bin\x00y` .
- Tree B: `a.bin` contains `x` ; `b.bin` contains `y` .

Both produce the exact independently specified preimage
`b"a.bin\x00x\nb.bin\x00y\n"` and the same product tree digest, despite
different file maps/counts. Expected: different trees must not have identical
serialized hash preimages.

**Fix plan:** version a canonical manifest of normalized relative path, explicit
size, and per-file content digest, or use unambiguous length-prefixed records.
Define symlink behavior and use portable path separators. Account for anchor
migration; silently changing the algorithm invalidates existing anchors.

**Acceptance tests/gap:** add this two-tree construction to
`tests/test_audit_anchor.py:140-195` , plus nested-path portability, binary
contents with delimiters, empty/missing distinction, and deterministic ordering.
Existing streaming tests prove bounded reads, not injective framing.

### C10 — Combined verification accepts a one-dimension, undeclared v3 Trust

**Full finding:** Combined verification accepts a one-dimension, undeclared v3
Trust Map as strong

**Severity:** High evidence-contract correctness risk when a successful
verification is taken to confirm the declared complete Trust Map coverage. This
demonstrates consistency/schema validation failure, not proof that unsigned
evidence can ever authenticate scientific truth.

**References:** `src/textforensics/verify.py:125-152,243-260` ;
`src/textforensics/casefile.py:239-260,1499-1514` ; completeness contract at
`src/textforensics/validation.py:2362-2367` .

**Root cause:** v3 overall replay requires all *present* names to be supported
(`supported == len(by_name)`), rather than the complete declared dimension set.
The dimension validator does not reject undeclared names, and the primary path
does not provide that missing semantic validation.

**Evidence:** the base probe deliberately leaves a stale manifest and therefore
combined verification fails there; **do not use that initial false result as
proof of acceptance**. Follow-up `v3_incomplete_map_precise_result` updates the
public `manifest.schema_versions.trust_map` consistently and recomputes the
unsigned hash. A v3 map with only `not-a-declared-dimension: supported` and
overall `strong` then yields primary errors **[]**, N-version valid **true**,
`trust_map_verified=true` , combined valid **true**.

**Fix plan:** require exactly the declared dimension set with unique valid names
before deriving `strong` ; reject unknown/duplicate names and enforce v3
required metadata/coverage consistency. Apply equivalent completeness validation
across all versioned verification paths without treating mere count equality as
name-set equality.

**Acceptance tests/gap:** extend `tests/test_verify.py:482` and
`tests/test_verify_consolidation.py:170-180` from the empty/full cases to
nonempty subsets, duplicated dimensions, arbitrary names, and 10 wrong names.
Complete supported controls and stale/out-of-scope maps must retain the correct
results.

### C11 — Windows key generation fails and leaks its temporary file descriptor

**Severity:** High release blocker for supported Windows signing/keygen
workflows; directly reproduced on the audit host.

**References:** `src/textforensics/sealing.py:75-104` , specifically the
unconditional `os.fchmod` at `:93` , descriptor ownership transfer at `:94` ,
and exception cleanup at `:100-103` .

**Root cause:** Windows has no `os.fchmod` . The call fails before `os.fdopen`
owns/closes the `mkstemp` descriptor. Cleanup attempts to unlink the still-open
file, suppresses the resulting `OSError` , and never closes the descriptor.

**Evidence:** `windows_sealing_key_save` : `os.name=nt` , `has_fchmod=false` ,
save raises **AttributeError**. Follow-up `windows_keysave_descriptor_leak`
tracks the actual scratch `mkstemp` : descriptor remains open after failure,
deletion is blocked until explicit close. The probe closes its tracked
descriptor afterward. No private seed bytes have been written at this failure
point. Parent JUnit independently records affected sealing
round-trip/refuse-overwrite and CLI keygen/signed-export failures plus teardown
errors.

**Fix plan:** implement owner-private file creation/access control per supported
platform, retain secure POSIX mode checks, and close the raw descriptor on every
pre-`fdopen` failure. Make no-clobber publication genuinely atomic, not just an
initial existence check. Do not replace the check with world-readable key
storage or skip the Windows tests.

**Acceptance tests/gap:** existing `tests/test_sealing.py:253-301` and
`tests/test_cli_case_seal.py:63-100,123-166` must pass on Windows and POSIX with
platform-appropriate ownership/permission assertions. Inject failures
before/after descriptor handoff; assert no open descriptor/orphan temporary file
and no key overwrite. Add concurrent no-clobber publication coverage.

### C12 — Ordinary malformed shapes escape verification APIs as exceptions

**Severity:** Medium availability/reliability risk for untrusted artifact
imports, especially if callers trust the documented never-raises contract. This
is not an allocation stress test.

**References:** `src/textforensics/verify.py:247-250,335-356` ;
`src/textforensics/_standalone_verify.py:1331-1341` .

**Root cause:** the N-version path calls `dim.get` even after its helper
identified a non-object; it runs outside the combined path's limited exception
handling. Standalone sorts manifest paths before establishing they are
comparable strings.

**Evidence:** `combined_malformed_dimensions` supplies `[None]` dimensions and
raises **AttributeError**. `bounded_shape_and_depth_failures` supplies manifest
paths `None` and `"case.json"` and raises **TypeError**. Expected: failed
verification reports with stable error codes, not exceptions. The same probe's
2,201-byte nested non-object JSON is a **negative control**: it returns
structured invalid; that tested depth is not reported as a defect.

**Fix plan:** validate shapes, key types, and required values before
iteration/sorting/hash lookup. Keep malformed-data handling at the public
boundary comprehensive while preserving programming errors separately. Establish
explicit parser-depth/input limits for JSON entry points; do not claim a depth
exploit based on this negative control.

**Acceptance tests/gap:** extend `tests/test_verify_consolidation.py:111` beyond
bad JSON syntax to null/scalar/list/object variants at every nested field. Add
malformed manifest item/path types to portable-verifier tests. Require
non-crashing failure and unchanged 0/1/2 semantics.

### C13 — Invalid RFC 3161 genTime is an exception in-package but verifies

**Full finding:** Invalid RFC 3161 genTime is an exception in-package but
verifies offline

**Severity:** Medium for imported TSA tokens; invalid times undermine both
reliability and the timestamp's stated meaning. These fixtures are synthetically
signed; no trusted external TSA is impersonated.

**References:** `src/textforensics/timestamp.py:285-304,604,885-889` ;
`src/textforensics/_standalone_verify.py:429-432,597,1583-1595` .

**Root cause:** the package's datetime conversion raises a plain `ValueError`
that `verify_timestamp_token` does not catch, while the standalone copy only
decodes ASCII and never validates the GeneralizedTime grammar/calendar value.

**Evidence:** `timestamp_bad_time_parity` creates an independently encoded,
correctly ECDSA-signed token with `genTime="invalid-date"` . Package:
**ValueError**. Standalone token verifier: **no errors**. The valid timestamp
control verifies through both. Expected: both reject with structured errors.

**Fix plan:** independently validate the same RFC 3161/DER time grammar,
timezone/fraction requirements, and calendar values in both paths; convert parse
errors into the appropriate structured verification result. Do not silently
interpret timezone-free timestamps as UTC.

**Acceptance tests/gap:** add invalid month/day, missing `Z` , malformed
fraction, invalid ASCII time, and valid fractional-second tokens to
`tests/test_timestamp.py` and `tests/test_standalone_verify.py` , using a
test-only DER fixture that does not import production parsing constants.

### C14 — ECDSA signature OIDs are incorrectly used to mandate a curve

**Severity:** Medium interoperability defect when a TSA uses a supported EC
curve with a different supported hash, e.g. P-256/SHA-384. Not a
signature-acceptance bypass.

**References:** `src/textforensics/timestamp.py:67-80,972-984` ;
`src/textforensics/_standalone_verify.py:707-715` .

**Root cause:** the ECDSA-with-SHA384 OID is mapped to both SHA-384 and P-384.
The signature OID identifies the signature/hash; the curve is declared
separately by the certificate's EC parameters. RFC 5758 §3.2 does not require
that pairing. The implementation already has P-256 arithmetic and correct hash
truncation needed for the reproduced case.

**Evidence:** `timestamp_valid_p256_sha384` builds a real P-256/SHA-384
signature and verifies it with `cryptography` before packaging. Both product
paths reject with `ec_curve_mismatch` ; expected: verify this supported
curve/hash combination or explicitly document a deliberately narrower policy
rather than diagnosing a valid certificate as a curve mismatch.

**Fix plan:** select the hash from the signature/digest OIDs and select the
supported curve from the certificate. Keep hash-algorithm agreement and reject
unsupported curve OIDs. Publish a precise supported algorithm matrix.

**Acceptance tests/gap:** current curve-generator tests
(`tests/test_timestamp.py:501`, `tests/test_standalone_verify.py:479` ) do not
cover algorithm composition. Cross-check P-256/P-384 with SHA-256/384/512
against an independent engine, include invalid signatures and genuinely
unsupported curves, and preserve existing live-token interoperability evidence
without inventing new network results.

### C15 — AuditLog writers race and a failed write poisons the in-memory head

**Severity:** Medium reliability risk with two live instances/processes sharing
a log or after an I/O failure. Unlike the snapshot ledger's separately tested
locking, this class has no reload-and-lock append transaction.

**References:** `src/textforensics/ledger.py:349-352,381-385,408-409,463-464` .

**Evidence:** `audit_log_stale_writer` creates two instances before either
appends, then appends sequentially. Stored indices are **[0,0]** and
verification fails. No timing/stress race is required.
`audit_log_failed_append_mutates_head` injects an `OSError` at the disk-write
boundary; a later successful append persists index **1** referencing a record
never written, and reloaded chain verification is **false**. Expected:
contiguous [0,1] for serialized writers and no committed head advancement after
failed persistence.

**Root cause/fix plan:** append derives the next head from a stale cache,
commits to `_entries` before disk success, and uses neither a shared append lock
nor a durable flush/fsync transaction. Lock the file across
reload/validate/append, persist a complete record with a defined failure policy,
then update in-memory state. The lack of explicit fsync is a static durability
observation; real power-loss behavior was not tested.

**Acceptance tests/gap:** extend `tests/test_audit_log.py` with deterministic
stale instances, interprocess append serialization, write/flush/fsync faults,
and partial final records. Acknowledge a write only after persistence succeeds;
do not silently discard non-tail corruption. Keep snapshot-ledger concurrency
tests separate so they do not mask this implementation.

### C16 — Workspace chains trust serialized head fields they never verify

**Severity:** Medium where serialized workspace chains are loaded and continued.

**References:** `src/textforensics/workspace_integrity.py:168,211-225,226-276` .

**Evidence:** `workspace_unvalidated_head` changes serialized `chain_hash` and
`last_entry_hash` to zeroes. Loaded `verify_chain` reports **valid**. A normal
`add_entry` then uses the unverified cached last hash and breaks the previously
accepted chain. Expected: reject or recompute those fields before calling a
loaded chain valid or appending.

**Fix plan:** validate/recompute cached root and head against verified entries
on load; also enforce index continuity/version. Use the actual verified last
entry for subsequent linkage. If fields are informational, do not use them as
trusted append state.

**Acceptance tests/gap:** extend
`tests/test_workspace_integrity.py:123-174,327-347` with mutated head/root,
omitted head, noncontiguous indices, and valid save-load-append round trips. All
accepted loaded chains must remain valid after an ordinary append.

### C17 — An explicitly requested missing workspace chain is reported healthy

**Severity:** Medium when an application explicitly supplies `audit_chain_path`
as an integrity requirement. A caller that deliberately requests no chain has
different semantics and is not the reproduced case.

**References:** `src/textforensics/workspace_integrity.py:834-854` .

**Evidence:** `workspace_missing_required_chain` passes a path to a nonexistent
chain for a clean synthetic workspace. Observed: `audit_chain_valid=true` ,
`overall_status="healthy"` . Expected: unavailable/invalid, never verified
healthy for the explicitly requested missing evidence.

**Fix plan:** distinguish not requested, missing, unreadable, malformed, valid,
and invalid chain states. A required path must fail closed; reflect unavailable
fingerprint/chain checks honestly rather than initializing them as successful
verification.

**Acceptance tests/gap:** complement
`tests/test_workspace_integrity.py:338,435-478` with high-level
explicit-missing/unreadable paths and a deleted previously present chain.
Preserve the deliberate no-chain mode as a separately labelled status.

### C18 — Legacy bundle verification accepts a non-archive with an empty

**Full finding:** Legacy bundle verification accepts a non-archive with an empty
manifest

**Severity:** Medium artifact-validation defect. A separately trusted expected
digest authenticates those bytes but still cannot make them a structurally valid
archive; this is not a digest-forgery claim.

**References:** `src/textforensics/bundle.py:320-327,347-350,378-380,413-420` .

**Root cause:** manifest schema/format are not validated globally, and archive
format/opening is checked only inside the per-file loop. An empty digest map
skips the loop entirely.

**Evidence:** `legacy_empty_manifest_accepts_non_archive` writes plain non-ZIP
bytes with a matching self-declared digest, wrong manifest schema, unsupported
format, and an empty file map. Observed: **valid true**, no file statuses,
errors **[]**. Expected: fail schema/format/archive validation.

**Fix plan:** validate the manifest contract first, open/validate the container
regardless of file-map emptiness, enforce name/member uniqueness and intended
completeness, and preserve digest checks. Define whether a legitimately empty
bundle is supported; do not treat arbitrary bytes as one.

**Acceptance tests/gap:** extend the normal round-trip tests at
`tests/test_bundle.py:121-203` and bomb tests at `:338-390` with
empty/wrong-shaped manifests, unsupported format, non-archive bytes, and
extra/duplicate/missing members.

### C19 — Benchmark verification accepts NaN metrics, negative counts, and a

**Full finding:** Benchmark verification accepts NaN metrics, negative counts,
and a nonhex fingerprint

**Severity:** Medium integrity/reliability defect when `verify_benchmark` is
used to validate benchmark artifacts. It is not a new measured
detector-performance claim and does not modify the scientific core.

**References:** `src/textforensics/verify.py:544-553,571-591` .

**Root cause:** counts are used without validating nonnegative-integer domains;
`abs(NaN-derived) > tolerance` is false; dataset fingerprints are checked for
string length only.

**Evidence:** `benchmark_invalid_inputs` , with a legitimate
finite/count-consistent control asserted first. Individually replacing all
stored rates by NaN, making `tp=tn=-1` and evaluated `-2` with corresponding
algebraically consistent rates, or replacing the dataset digest with 64 `z`
characters each yields **valid true**. Expected: all three reject.

**Fix plan:** validate finite rates, exact count domains (excluding bool),
nonnegative totals, metric bounds, hexadecimal digest syntax, and required
metrics before recomputation/comparison. Continue independently deriving the
rates from valid counts.

**Acceptance tests/gap:** add NaN/infinity/null/string/bool/negative/fractional
count cases, invalid hex, and finite boundary controls to `tests/test_verify.py`
. Verify artifact rejection, not merely that a comparison helper returns a
value. Coordinate scientific-domain semantics with the parent's core audit
rather than duplicate findings in unrelated modules.

### C20 — Watermark expiry checks trust unsigned envelope dates, not the

**Full finding:** Watermark expiry checks trust unsigned envelope dates, not the
trusted key

**Severity:** Medium when watermark key-expiry policy is relied upon;
independent of C01's substituted-payload attack.

**References:** `src/textforensics/watermarking.py:349-379,401-412,445-450` .

**Root cause:** the primary verifier compares editable `signature.signed_at` and
`signature.expires_at` , ignoring `public_key.expires_at` and the authenticated
payload timestamp. The manager does not enforce validity bounds at all.

**Evidence:** `watermark_public_key_expiry` accepts a genuine signature whose
trusted key object expired before the authenticated signing timestamp.
`watermark_unsigned_dates` changes only the unsigned envelope dates; primary and
manager both accept even with that expired trusted key. Expected: enforce the
chosen trusted validity policy using authenticated data, not attacker-editable
fields.

**Fix plan:** define historical-versus-current validity explicitly. Compare an
authenticated signing-time assertion against trusted key validity bounds,
require redundant dates/IDs/algorithm fields to agree, and do not claim a
self-reported signed timestamp is an external trusted time. Preserve valid
historical signatures where policy permits them.

**Acceptance tests/gap:** existing expiration coverage
(`tests/test_watermarking.py:549`) concerns loading expired private keys, not
verification of imported signatures. Test trusted expiry before/after
authenticated time, forged envelope dates, missing/naive/malformed dates, and
both public verifier entry points.

### C21 — Watermark key IDs escape the configured private-key directory

**Severity:** Medium with caller-controlled/untrusted key IDs, or automation
assuming writes stay within its configured key store. No claim of an existing
unauthenticated remote route to this API.

**References:** `src/textforensics/watermarking.py:273-286,299-305` .

**Evidence:** `watermark_key_path_traversal` constructs a manager inside the
synthetic scratch key directory and generates ID `../synthetic-outside` .
Observed: an actual private-key JSON is written outside that directory.
Expected: reject traversal/separators and remain within the configured key
store. The probe checks only that a private-key field exists; it never prints
the key material.

**Fix plan:** use an allowlisted opaque key identifier independent of the
filename; reject traversal/absolute/drive/UNC/reserved-name forms. Resolve and
confine all create/read/delete operations, publish private files atomically with
appropriate owner-only access, and avoid silent replacement of an existing key
ID.

**Acceptance tests/gap:** add traversal, absolute paths, Windows
separators/drives, collisions, and revoke/delete confinement to
`tests/test_watermarking.py` . On POSIX separately test owner-private modes; on
Windows test ACL semantics. Those permission/ACL properties were not measured by
this Windows traversal probe.

### C22 — Appending custody leaves an invalid T2 signature attached to the

**Full finding:** Appending custody leaves an invalid T2 signature attached to
the new case

**Severity:** Medium workflow reliability risk for legitimate signed-case
custody updates. Verification with the actual key correctly rejects the changed
body; this is not a false cryptographic acceptance.

**References:** `src/textforensics/casefile.py:1596-1628` ;
`src/textforensics/sealing.py:203-221` .

**Root cause:** `append_custody_entry` changes the signed custody/body/hash but
preserves the old signature and offers no re-signing/invalidation contract.

**Evidence:** `append_retains_invalid_signature` appends one legitimate
synthetic custody event to a T2 case. No-key verification is hash-valid (with
existing unverified-signature warning semantics); public-key verification is
**false**. Expected: the append operation either produces a correctly re-signed
successor or explicitly refuses/downgrades and preserves the prior signature as
historical evidence, not as an apparently current seal.

**Fix plan:** require a new signing operation for signed successors or make an
explicit, reported invalidation/downgrade choice. Preserve and reference the
prior signed version as necessary for custody continuity; do not silently strip
origin authentication and call it equivalent T2 evidence.

**Acceptance tests/gap:** add signed append/re-sign/refusal cases to
`tests/test_casefile_v3.py` and `tests/test_casefile_v4.py` , verify predecessor
immutability and both verification modes, and test the archive path too.

### C23 — Public bundle schema rejects a genuine v3 Trust Map that

**Full finding:** Public bundle schema rejects a genuine v3 Trust Map that
runtime/case schema accept

**Severity:** Medium public-contract/interoperability blocker for portable cases
with current validation-derived v3 Trust Maps.

**References:**
`src/textforensics/schemas/forensic-bundle.schema.json:54-60,108-111` ;
`src/textforensics/schemas/trust-map.schema.json:8-9,142-195` ;
`src/textforensics/casefile.py:239-260` ; `src/textforensics/verify.py:239-242`
.

**Evidence:** `genuine_v3_schema_disagreement` calls the current
`derive_trust_map` with a real empty `ValidationRegistry` , creates a case
through the production sealer, and validates with installed Draft 2020-12
`jsonschema` . Trust-map schema: **no errors**. Case schema: **no errors**.
Runtime combined: **true**. Forensic-bundle schema: **enum and const errors at
`trust_map/schema` **. This is a generated current map, not the malformed map
used in C10.

**Expected/fix plan:** make a deliberate versioning/compatibility decision for
v3 maps inside forensic bundles, then align producers, runtime importers, nested
schemas, manifests, and documentation. `AGENTS.md:42` forbids silently changing
public field meaning; do not merely loosen every old schema without deciding the
compatibility contract.

**Acceptance tests/gap:** validate a complete generated bundle and its embedded
case against all applicable public schemas, for every accepted bundle/map
version pair, including stale v3 dimensions and legacy controls.
`tests/test_case_schema.py` alone is insufficient because its case schema does
not enforce the stricter standalone forensic-bundle schema.

## Verified lower-priority observations / explicitly bounded concerns

### O01 — `bundle_hash` is only a partial presentation hash

`src/textforensics/bundle_consistency.py:363-380` describes a forensic-bundle
content hash but selects only schema/consensus/trust_map/detector_results/input.
`bundle_content_hash_omissions` changes `content_sha256` and provenance and
obtains the same hash. No production security-sensitive caller was established
in this audit; usage found was in consistency tests. **Low, not evidence of a
case-seal bypass.** Rename/document its restricted scope, or version a complete
stable-content hash. Tests at `tests/test_bundle_consistency.py:120-144` should
assert subject/provenance sensitivity if the public helper is intended as a full
identity hash.

### O02 — Strict Ed25519 decoding needs an explicit malformed-key policy

`src/textforensics/ed25519.py:98-110` and the standalone copy accept an encoded
identity public key with sign bit 1 for recovered x=0; the verifier accepts an
identity commitment/zero scalar against that supplied key. The bounded
`ed25519_noncanonical_identity_key` probe confirms acceptance in both product
paths **and in the installed OpenSSL-backed cryptography verifier**. RFC 8032
strict decoding has an x=0/sign-bit rule; add explicit canonical/small-order-key
policy tests and explain any library-policy differences. **Not promoted to a
legitimate-key signature-forgery finding:** the reproduction supplies the
malformed/degenerate trusted key itself, and generated public keys were not
compromised. Do not misstate the independent engine as rejecting it.

## Hypotheses, residual gaps, and limits (not represented as reproduced exploits)

1. **Atomic no-clobber key publication:** `src/textforensics/sealing.py:83-99`
   checks existence and later calls replacing publication. A concurrent creator
   between those operations may be overwritten. This is a clear static race
   concern, but native POSIX concurrency was not executed on this Windows audit
   host; include a deterministic two-writer/no-clobber regression test with C11
   rather than claim it was reproduced here.
2. **Private-key file permissions:** watermark persistence uses ordinary
   `write_text` ; POSIX umask/ACL confidentiality and Windows inherited ACL
   behavior remain to be measured. The confirmed path-confinement defect C21 is
   separate from these unmeasured access-control properties.
3. **Whole-log replacement, suffix deletion, and fabricated evidence:** unkeyed
   local chains/hash seals cannot prevent these without an independently trusted
   checkpoint. Do not fix C07/C08 by implying a local self-consistent hash chain
   authenticates time, identity, or detector execution.
4. **Timestamp trust is intentionally limited:**
   `src/textforensics/timestamp.py:8-18` explicitly verifies only the embedded
   certificate's signature math, not PKI trust, and keeps qualification unknown.
   Acceptance of a self-signed synthetic control is therefore not filed as a new
   trust-store vulnerability. Deployment requiring a trusted TSA, certificate
   policy/EKU, validity/revocation, or qualified status needs an explicit
   external trust policy and independent evidence. No live TSA
   availability/interop claim was measured by this auditor.
5. **Pure-Python signing timing:** `src/textforensics/ed25519.py:13-20`
   documents non-constant-time local signing. No side-channel exploit was
   attempted. Remote/multi-tenant key use would change this deployment
   assumption; the documented local-only caveat is not itself a newly proven
   exploit.
6. **Broad parser/fault-injection coverage:** byte caps are not
   shape/depth/complexity caps. Test bounded malformed DER/JSON, duplicate JSON
   keys, member/path aliasing, invalid UTF-8, excessive nesting, and partial
   writes. Only the concrete bounded cases identified above were executed; a
   recursive-parser memory/CPU exploit was not established.
7. **DSSE/domain separation:** the owned DSSE implementation was fully reviewed.
   No independent DSSE PAE/signature forgery against a valid supplied generated
   key was established. Keep strict canonical base64, exact envelope fields,
   keyid/public-key matching, and expected-payload-type checks intact while
   fixing surrounding metadata/validation bugs.

## Concrete release-blocking acceptance work

- **Authenticated detector outputs**
  Required evidence before the corresponding release claim: C01
  tamper-with-matching-expected-output test fails closed in both watermark
  verifiers; C20 trusted-expiry policy is tested.

- **Authenticated case origin**
  Required evidence before the corresponding release claim: C02
  signer/fingerprint mutation is rejected or explicitly unauthenticated under a
  versioned legacy policy; C22 signed custody updates have defined verified
  successor behavior.

- **Portable/privacy-safe artifacts**
  Required evidence before the corresponding release claim: C03 whole-case
  canary tests; C04 shared pass/fail corpus across
  sealer/packer/combined/offline; C23 generated artifacts pass all applicable
  published schemas.

- **Complete archive verification**
  Required evidence before the corresponding release claim: C05 duplicate/member
  coverage and C18 empty/wrong manifest cases fail; preserve real signed
  controls and external whole-archive digest controls.

- **Bounded untrusted verification**
  Required evidence before the corresponding release claim: C06 no reads after
  rejected container; C12 shape matrix returns failures; C13 invalid times fail
  identically; use small configurable limits rather than resource-stress
  payloads.

- **Provenance/anti-rollback**
  Required evidence before the corresponding release claim: C07 prefix deletion
  is propagated; C08 changed roots cannot be authorized by copied/arbitrary
  chains; C09 manifest framing is unambiguous and versioned.

- **Durable multiwriter provenance**
  Required evidence before the corresponding release claim: C15 serialized
  independent writers and injected I/O failures preserve a reloadable chain; C16
  loaded-head validation and C17 explicitly missing-chain cases are covered.

- **Scientific-artifact replay integrity**
  Required evidence before the corresponding release claim: C10 exact declared
  dimensions required; C19 invalid numeric/count/digest domains rejected,
  coordinated with the core audit.

- **Cross-platform key lifecycle**
  Required evidence before the corresponding release claim: C11 real Windows
  keygen/export + descriptor cleanup and POSIX private modes; C21 create/revoke
  stay within the key store; concurrent no-clobber regression coverage.

- **TSA algorithm interoperability**
  Required evidence before the corresponding release claim: C14 independent
  curve/hash matrix and valid-token controls; preserve declared
  PKI/qualification limits and do not claim new live-provider success.

## Suggested implementation sequence (plan only)

1. **Immediate trust/availability fixes:** payload binding, signer binding,
   whole-case privacy, validation parity, duplicate archives, seal-record
   gating, Windows descriptor/key handling. Add small red-capable regression
   fixtures before fixes.
2. **Provenance correctness:** propagate chain failures; redesign versioned
   anchor state binding and tree framing; add atomic locked/durable append
   semantics and validated workspace heads/missing-evidence states.
3. **Contract consistency:** exact Trust Map dimensions, numeric artifact
   domains, complete legacy manifest validation, public schema compatibility,
   signed-custody lifecycle, key-store confinement/expiry policy.
4. **Independent cross-engine verification:** run the adversarial corpus through
   installed and truly standalone entry points on supported Windows/POSIX
   interpreters; independently encoded DER and cryptography-backed controls must
   remain part of the matrix. Then the parent reruns the full suite/build/gates.
   Do not substitute a green probe-execution exit code or historic coverage
   number for these acceptance results.
