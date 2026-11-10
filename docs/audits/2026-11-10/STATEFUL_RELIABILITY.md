# Stateful reliability, policy, cache, and observatory audit

Baseline: `5ea804c3bcfeaa333ae7d346ee6400ea434e5fdb` . Audit-only; no production
source, tests, configuration, registry, corpus, Git, remote, or
installed-package changes were made by this auditor. All executable probes used
disposable synthetic state below the audit scratch directory, the shared Python
3.12 environment, and the real implementation. No network, browser, GPU,
provider, or user-store access occurred.

## Outcome and evidence

The strongest reproduced defect is a fail-open U3 completion path: a
**structurally verified 400-item synthetic corpus**, with **399 detector
failures per run**, produced two nominally clean `full` runs, cleared a
pre-existing U3 demotion, and reported `temporal_support=true` . Independent
policy instances also persisted a rollback from revision 10 to 1. Other
confirmed defects affect provenance validation, demotion preservation, sample
gates, retry scheduling, cache budgets/invalidation/concurrency, and health
monitoring.

Measured synthetic observations are preserved in `evidence.json` under
`state_primary` , `state_followup` , and `state_fullcorpus` . Each finding
provides the construction and an explicit acceptance test. Temporary probe
scripts/state are not part of the shipped repository. The targeted existing
60-test run passed; that is not a full-suite pass. The NaN nontermination probe
used a separate child with a 1.5-second timeout and left no running job.

Severity convention: **High** = can incorrectly admit/reinstate evidence or
bypass a safety boundary; **Medium** = reproducible wrong measurement,
loss/corruption, operational-budget failure, or API reliability error; **Low** =
localized presentation/contract defect. Preconditions below are part of each
severity, not claims of an unauthenticated remote exploit.

## High-confidence findings

### S01 — Failed observations disappear; incomplete full runs clear

**Full finding:** Failed observations disappear; incomplete full runs clear
demotions and establish temporal support

**High.** `src/textforensics/probe_runs.py:1728-1731` , `:1789-1802` ,
`:1851-1856` , `:1879` ; `:1413-1438` compounds the issue. Related data origin:
`src/textforensics/observatory.py:986-1008` correctly collects failures, which
the coordinator discards.

- **Precondition:** a selected detector succeeds on at least one corpus item and
  fails on the remainder. No malicious input/history is needed.
- **Observed:** `state-fullcorpus-results.json` reports
  `verified_corpus_problems=[]` , 400 selected items and 400 attempts on each
  run, `scored_each=[1,1]` , `alerts_each=[[],[]]` , one cleared registry
  record, zero remaining demotions, two clean full runs, and
  `temporal_support=true` . The first four-item minimal probe gives the same
  result.
- **Expected:** selected, attempted, succeeded, failed, missing, and abstained
  populations must be distinguishable. An incomplete run is not a clean
  full-corpus revalidation, cannot clear demotions, cannot become a complete
  baseline, and cannot advance a clean full-run streak. Metrics on the
  successful subset may be reported only with that denominator and the coverage
  gap.
- **Root cause:** the sole completion check is that `records` is nonempty;
  failure counts/records are never carried into the run manifest or clean-run
  predicate. Slice construction iterates only successful records (`:718-720`),
  so fully failed slices vanish altogether.
- **Fix:** establish an explicit completion invariant against the scope-selected
  item set, persist failure/missing/abstention accounting and item hashes, and
  gate baseline eligibility, demotion clearing, and temporal support on verified
  complete coverage. Keep failures separate from abstention; do not invent
  scores or renormalize missing evidence.
- **Acceptance tests:** verified eight-slice/400-item corpus with one failing
  item, one fully failing slice, 399 failures, all failures, and intermittent
  failures across two runs; retain old demotions and refuse temporal promotion
  for every incomplete case. Pin selected/attempted/success/failure counts and
  missing item IDs. A genuinely complete clean run must still work.

### S02 — Stale policy instances can lower the persisted anti-rollback floor

**High.** `src/textforensics/policy.py:709-710` , `:836-887` , `:975-984` ;
persistence itself is atomic at `:715-732` , but the read/check/advance
transaction is not serialized.

- **Precondition:** two processes or objects share the same policy state/key and
  initialize before one advances it. This is ordinary concurrent or long-lived
  use, not ciphertext forgery.
- **Observed:** object A loaded revision 10; stale object B then loaded revision
  1 with `lower_policy_rejections=[]` ; a fresh object read disk floor **1**,
  expected **10** (`policy_stale_writer`).
- **Expected:** monotonicity must hold across all users of the persisted state,
  not merely inside one object's snapshot.
- **Fix:** hold an interprocess lock across key initialization and
  reload/check/advance/commit; re-read authenticated state while locked; verify
  persisted revision/digest and do not publish in-memory success before durable
  commit. Generate new keys with exclusive creation rather than an
  exists-then-replace race.
- **Acceptance tests:** two independent instances initialized at the same old
  floor, interleaved loads 10 then 1, same-revision conflicting digests,
  concurrent first key creation, and failed persistence. Final disk floor must
  never decrease and all accepted instances must reference the same key
  material.

### S03 — U3 demotion overwrites a foreign/manual demotion, which a later

**Full finding:** U3 demotion overwrites a foreign/manual demotion, which a
later clean run erases

**High.** `src/textforensics/probe_runs.py:1272-1298` , `:1220-1234` ,
`:1325-1333` .

- **Precondition:** a target validation record is already demoted for a non-U3
  reason and a U3 Tier-1 event subsequently occurs.
- **Observed:** `foreign_demotion_erased` starts with a manual reason, replaces
  it with a `U3 probe run ...` reason, then `clear_demotions` leaves
  `demoted_by=null` . The original manual safety restriction is lost.
- **Expected:** U3 clearing must remove only the U3 restriction; the previous
  independent demotion must survive. The existing test
  `tests/test_probe_runs.py:1151-1175` covers clearing a foreign reason
  directly, not the overwrite-then-clear path.
- **Fix:** represent demotions as separate source-scoped events/reasons or
  otherwise preserve existing non-U3 restrictions. Re-sign changes without
  discarding independent history.
- **Acceptance tests:** manual -> U3 -> clean remains manually stale; U3 ->
  another U3 retains an auditable history; clean clears only U3 reasons; foreign
  reasons cannot be rewritten just to make them clearable.

### S04 — Invalid or expired capability evidence is still accepted as

**Full finding:** Invalid or expired capability evidence is still accepted as
validated/supported

**High for consumers treating these APIs as claim gates.**
`src/textforensics/policy.py:112-117` , `:134-137` , `:201-216` , `:242-267` ,
`:366-384` .

- **Precondition:** a capability claim carries `tier=VALIDATED` but no executed
  evidence, no evidence at all, or an expired `valid_until` . CLI registration
  also does not call `validate_claim` (`src/textforensics/cli.py:2035-2050`).
- **Observed:** an empty-evidence claim expiring in 2000 yields two
  `validate_claim` errors, yet the calibration policy passes it and
  `ledger_to_trust_dimension` returns `supported`
  (`capability_invalid_expired`). Expiration is only printed as a limitation.
- **Expected:** evidence tier is not self-authenticating. Invalid/expired claims
  cannot authorize calibrated output or raise a Trust Map dimension to
  supported.
- **Fix:** validate at ingestion and at the decision boundary; use a supplied
  UTC clock for expiry; verify artifact existence/provenance under a defined
  evidence resolver when claiming execution-backed validation. Define
  duplicate-claim replacement rather than returning the first ever registration
  as the 'current' claim.
- **Acceptance tests:** missing evidence, REPORTED-only evidence with VALIDATED
  tier, expired/today/malformed dates, unavailable artifacts, and replacement of
  an old claim. All supported/validated predicates and policy evaluation must
  agree on eligibility.

### S05 — Imported snapshots bypass per-record corpus and observation validation

**High when imported snapshots are used as reliability evidence.**
`src/textforensics/observatory.py:1013-1017` , `:1038-1058` , `:1084-1090` ,
`:1095-1103` , `:1216-1224` .

- **Precondition:** caller imports or compares a snapshot dictionary/file rather
  than constructing it through `snapshot_from_observations` .
- **Observed:** two records with sample IDs not present in the corpus and
  changed per-item text hashes are accepted as **stable**, with two comparable
  samples and `drift_claim_allowed=true` , provided the top-level corpus hash
  string is copied (`imported_snapshot_unlinked`).
- **Expected:** top-level hash equality is not proof that record IDs/hashes link
  to that corpus. The same numeric, verdict, calibration-ID, timestamp,
  duplicate, detector, and corpus-member checks must protect imported
  observations.
- **Fix:** normalize and validate every imported record/failure, verify exact
  per-item membership/hash links and declared counts, and reject unknown IDs or
  inconsistent identities. Validate before mutating stored snapshots. Retain
  missing/failed detector IDs in comparisons instead of deriving the detector
  universe only from successful records (`:1130-1139`).
- **Acceptance tests:** foreign IDs, same ID/different hash, forged top-level
  hash, bad counts, duplicate records, bad verdict/calibration linkage,
  malformed timestamps, and detectors with only failures. None may produce a
  stable/claimable result.

### S06 — Temporal streak ignores intervening versions, partial-run

**Full finding:** Temporal streak ignores intervening versions, partial-run
breaches, and provider identity

**High for temporal evidence promotion.**
`src/textforensics/probe_runs.py:1373-1384` , `:1402-1438` , `:1732-1736` ,
`:1773-1787` ; provider-diff handling at `:1178-1205` does not rebaseline.

- **Preconditions:** history changes detector version then returns to an earlier
  version; latest partial-scope run has Tier 1/2; or provider model/version
  changes without changing adapter version.
- **Observed:** history v1-clean -> v2 -> v1-clean yields two 'consecutive' v1
  clean runs and temporal support. Two full clean runs followed by a monthly
  Tier-1 breach still yield temporal support. Two full entries with provider
  versions p1/p2 also yield temporal support, and baseline resolution chooses p1
  for the p2 run (`streak_*`, `provider_changed_temporal_support` ).
- **Expected:** do not filter out streak-breaking events before examining
  chronology. Version/provider identity and corpus identity must define an
  evidence epoch; a current breach cannot disappear because its scope is
  partial.
- **Fix:** evaluate complete detector chronology first, stop on identity/corpus
  changes or current safety breaches, and key/rebaseline by the exact
  adapter/provider/model/calibration/configuration provenance. Define watch
  expiry/recovery explicitly; current code finds any historic Tier-2 alert
  forever (`:1421-1430`).
- **Acceptance tests:** v1 -> v2 -> v1, corpus A -> B -> A, provider p1 -> p2 at
  identical adapter version, latest monthly breach, clean full recovery, and
  stale/duplicate run entries. Clean counts and current watch must follow the
  same chronological state machine.

### S07 — One human sample can cause Tier-1 detector-wide demotion despite

**Full finding:** One human sample can cause Tier-1 detector-wide demotion
despite the n>=50 rule

**High for false safety actions and evidence integrity.**
`src/textforensics/probe_runs.py:1011-1045` , `:1096-1121` ; declared minimum at
`:159` , calculated eligibility at `:664` . Drift-statistic handling correctly
consults eligibility at `:948-949` ; flip/calibration handling does not.

- **Precondition:** a human slice has fewer than 50 paired observations,
  including a partially failed run, and at least one human->AI flip.
- **Observed:** n=1, `drift_signal_allowed=false` , a single human->AI flip
  yields `demote=true` and alert tiers `[1,2]` (`one_sample_demotes`). The rate
  is 1/1=100%, not reliable evidence from 50 paired samples.
- **Expected:** the declared sample floor applies to the actual comparison
  denominator, not total current records, and one-sample drift cannot demote the
  detector. The module's blanket 'single run never demotes' wording is also
  contradicted by its deliberate absolute-FPR behavior; that policy needs
  explicit reconciliation rather than relying on the wording.
- **Fix:** enforce minimum paired n separately for flips and calibration drift;
  validate label composition, effective denominators, and the persistence
  requirement for the chosen rule. Preserve the intentional absolute-FPR rule
  only with a clearly specified first-run policy and its declared n>=100 gate.
- **Acceptance tests:** 1, 49, 50 paired observations; n_current>=50 but
  n_paired=1; one-sample ECE jump; mixed-label slices; exact 5% threshold and
  values just above it. Below-floor comparisons may be recorded, never escalated
  as adequately sampled drift.

### S08 — Observatory execution does not honor an active emergency stop

**Full finding:** Observatory execution does not honor an active emergency stop
between detector calls

**High for remote-adapter users; Medium for local work.**
`src/textforensics/observatory.py:972-1000` ;
`src/textforensics/probe_runs.py:1724-1729` delegates to that unguarded loop.
CLI checks only dispatch entry (`src/textforensics/cli.py:1551-1561`).

- **Precondition:** direct observatory/coordinator use with an active sentinel,
  or sentinel activates after a long CLI drift run begins. A plugin need not
  call the built-in engine, whose own guard is separate.
- **Observed:** with a disposable active stop file, `take_snapshot` invoked a
  supplied synthetic detector and stored one observation
  (`snapshot_ignores_stop`). No real remote call was made.
- **Expected:** a stop must prevent the next operation, including opt-in remote
  execution, not merely stop new CLI commands. It must not turn a
  stopped/incomplete run into successful revalidation.
- **Fix:** check the canonical guard before execution and between
  sample/detector operations; propagate the stop as an explicit
  terminal/incomplete condition, not an ordinary suppressed detector failure.
  Define cancellation/timeout semantics for already-running plugins separately.
- **Acceptance tests:** stop already active, stop activated after first item,
  custom local plugin not using `analyze_text` , and synthetic remote adapter
  under explicit opt-in. Zero subsequent calls; no demotion clearing, baseline
  advancement, or clean-run promotion.

## Additional reproduced correctness/reliability defects

### S09 — Score direction is discarded and attacked-slice TPR reverses a

**Full finding:** Score direction is discarded and attacked-slice TPR reverses a
valid detector

**Medium.** `src/textforensics/observatory.py:879-896` , `:826-844` ;
`src/textforensics/probe_runs.py:364-379` , `:622-635` ;
`src/textforensics/probe_metrics.py:365-377` .

TFDP explicitly permits `lower_means_ai`
(`src/textforensics/schemas/detector-result.schema.json:58-64`), but snapshot
normalization/score-series storage omit direction and run aggregation always
uses `score >= threshold` . A human score 0.9 and AI score 0.1 with
lower-means-AI yield reported TPR **0** at FPR **0**, whereas the direct
lower-tail decision `score <= 0.1` yields TPR **1**, FPR **0**
(`lower_score_direction_ignored`). Preserve direction/range/semantics in
snapshots and histories; orient empirical ROC correctly or report unavailable
for unknown/not-applicable direction. Test higher/lower affine-equivalent
scores, tied scores, unbounded native ranges, and unknown direction; equivalent
detectors must yield identical TPR/FPR.

### S10 — NaN can hang KS indefinitely and fabricate FPR zero

**Medium; potentially High for an unattended history-import boundary.**
`src/textforensics/probe_metrics.py:69-93` , `:298-313` ;
`src/textforensics/probe_runs.py:383-389` , `:1575-1579` , `:1617-1619` .

`ks_statistic([NaN],[0])` timed out after 1.5 seconds: both ordered comparisons
and NaN equality are false, so the tie branch advances neither cursor. A NaN
threshold produces FPR **0.0** for a human score 0.9 instead of rejecting the
undefined decision (`nan_ks_hang`, `nan_fpr` ). `validate_run_manifest` accepts
a NaN score; `load_run` uses Python's permissive JSON parser. Live observation
creation rejects nonfinite scores, but saved/imported history and direct metric
calls do not. Reject nonfinite numeric inputs before sorting/comparison, use
strict JSON parsing/serialization, and validate integer
cardinalities/types/bounds in Wilson/KS/PSI inputs. Test NaN/+Infinity/-Infinity
in every score, threshold, p-value, count and configuration surface; rejection
must be bounded and must not emit a finite metric for undefined input.

### S11 — Cache capacity and replacement accounting are wrong; compression

**Full finding:** Cache capacity and replacement accounting are wrong;
compression is not resident-size enforcement

**Medium.** `src/textforensics/detection_cache.py:357-367` , `:444-468` ,
`:612-615` .

An empty cache configured for 20 bytes accepted and retained a 75-byte
uncompressed entry (`cache_budget`). Capacity is checked *before* adding the
incoming entry, and oversized entries are never refused. Putting the same key
twice counts two entries; invalidating the sole real entry leaves one phantom
entry and seven phantom bytes (`cache_replace_accounting`). Compressed byte
length is charged while the raw dictionary remains resident; disk load trusts
stored sizes and skips capacity admission. Fix admission using incoming/resident
cost, replace accounting by subtracting the old entry, reject single oversized
results, and validate/recompute costs when loading. Test exact-boundary size,
single oversized object, replacement at capacity, repeated replacement/deletion,
compressible large results, and an oversized stored cache; real contents, index,
and statistics must reconcile and never exceed the configured budget.

### S12 — Cache config/max-age invalidation fails open and callers can

**Full finding:** Cache config/max-age invalidation fails open and callers can
mutate cached evidence

**Medium.** `src/textforensics/detection_cache.py:98` , `:393-400` , `:424` ,
`:440` , `:448-456` , `:561-565` .

With a current config hash set, an entry missing `metadata.config_hash` is
returned fresh; `max_age_seconds=0.001` is never consulted and a 0.01-second-old
entry is still fresh (`cache_unknown_config_max_age`). Result and metadata are
stored/returned by reference: changing a returned result to `v=99` changes the
next cache hit without recomputation or byte-accounting change
(`cache_mutable_result`). Require exact config provenance or miss
conservatively, enforce maximum age, validate explicit TTL overrides rather than
`ttl_seconds or default` , and snapshot/copy immutable serialized results.
Tests: absent/current/mismatched config hash, max-age shorter than TTL,
zero/negative/NaN/Infinity overrides, mutations of put arguments and get
results, and restart with changed runtime config.

### S13 — Advertised thread safety is absent; concurrent clear resurrects

**Full finding:** Advertised thread safety is absent; concurrent clear
resurrects entries outside the index/statistics

**Medium.** `src/textforensics/detection_cache.py:408-424` , `:573-580` ; module
claim at `:9` .

A deterministic two-thread probe pauses a real `get` inside the supported custom
invalidator, calls `clear` on the other thread, and resumes the read. The
cleared entry is **reinserted**, while `stats.total_entries` remains **0**
(`cache_read_clear_race`: actual entries 1, stats entries 0). The resurrected
entry is no longer correctly indexed for invalidation. Serialize all compound
cache/index/statistics transactions with a real appropriate lock; do not invoke
arbitrary callbacks under a non-reentrant lock without a defined protocol. Pin
this interleaving and get/invalidate/put/cleanup races, asserting no
resurrection, stale return, exceptions, or index/statistic divergence.

### S14 — Cache persistence is not part of lifecycle and malformed loads

**Full finding:** Cache persistence is not part of lifecycle and malformed loads
leave poisoned partial state

**Medium.** `src/textforensics/detection_cache.py:291-297` , `:582-624` .

After `put` and `stop` , configured `storage_path` does not exist: save is a
private method with no lifecycle caller (`cache_lifecycle_not_persisted`). On an
explicitly loaded file with an invalid expiry, `_load_from_disk` returns false
only *after* installing the entry; subsequent `get` raises `ValueError` instead
of a graceful miss (`cache_partial_load`). Writes truncate the target directly
and load reads without a file/count/size budget. Add an explicit, documented
persistence lifecycle, atomic temp+flush+replace, validated temporary loading
before publication, error observability, and size/count limits. Test normal
context exit/restart, forced write failure preserving the old file, bad
first/last entry, invalid/naive expiry, oversized metadata/file, and
simultaneous writers. Do not silently claim successful persistence when a
private save was never invoked.

### S15 — Retry readiness ignores backoff, half-open admits unlimited

**Full finding:** Retry readiness ignores backoff, half-open admits unlimited
probes, and opening shortens Retry-After

**Medium.** `src/textforensics/retry.py:126-143` , `:192-218` .

After a closed-gate failure requesting 30 seconds of backoff, `ready()`
immediately returns `(true,0)` . On the opening failure with `retry_after=60` ,
`circuit_reset_timeout=5` overwrites the longer deadline; at t+5 both the first
and second `ready()` calls are allowed (`retry_closed_backoff`,
`retry_half_open_retry_after` ). This contradicts both backoff and 'one probe'
semantics, and `RetryPolicy` also accepts nonfinite delay/reset values. Respect
a monotonic next-allowed deadline in every state, combine circuit timeout with
the longer provider deadline, acquire/release one half-open probe atomically,
and validate all finite durations/counts. Test repeated scheduled callers before
backoff, exactly one half-open request across concurrent callers, long
Retry-After plus short reset, failed/cancelled recovery probes, and finite
validated policy bounds.

### S16 — Waiting on an open retry gate consumes an attempt without calling

**Full finding:** Waiting on an open retry gate consumes an attempt without
calling the operation

**Medium.** `src/textforensics/retry.py:286-310` .

An already-open gate with `max_retries=0` waits its five-second deadline and
raises `RuntimeError('Retry gate exhausted')` with **zero operation calls**,
although the operation would succeed and one initial attempt is allowed
(`open_gate_consumes_attempt`). `last_exception` is never assigned. Keep
readiness waiting separate from operation-attempt counting, and preserve the
actual last failure when exhaustion is genuine. Test initially
open/half-open/closed gates at retry budgets 0/1, fake clock/sleep,
cancellation, and a successful first operation after the wait.

### S17 — Built-in health thresholds do not implement their own

**Full finding:** Built-in health thresholds do not implement their own
warning/critical contracts

**Medium.** `src/textforensics/observatory.py:1764-1785` , `:1802-1814` ,
`:1835-1871` , `:1874-1894` .

Two requests in the last minute imply 2/60 = **0.033333 rps**, below the
declared 0.1 critical threshold; no throughput alert is ever returned because
the check is not inverted (`health_throughput`). P95 latency 4,000 ms exceeds
the declared 3,000 warning threshold but is returned healthy because `check_fn`
short-circuits at its separate 5,000 threshold (`health_latency_warning`). The
entropy check similarly short-circuits above 0.3, making its declared warning
interval up to 0.5 unreachable. Make threshold direction and boundaries
authoritative in one place rather than combining incompatible pass/fail gates.
Test rate 0/below/at/above 0.1 and 0.5, latency around 3,000/5,000/10,000, and
entropy around 0.3/0.5. `tests/test_detector_health.py:245-258` explicitly
expects healthy for two requests and contains incorrect arithmetic commentary;
change the expectation from the rate definition, not from current output.

### S18 — Health reports can label undefined or ancient observations healthy

**Full finding:** Health reports can label undefined or ancient observations
healthy and refresh their timestamp

**Medium.** `src/textforensics/observatory.py:1937-1960` , `:1991-2044` .

Recording NaN latency yields `HEALTHY, health_score=1.0` (`health_nan`). A sole
latency metric timestamped in 2000 still yields healthy and gets a fresh
`last_updated` on read (`health_stale_observation`). Missing checks are omitted
from the denominator and fewer-than-minimum score samples count as passed
checks. Reject nonfinite/invalid metric values, use an explicit observation-age
window and sufficient-sample state, distinguish observed-at from
report-generated-at, and return unknown/offline/degraded when required evidence
is missing/stale. Tests: no data, one stale datum, finite fresh data,
NaN/Infinity/negative latency, metric disappearance, and minimum-sample
boundaries. A fresh report time must never imply fresh measurements.

### S19 — Health alert persistence loses the enum type; alert history is

**Full finding:** Health alert persistence loses the enum type; alert history is
unbounded

**Medium.** `src/textforensics/observatory.py:1663-1674` , `:1712-1725` ,
`:1917` , `:1985-1989` .

Saving/loading a report with an alert succeeds, but reserializing it raises
**AttributeError**, because `HealthAlert(**a)` keeps `severity` as a plain
string and `to_dict()` accesses `.value` (`health_persistence`). Existing
round-trip test checks only alert count. Separately, `max_history=2` retains two
metric points but six alerts after six anomalies; repeated persistent anomalies
append forever, including re-evaluation on unrelated metric updates. Rehydrate
severity with `AlertSeverity(...)` , validate stored values, and
bound/deduplicate alert history by state transition/time with explicit
retention. Test save -> load -> save/to_dict equality with all severities, bad
stored severities, sustained anomaly under a tiny history cap, recovery, and
recurring distinct incidents.

### S20 — Probe history is overwriteable and run validation is materially

**Full finding:** Probe history is overwriteable and run validation is
materially weaker than the shipped schema

**Medium; High if history files are accepted as authoritative evidence from
another party.** `src/textforensics/probe_runs.py:1538-1582` , `:1585-1606` ,
`:1615-1629` ; contract `src/textforensics/schemas/probe-run.schema.json:1` .

Saving a different manifest with the same `run_id` replaces the old file; the
directory contains one changed record (`run_history_overwrite`), contradicting
the append-only contract (`probe_runs.py:28-29`). The custom validator accepts
NaN scores and missing schema-required `code_sha` , `thresholds` ,
`alpha_per_run` , `is_baseline` , and linkage fields (`nan_manifest_accepted`).
It does not check unknown keys or verify links/metric totals against the score
series. Fix no-clobber append semantics (optionally idempotent exact-byte
re-save only), safe basename run IDs, canonical strict validation, item-hash and
previous/baseline/run-digest linkage, and chronological UTC parsing rather than
arbitrary ISO string sorting. Test changed-content duplicate ID, concurrent
duplicate saves, malformed/non-UTC/out-of-order dates, omitted required fields,
NaN, unknown fields, forged predecessor and inconsistent metric/series totals.
Hash-only integrity is not issuer authentication; label it accordingly.

### S21 — A partial calibrated baseline causes a KeyError instead of

**Full finding:** A partial calibrated baseline causes a KeyError instead of
recording missing calibration evidence

**Medium.** `src/textforensics/probe_runs.py:549-558` .

With two currently scored calibrated items and only one baseline item,
`compute_run_metrics` raises `KeyError: 't'` (`partial_calibrated_baseline`).
Score and flip paths explicitly check baseline membership; the calibrated path
directly indexes every current labelled item. This is reachable after an earlier
partially failed baseline (S01). Use an explicitly matched item set and disclose
its n, or withhold the aggregate when complete required probability evidence is
absent; do not silently average only the surviving inputs. Test current/baseline
supersets/subsets, disjoint sets, mixed calibration availability, and changed
calibration IDs.

### S22 — Model-card and codec numeric validation accepts non-JSON/nonfinite

**Full finding:** Model-card and codec numeric validation accepts
non-JSON/nonfinite values; zero metrics disappear

**Medium for nonfinite transport; Low for zero display.**
`src/textforensics/model_card.py:255-268` , `:375-383` , `:418-427` , `:599-601`
, `:638-640` ; `src/textforensics/result_codec.py:190-193` , `:215-220` .

`ModelCard.from_dict` accepts a NaN metric and `to_json()` emits literal `NaN`
(`nan_model_card`); intervals, dataset sizes, ratios, and bounded
AUC/calibration fields also lack semantic range validation. A zero ROC AUC, PR
AUC, or calibration error displays `N/A` , losing valid and sometimes critical
performance evidence (`model_card_zero_hidden`). Codec encode forbids NaN, but
decode accepts it inside a valid enterprise-policy settings object and returns
it under default validation (`codec_decode_nan`). Reject nonfinite JSON tokens
and recursively nonfinite numeric values, enforce relevant bounds/count/interval
ordering, and distinguish `None` from zero during rendering. Test zero,
endpoints, reversed CIs, out-of-range AUC, negative sizes, inconsistent split
ratios, NaN/+Infinity/-Infinity and strict JSON round-trip symmetry. No extra
dependency is required for these checks.

## Further contract problems found by source review / minimal probes

These are lower-priority than S01–S22 but should not be mistaken for implemented
guarantees.

1. **Capability required-tier typos fail open; interior glob patterns silently
   do not apply.** `src/textforensics/policy.py:339-343` , `:373-382` ,
   `:398-411` . A READABLE claim satisfies a `misspelled-tier` requirement
   (`capability_unknown_tier`), and `vendor/*-v1` does not match
   `vendor/model-v1` . Existing mutation tests explicitly pin unknown-tier
   acceptance and interior-star rejection
   (`tests/test_enterprise_policy.py:1492-1514`, `:1913-1917` ). Reject
   unsupported tiers/pattern grammar at ingestion or use proper glob matching;
   test malformed tiers and every documented pattern shape through the public
   policy API. **Medium** for operator-authored policy mistakes.
2. **Enterprise digest does not cover schema-accepted `conditions` .**
   `src/textforensics/policy.py:523-531` ;
   `src/textforensics/schemas/enterprise-policy.schema.json:86-89` . Changing
   conditions leaves the digest equal (`policy_conditions_digest`); `evaluate`
   also ignores conditions. Hash all accepted policy semantics, and either
   implement a specified condition grammar or reject conditions explicitly until
   supported. Test that every semantically accepted condition change changes the
   digest and that applicability obeys it. **Medium**, not a demonstrated
   runtime remote-policy bypass because conditions are currently unused.
3. **Frozen enterprise policies remain deeply mutable and can bypass
   admission.** `src/textforensics/policy.py:568-598` , `:910-924` , `:986` ,
   `:1042-1065` . Mutating `engine.policy.rules[0]['action']` after loading
   changes status to disabled while the stored digest remains unchanged and
   recomputed content no longer matches (`policy_mutable_content`).
   Constructor/setter also accept unvalidated policies; unknown actions fall
   through to status `ok` . Use one validated admission path,
   immutable/deep-copied content, and revalidation as appropriate. Pin nested
   mutation and constructor/setter invalid-rule behavior. **Medium** for API
   callers sharing policy objects, not an assertion that arbitrary in-process
   attackers need this bypass.
4. **Nontransactional state exports remain.**
   `src/textforensics/observatory.py:1019-1029` , `:1700-1709` ;
   `src/textforensics/model_card.py:662-676` ;
   `src/textforensics/result_codec.py:231-241` ;
   `src/textforensics/probe_corpus.py:572-584` . They directly truncate files
   rather than atomically replacing them. U3 registry writes and run save are
   individually atomic, but registry mutation precedes manifest
   construction/save (`probe_runs.py:1838-1882`), so a failed manifest save can
   leave a demotion/clearing whose cited run does not exist. Stage/validate all
   outputs before committing, define recovery/transaction semantics, lock shared
   read-modify-write targets, and pin fault injection before/during each write.
   **Medium**; crash/concurrent-write consequences are source-derived, not a
   forced host crash.
5. **Codec features are incomplete rather than equivalent to the advertised
   behavior.** `src/textforensics/result_codec.py:57` , `:96-111` , `:207-213` ,
   `:254-263` . Configured migration callbacks are not consumed; migration is
   warn-and-return unchanged; streaming materializes the whole byte string. The
   schema-version map advertises names not supported by the imported generic
   validator (`src/textforensics/schema.py:171-196`); its trust-map current
   version is v2 even though the shipped Trust Map schema accepts v3. Keep these
   explicit limitations or implement and test actual callbacks/dispatch/bounded
   streaming; do not silently relabel artifacts. No destructive migration was
   observed.

## Independent mathematical checks

The audit did not copy expected numbers from existing tests. `math_oracles` and
`ks_exhaustive_oracle` derive expectations directly from definitions:

- KS: `max_t |count(a<=t)/n - count(b<=t)/m|` ; independent enumeration covered
  **225 pairs** of length-four discrete samples, with **zero mismatches** for
  finite values. The separate NaN nontermination is still a defect.
- Wilson, k=0/n=50/z=1.96: upper `z^2/(n+z^2)` = **0.07135003417431873**,
  matching the implementation.
- Two-bin PSI with reference proportions (0.5,0.5), actual (0.25,0.75): sum
  `(a-e) ln(a/e)` = **0.2746530721670274**, matching.
- Probabilities (0.2,0.2), labels (0,1): one-bin ECE `|0.2-0.5|` = **0.3**;
  Brier `(0.2^2+0.8^2)/2` = **0.3400000000000001**, both matching.
- Holm p=(0.01,0.04,0.03): sorted step-down running maximum gives
  **(0.03,0.06,0.06)** in original order, matching.
- FPR is FP divided by the labelled human population, not just decided humans.
  The current verdict-based formula counts abstentions in that denominator and
  reports decided counts separately in the legacy observatory. That is a
  defensible unconditional operating-point definition, not itself a math bug.
  The defect is silent deletion of execution failures or changing denominator
  populations without disclosure.
- Attacked TPR expected value for lower-means-AI was derived from the explicit
  lower-tail classifier, not by negating the implementation's reported metric.
- Throughput expected 2/60 comes directly from the documented 60-second window;
  the existing test's claim that this exceeds 0.1 is false.

No general claim of statistical validity beyond these bounded checks is made. KS
p-values are deliberately asymptotic, PSI uses smoothed reference-quantile bins,
and effect thresholds are design choices rather than proof of significance.

## Corpus, provenance, privacy, and resource-budget assessment

- Reviewed every owned source line; focused matching tests, related schemas,
  integration seams and corpus artifacts are itemized in `inventory.json` with
  full/partial/programmatic-review distinctions.
- The committed `docs/probe-corpus/v1.0.0/manifest.json` was parsed and all
  **400 items** checked: eight slices of **50**, **400 distinct content
  hashes**, canonical item-list fingerprint recomputes, `verify_manifest=[]` .
  Dataset counts: MAGE 150, RAID 100, Beemo 50, DetectRL-X 50, OpAI-Bench 50.
  Recorded transforms: double-space-after-period 30, trailing-newline 14,
  curly-apostrophe 4, Unicode-ellipsis 2. This verifies the committed metadata,
  not possession/labels/licences of external raw corpus files.
- `testdata/drift_corpus.json` has **34** actual and declared samples, **22**
  labelled human and **12** labelled AI, all text hashes and stored word counts
  verified. AI labels are explicitly formulaic-style proxies, not authorized
  provider outputs; do not present this fixture as measured real-generator
  validation.
- The shipped frozen corpus's human slices have n=50 and deliberately cannot
  establish the coordinator's n>=100 human-FPR claims. ESL is explicitly absent,
  conformal coverage/MMD are explicitly unavailable, and native scores without
  calibrated probabilities leave ECE/Brier unavailable. These are documented
  **limitations**, not requests to relax thresholds.
- No user cache or external corpus text was opened. Therefore held-back label
  correctness, live licence claims, and the corpus/U1 disjointness claim could
  not be independently verified here; their manifest assertions are not upgraded
  to executed evidence by this audit.
- `CURRENT_GENERATORS` is dated and no in-module cadence freshness gate exists.
  The builder filters current-generator rows by label/language/quality, not
  membership in that list (`scripts/build_probe_corpus.py:390-402`), and
  per-item manifests do not retain generator identity. Without the external raw
  source, the assertion that those exact four generators populate the slice is
  **unverified**, not a confirmed wrong-generator finding. Preserve enough
  generator/version provenance to verify future builds.
- `verify_manifest` checks content hashes/counts but does not fully enforce its
  transform provenance contract: it does not require transforms specifically on
  `benign-transformed` , prohibit them on other slices, or validate base-hash
  format (`src/textforensics/probe_corpus.py:468-476`). This is an
  integrity-validation gap; it does not prove the committed corpus is wrong. Add
  those exact invalid-fixture acceptance tests.
- Cache storage is opt-in by `storage_path` ; it hashes the input key rather
  than saving the `text` argument. However arbitrary `result` /`metadata`
  dictionaries are persisted verbatim, with no raw-text gate, retention scrub,
  encryption or keyed content hash. That is a **privacy contract limitation**
  for sensitive caller-supplied evidence, not proof that a valid built-in
  detector leaks submitted text. Expired/cleared data is not automatically
  scrubbed from a previously saved file because lifecycle persistence is absent
  (S14).
- Policy state uses authenticated Fernet ciphertext and atomic file replacement;
  it correctly raises on ordinary corrupt ciphertext/wrong keys. Its key is
  stored beside state and the anti-rollback floor is not an externally anchored
  freshness proof. Restoring an old valid state+key or explicitly
  resetting/removing it is outside its current protection. This does not excuse
  S02's ordinary stale-writer violation.
- U1 record 'signatures' recomputed by U3 are content digests, not externally
  authenticated signatures. U3 changes them consistently in successful
  single-writer probes, but its reasons currently link to mutable run IDs
  without a run digest/existence proof (S20 and transactional note). No external
  signer was invoked.
- Enterprise settings are schema data and the engine returns rule evaluations;
  repository call-site review found no runtime analysis/settings consumer of
  `EnterprisePolicyEngine.evaluate` . Do not describe loading a policy as
  enforcing all runtime analysis/remote-access settings. Capability policy
  similarly evaluates claims rather than intercepting inference automatically.
  These are integration limitations pending a clearly specified enforcement
  surface.
- No per-plugin timeout, wall-clock/query/token budget, text-byte limit, or
  interruptible execution mechanism is exposed by `take_snapshot` ; synchronous
  plugin execution runs inside its nested loops. This is a **resource-control
  limitation** and needs explicit policy/testing before scheduling
  untrusted/remote adapters. The confirmed emergency-stop bypass is S08.
- `models.py` is a lightweight result-container module, not an independent
  trust-validation boundary. `constants.py` retains the documented fixed exit
  values. `config.py` correctly checks environment integer/boolean values and
  UTF-8 byte limits on ordinary regular-file reads; direct `Settings`
  construction is not validated, and `read_text_file` uses
  stat-then-unbounded-read rather than a bounded streaming read.
  File-growth/special-file handling remains a resource-hardening limitation; no
  large allocation/special-file probe was run.

## Test gaps that matter

Several test suites are large mutation-focused pin sets, not evidence that the
invariants above hold. Specific examples: unknown capability tiers and
unsupported interior globs are deliberately accepted/pinned; health alert reload
is never reserialized; the cache replacement/clear race is absent; probe-run
tests use injected primitives and complete successful snapshots; current U3
integration tests do not include selected-but-failed items. Fuzz helpers often
catch `Exception` around both the operation and assertions, so a failed
assertion can be swallowed (`tests/fuzz/fuzz_drift.py`,
`tests/fuzz/fuzz_enterprise_policy.py` ). These facts explain coverage gaps;
they are not suppression/dismissal recommendations. Acceptance tests should
exercise the real implementation and defined failure boundaries.

## Scope and remaining work

No implementation was attempted. Recommended ordering is
S01/S02/S03/S04/S05/S06/S07/S08 first, then the score/math, cache, retry, health
and transport defects. Parent-owned detector/engine/validation/evidence/schema
findings may overlap the boundary notes; reconcile by root cause rather than
counting the same defect twice. Full suite, package/build verification,
network/provider behavior, cross-process stress on every platform, power-loss
durability, real user-store state and live corpus/provider verification were
intentionally not run.
