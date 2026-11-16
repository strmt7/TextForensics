# Mutation Proof Scope

Status: Audit W7 (CC-18), branch `audit-w7-f`, base main `7d2112c`.
This document states exactly what the mutation proof covers, what it
does not cover, and how the boundary was measured — so no claim about
the proof is ever read as broader than the evidence.

## What the proof covers

The mutation proof is the baseline in `mutation-baseline.toml`
(`equivalent` key) plus the gate in `tests/test_mutation.py`. Every
baseline entry is a mutant that was executed against the test suite,
survived it, and was then hand re-proved equivalent in a scratch
worktree (the re-prove is the authority: killables are killed by a
named test, equivalents survive it). Nothing is added to the baseline
without that proof.

After W7 the baseline covers **46 modules** with **7010 entries**
(6937 at main `7d2112c` + 73 appended in W7: 44 annotation-equivalent
+ 29 runtime-equivalent).

### The W7 extension (CC-18): `textforensics.dsse` + `textforensics.ed25519`

These two hand-rolled crypto primitives underpin the sealing trust
model (DSSE envelope format with PAE encoding; pure-stdlib Ed25519
per RFC 8032). They were enumerated, proved, and appended in W7:

| module | live items | proof items | exec-killed | survived | incompetent |
| --- | --- | --- | --- | --- | --- |
| `textforensics.dsse` | 216 | 216 | 186 | 29 | 1 |
| `textforensics.ed25519` | 1189 | 1023 | 970 | 53 | 0 |
| **total** | **1405** | **1239** | **1156** | **82** | **1** |

Survivor disposition (82): 44 annotation-equivalent (PEP 563
postponed-evaluation `|` annotations, never evaluated at runtime),
29 runtime-equivalent (hand re-proved, 0 gaps), 9 killed by new kill
tests during the hand re-prove. The single incompetent item is a
cosmic-ray operator crash on a dotted exception name
(`ExceptionReplacer` on `binascii.Error` in dsse) — no mutant exists
for it, so there is nothing to prove.

Kill tests: `tests/test_audit_w7_worker_f_dsse.py` (10 tests) and
`tests/test_audit_w7_worker_f_ed25519.py` (13 tests). Each covers
100% of the statements in its module, strictly dominating the
previous coverage (`tests/test_sealing.py`: 83% dsse / 88%
ed25519). The runner maps each module to its kill file only
(`scripts/run_mutation.py`, `_MODULE_TEST_FILES`).

## What the proof does NOT cover (explicit out-of-scope boundary)

### The 13 non-baselined modules

The following modules have **no baseline entries** and are **not
covered by the mutation proof**. They are interface, transport,
configuration, probe, or feature/model layers — not safety-critical
decision logic — and were deliberately left out of scope by the
CC-18 decision:

| module | layer / reason out of scope | live items |
| --- | --- | --- |
| `textforensics.adapter_scanner` | feature layer: adapter discovery, not decision logic | 776 |
| `textforensics.api` | interface layer: public API surface | 134 |
| `textforensics.compliance` | config/data layer: compliance declarations | 188 |
| `textforensics.conditions` | config/data layer: condition definitions | 557 |
| `textforensics.config` | config/data layer: configuration | 183 |
| `textforensics.constants` | config/data layer: constants | 9 |
| `textforensics.corpus_analyzer` | probe tooling: corpus analysis | 416 |
| `textforensics.features` | feature layer: feature extraction | 419 |
| `textforensics.localize` | feature layer: localisation | 423 |
| `textforensics.mcp_server` | transport layer: MCP server | 86 |
| `textforensics.mcp_tools` | transport layer: MCP tools | 176 |
| `textforensics.models` | model layer: model definitions | 7 |
| `textforensics.probe_corpus` | probe tooling: probe corpus | 452 |
| **total, 13 modules** | | **3826** |

Live-item counts are cosmic-ray enumerations on head `7d2112c`
(`audit-w7-f-boundary-workitems.json` in the W7 proof evidence).

### Module-level code is not decision logic

A mutant is *module-level* when it sits outside any function
(enclosing function is `None`: module constants, top-level
statements, class-level annotations). Module-level code is not
decision logic, so module-level mutants are out of scope for the
proof even inside covered modules.

Re-derived on head `7d2112c` (method: enclosing-function-None, see
`audit-w7-f-proofset.py`):

| scope | module-level live items |
| --- | --- |
| the 15 non-baselined modules | **321** |
| of which `textforensics.ed25519` | 166 (lines 30–35, 63: the `_Q`/`_L`/`_D`/`_I`/`_BY`/`_BX`/`_BASE_POINT` constants) |
| of which `textforensics.dsse` | 0 |
| of which the 13 out-of-scope modules | 155 |
| whole repo (59 modules) | 1829 |

Per-module module-level counts (15 modules): adapter_scanner 16,
api 12, compliance 2, conditions 61, config 9, constants 8,
corpus_analyzer 23, ed25519 166, localize 2, mcp_server 8, models 6,
probe_corpus 8; dsse 0, features 0, mcp_tools 0.

**Discrepancy, flagged not hidden:** the CC-18 scope decision cites
**641** module-level live items. That figure could NOT be
reproduced on head `7d2112c` by either definition tried
(enclosing-function-None: 321 for the 15 modules, 1829 repo-wide;
empty `definition_name`: 303 for the 15 modules, 1630 repo-wide).
The re-derived **321** (method stated above) is the figure this
document stands behind; the 641 figure is recorded here as
unreproduced and must not be quoted as a measured count.

## What "out of scope" means

- No claim is made about mutants in the 13 modules or about
  module-level mutants anywhere: they were enumerated (so the
  boundary is measured, not assumed) but never executed, classified,
  or baselined.
- A future wave may extend the proof to some or all of them; until
  it does, `tests/test_mutation.py` does not assert anything about
  them and `scripts/check_claims.py` must not count them as covered.
- The boundary is re-derived per wave: if a module gains
  safety-critical decision logic, its exclusion must be re-decided
  explicitly, not carried forward silently.
