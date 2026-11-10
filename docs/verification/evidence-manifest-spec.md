# Evidence-manifest specification

Schema: `textforensics.evidence-manifest/v1`
(`src/textforensics/schemas/evidence-manifest.schema.json`).
This document is the normative companion to that schema. Worker B
(`scripts/verify_release.py`) consumes this schema; it does not
redefine it. The manifest is the shared boundary between W0 (this
spec), W7 (gates that feed it) and W10 (the candidate dossier that
presents it).

## Purpose

One file that immutably binds a release candidate to everything that
was checked about it, so a second verifier can reproduce the verdict
without trusting the first verifier's word. The manifest is a
*binding*, not a report: it carries identities and digests, and
status strings by reference. Full results live elsewhere.

## Fields

| Field | Meaning | Rules |
| --- | --- | --- |
| `schema` | Schema id | Const `textforensics.evidence-manifest/v1` |
| `manifest_version` | Format version | Const `"1"`. A format change requires a new schema id (`/v2`); this field never silently changes meaning |
| `candidate_source_sha` | Candidate commit | Full 40-hex Git SHA. Any other tree is a different candidate |
| `source_tree_digest` | Digest of the candidate source tree | `{method, value}`. `method` is `git-tree` (Git tree SHA, 40 hex) or `sha256-manifest` (SHA-256 over a sorted manifest of `(path, SHA-256)` pairs for every tracked file, 64 hex). Digests are computed over persisted bytes (UTF-8, LF) |
| `package_inputs` | Package inputs that produced the candidate | Array of `{name, version, digest: {algorithm: "sha256", value}}`. At least one entry (the project itself). The digest is the SHA-256 of the exact distribution artifact or lockfile entry the build consumed, as recorded by `verify_release.py`; it is not a hash of the package name |
| `schema_versions` | Schemas referenced by the candidate | Map from schema name to schema id, e.g. `{"case-file": "textforensics.case-file/v1"}`. At least one entry |
| `test_suites` | Test suites executed | Array of `{suite, run_id}`. At least one suite: a candidate with zero executed test work is `zero_work`, never a pass |
| `scientific_run_ids` | Scientific runs supporting the candidate | Array of run-id strings. May be empty (a candidate with no scientific claims); the field is always present so absence is explicit, not omitted |
| `artifacts` | Candidate artifacts | Array of `{path, sha256, role}`, paths relative to the candidate root, SHA-256 over persisted bytes. At least one entry. `role` is free-form (e.g. `wheel`, `sdist`, `sbom`, `provenance`, `notes`, `checksums`, `report`) so future asset types are not blocked; it must be non-empty |
| `gate_results` | Gate verdicts by reference | See below |
| `recorded_at_utc` | When the manifest was written | ISO 8601 UTC timestamp. Informational only; not part of any digest preimage |

## Gate results by reference

`gate_results` has exactly three members:

- `verify_release_output`: `{path, sha256}` — a pointer to the
  `scripts/verify_release.py` JSON output file for this candidate,
  bound by its SHA-256 over persisted bytes.
- `gates`: a map from gate id to `{status, detail?}`. `status` is one
  of the frozen vocabulary strings below. `detail` is an optional
  one-line pointer or note (for example which section of the
  referenced output records the gate). It must not duplicate gate
  results.
- `required_gates`: the list of gate ids that must pass for this
  candidate to be promotable. The list is part of the manifest so a
  candidate cannot silently drop a required gate.

**The manifest never embeds the verify-release output.** Counts,
logs, per-test outcomes and per-finding details live only in the
referenced file. The manifest's `gates` map is a verdict binding,
not a copy of the results: it says *which* gates passed, not *why*.

## Gate-status vocabulary (frozen)

Exactly these six strings, everywhere (baseline record, manifest,
`verify_release.py` output, W10 dossier). No other status string is
valid in a manifest:

| Status | Meaning |
| --- | --- |
| `pass` | The gate ran, executed positive work, and its acceptance criterion held |
| `fail` | The gate ran and its acceptance criterion did not hold |
| `skipped` | The gate was deliberately not run for a recorded reason (e.g. no relevant changes, platform not applicable to this run) |
| `unavailable` | The gate could not run because a required tool, service or input was missing |
| `not_applicable` | The gate does not apply to this candidate (e.g. a platform-specific gate on another platform) |
| `zero_work` | The gate ran but executed zero work (zero tests collected, zero mutants, zero files checked, empty comparison) |

**Required gates accept ONLY `pass`.** `verify_release.py` must
enforce that every id in `required_gates` is present in `gates` with
status `pass`; any other status — including `skipped`,
`not_applicable` and `zero_work` — blocks promotion. This is a
verifier rule, not a schema rule: JSON Schema cannot express the
cross-field requirement (required id ⊆ gates keys, with status
`pass`), so the schema constrains the vocabulary and the required
lists, and `verify_release.py` enforces the binding. A manifest that
claims `pass` for a gate whose referenced output shows no executed
work is a corrupt manifest, not a passing candidate.

## Byte policy

Canonical persisted bytes for hash-covered artifacts are UTF-8, LF
newlines; digests are computed over persisted bytes (Worker C owns
the byte policy; this spec conforms to it). The manifest's own
`artifacts[].sha256` and `gate_results.verify_release_output.sha256`
are SHA-256 over the persisted file bytes, exactly as recorded.

## What the manifest does not do

- It does not authorise a release. Promotion is a separate,
  owner-authorized boundary (W10); the manifest is evidence for it,
  not permission.
- It does not replace the evidence registry (`docs/evidence/registry.json`)
  or the claims gate (`scripts/check_claims.py`). Those are unchanged
  by W0; the manifest references run ids and artifact digests, it
  does not re-seal registry entries.
- It does not version public contracts. If a referenced schema
  changes meaning, that schema's own version changes; the manifest
  records the new id.

## Worked minimal example

```json
{
  "schema": "textforensics.evidence-manifest/v1",
  "manifest_version": "1",
  "candidate_source_sha": "3ff365031faf48bc0d14212d81d147ac11c7b232",
  "source_tree_digest": {"method": "git-tree", "value": "0000000000000000000000000000000000000000"},
  "package_inputs": [
    {"name": "textforensics", "version": "0.2.0",
     "digest": {"algorithm": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"}}
  ],
  "schema_versions": {"case-file": "textforensics.case-file/v1"},
  "test_suites": [{"suite": "core", "run_id": "example-run-1"}],
  "scientific_run_ids": [],
  "artifacts": [
    {"path": "dist/textforensics-0.2.0-py3-none-any.whl", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "role": "wheel"}
  ],
  "gate_results": {
    "verify_release_output": {"path": "verify-release.json", "sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
    "gates": {"core-pytest": {"status": "pass"}},
    "required_gates": ["core-pytest"]
  },
  "recorded_at_utc": "2026-11-10T19:17:39Z"
}
```

(The zero digests above are placeholders for shape only; a real
manifest binds real digests. Do not use this example as a candidate.)

## Tests

`tests/test_evidence_manifest.py` validates a minimal valid manifest
and rejects a manifest with an unknown status string and one with a
missing artifact digest. It loads the schema file directly from the
packaged schemas directory and does not depend on schema discovery
(`schema.py`), which is itself under repair (audit CORE-10).
