# Audit anchor migration: directory-hash framing v1 → v2 (W4)

This note records the breaking change made while closing audit findings
C08 and C09 (audit wave W4). It is the migration decision the W3 report
left to the parent/integrator: the algorithm changed, existing anchors
are invalidated, and the invalidation is explicit and fail-closed --
never silent.

## What changed

### C09 — directory hashing is now versioned framing v2

The v1 tree preimage concatenated `relative_path || NUL || raw_content
|| LF` records with no length framing and no per-file hashes. Raw file
content could contain the next record's delimiter/path bytes, so two
different trees shared one digest (a framing defect, not a SHA-256
collision; it never gave a second preimage for an arbitrary pre-existing
honest directory).

The v2 preimage (`textforensics.directory-hash/v2`) is unambiguous:

- a fixed version header, `textforensics.directory-hash/v2\n`, which
  domain-separates v2 digests from every v1 digest;
- one length-prefixed record per file, in sorted order of the portable
  (forward-slash) relative path: an 8-byte big-endian path length, the
  path bytes, an 8-byte big-endian content size, and the 32-byte SHA-256
  digest of the file's content (streamed in 1 MiB chunks);
- symlinks: as in v1, a symlink to a file is followed and hashed as the
  file at that path (the record carries the link path, not the target).

Consequences of the new framing:

- an existing directory with no files hashes the SHA-256 of the version
  header alone (previously the SHA-256 of empty input);
- a missing directory still hashes to the empty-string sentinel `""`;
- a directory holding one empty file still differs from an empty
  directory (the empty file contributes a record: path length, path,
  size 0, SHA-256 of empty input).

### C08 — anchors bind versioned state transitions

`verify_audit_anchor` no longer accepts any hash mismatch when a chain
merely extends the anchor chain by list prefix. `chain_valid` now
requires a *bound* transition: a strict chain extension whose final
entry is the hash of the current calibration root, an unchanged
benchmark root, and unchanged declared detector versions. A copied
chain, an arbitrary appended digest, or a calibration-only chain
presented against benchmark tampering all raise `RollbackError`.

The anchor schema version is now **2** (`SCHEMA_VERSION` in
`src/textforensics/ledger.py`). Detector versions bind only what the
anchor declares: an anchor exported with no declared versions makes no
version claim. Anchors exported by `export_audit_anchor` without an
explicit override auto-detect versions, so real anchors do bind them.

## Effect on existing v1 anchors: invalidated, explicitly

Every anchor exported under schema version 1 stores v1-framed
directory digests. Those digests can never match a v2 recomputation,
so a v1 anchor can never verify -- by design. Verification fails
closed with an explicit error instead of a misleading rollback:

> `Audit anchor uses schema version 1, but the current schema version
> is 2: the anchor was exported with the superseded v1 directory-hash
> framing and its stored digests can never match current state.
> Re-export the anchor ...`

The CLI reports this as a rollback-detection failure (`valid: false`),
not as a successful verification.

## How to migrate

1. Establish a trusted state first. Do **not** re-export blindly: a
   re-export blesses whatever is on disk now. If the artifacts changed
   since the v1 export, determine whether the change is legitimate
   (a real recalibration / benchmark run) or tampering, using the
   same evidence you would have used before (run manifests, case
   files, version control).
2. Re-export the anchor from the trusted state:
   `textforensics audit export <anchor.json> --base-dir <root>`
   (with `--chain <chain.json>` when a calibration chain is in use).
   The new anchor carries `schema_version: 2` and v2 digests.
3. Verify it: `textforensics audit verify <anchor.json> --base-dir
   <root>` must report `no_changes`.
4. Discard or archive the v1 anchor file (label it superseded); do
   not keep it where tooling might read it as current. There is no
   automatic upgrade path: converting a v1 anchor's stored digests
   would require re-hashing the original artifacts, which is exactly
   what a fresh export does -- and an automatic conversion could not
   distinguish a legitimate re-hash from a tampered one.

## What did NOT change

- The `AuditLog` (JSONL hash chain) and `DecisionLedger` formats are
  unchanged; no log or decision records need migration.
- The audit-anchor JSON field names are unchanged; only
  `schema_version` (1 → 2) and the meaning of the two `*_sha256`
  fields (v1 framing → v2 framing) changed.
- No case-file, trust-map, or bundle schema changed in this wave.
