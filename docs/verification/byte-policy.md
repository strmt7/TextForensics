# Canonical persisted-byte policy for hash-covered artifacts

Status: W0 (ENG-07/13/16; ENG-08 is W6). This document defines the single
well-defined representation whose digests the repository's gates verify.
It does not add `.gitattributes` (that is ENG-08, W6) and it does not
reseal or rehash any existing registry digest.

## The policy

1. **Encoding is UTF-8.** Every hash-covered text artifact is persisted
   as UTF-8 bytes. No BOM, no host-default encoding.
2. **Line endings are LF (`\n`).** No CRLF. A file whose persisted bytes
   contain CRLF is not in canonical form.
3. **Digests are computed over persisted bytes, never in-memory
   strings.** The digest input is exactly the bytes on disk (or in the
   archive), read in binary mode. Re-encoding a decoded string, normalising
   line endings in memory, or hashing a serialised-in-memory copy can
   produce a different digest from the persisted bytes and is forbidden
   for verification.
4. **The digest function is SHA-256, lowercase hex.** This matches the
   existing registry (`run_artifact_sha256`), the validation registry
   (`registry_id`), and the doc-evidence fields in `docs/CLAIMS.yaml`
   (`doc_sha256`).

## How to verify

```sh
# Digest of the persisted bytes (Linux/macOS):
sha256sum <path>

# Same check in Python (binary read — never text mode):
python -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" <path>
```

A mismatch is a real finding, not a formatting nit. Before concluding
tampering, check for checkout conversion first:

```sh
git ls-files --eol <path>   # `i/lf w/crlf` means the worktree converted the bytes
```

If the worktree converted the bytes, the checkout is not in canonical
form: restore the canonical bytes (`git checkout -- <path>` after
confirming no local edits are being discarded, or re-clone) and re-verify.
**Never** refresh a recorded digest to host-specific (CRLF) bytes to make
a mismatch go away — that would silently rehash history as if unchanged
and break every other checkout. The claims gate
(`scripts/check_claims.py`) names CRLF in its mismatch message for
exactly this reason.

## Hash-covered paths

These paths are covered by a recorded digest somewhere in the repo, and
their persisted bytes must stay in canonical form:

| Path | Digest recorded in |
| --- | --- |
| `docs/evidence/runs/*.json` | `docs/evidence/registry.json` (`run_artifact_sha256`) and the citing claim's `run_artifact_sha256` in `docs/CLAIMS.yaml` |
| `docs/evidence/registry.json` | Verified against `src/textforensics/schemas/evidence-registry.schema.json`; its records' digests are the pins above |
| `docs/validation/registry.json` | Its own `registry_id` (SHA-256 of the canonical JSON of `{schema, records}`), verified by the loader in `src/textforensics/validation.py` |
| `docs/evidence/EV-*.json` (standalone evidence files) | Referenced by run artifacts / registry patches; hashed where cited |
| `requirements-pinned.txt` | `sbom/textforensics.cdx.json` properties and the SBOM/checks in `docs/VERIFICATION.md` |
| `sbom/textforensics.cdx.json` | Its own content hash where published (release checksums) |
| Doc-evidence files cited by `docs/CLAIMS.yaml` (`doc` claims) | The claim's `doc_sha256` field, verified by `scripts/check_claims.py` against current persisted bytes and the recorded `doc_as_of_sha` |

## What the claims gate checks (ENG-16)

For every `doc` claim, `scripts/check_claims.py` verifies, byte-exactly
per this policy:

- the cited file exists and its persisted bytes hash (SHA-256 over
  `read_bytes()`) to the claim's `doc_sha256` — any mismatch fails;
- the claim's `doc_as_of_sha` is a full commit SHA that resolves in the
  repo;
- `doc_state` is one of `implemented` / `tested` / `historical` /
  `blocked`:
  - `implemented` / `tested` assert a property of the **current** tree,
    so the cited document must be unchanged since the as-of SHA
    (`git diff --quiet <as-of> HEAD -- <path>`);
  - `historical` is a dated record (bytes still pinned by the digest);
  - `blocked` can never pass the gate;
- when the claim asserts an executable property
  (`executable_property: true`), the named `executable_check` command
  must be present and exit 0. A saved note such as
  `cited_content_present=true` is not execution evidence.

## What this policy does not do

- It does not add `.gitattributes` or change any checkout behaviour
  (ENG-08, W6 owns repository-controlled checkout conversion).
- It does not reseal or rehash any existing registry digest to
  host-specific bytes.
- It does not make a doc assertion true: a digest match proves the
  cited document's bytes are unchanged since verification, nothing
  more. Executable properties need executable checks.
