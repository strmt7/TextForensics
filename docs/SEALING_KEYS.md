# Sealing keys

How Ed25519 sealing keys work in TextForensics, and what to do when
one is lost or compromised. This document describes v1.0 key handling.
Key management beyond this (hardware keys, central revocation) is
deliberately deferred — see "Compromise and revocation" below.

## What a sealing key is

A sealing key is an Ed25519 keypair stored as a
`textforensics.sealing-key/v1` JSON file:

- `seed_b64` — the 32-byte private seed (base64). **Never share this.**
- `public_key_b64` — the 32-byte public key (base64).
- `keyid` — the SHA-256 hex fingerprint of the public key. This is
  what a case file's seal and a sealed bundle's manifest record, so a
  verifier can tell *which* key a signature claims to be from.
- `identity` / `role` — who holds the key and for what purpose
  (for example `"auditor"` / `"sealer"`).
- `algorithm` — always `"ed25519"`.
- `created_at_utc` — when the key was generated.

The key signs two things, both with the same key when
`case export --seal --signing-key` is used:

1. The case file itself (T2 case signature, a DSSE envelope over the
   canonical case bytes with the seal signature removed).
2. The sealed bundle's manifest (T2 manifest signature, a DSSE
   envelope over the canonical manifest bytes with the signature field
   itself null).

The private seed never leaves the key file and never appears in a
case file or a bundle. A bundle carries only the signer's identity,
role and key fingerprint.

## Generating a key

```bash
textforensics case keygen --output sealing-key.json \
    --identity auditor --role sealer \
    --public-out sealing-key.pub.json
```

- The key file is written atomically with mode `0600` and the command
  **refuses to overwrite** an existing file: a sealing key must never
  be silently replaced. Pick a new path if the file already exists.
- `--identity` defaults to the current username; `--role` defaults
  to `"sealer"`.
- `--public-out` writes the public half (`algorithm`,
  `public_key_b64`, `keyid`, `identity`, `role`). That file is safe to
  publish and to hand to verifiers.

Loading a key file fails closed when the file is readable by anyone
other than its owner (POSIX mode `& 0o077 != 0`), when the seed does
not reproduce the recorded public key, or when the keyid does not
match the public-key fingerprint.

## Storing a key

- Keep the key file on the machine that seals cases, with mode `0600`.
  Do not copy it to shared machines, do not commit it to a repository,
  do not email it, and do not put it in a case file or bundle.
- Make an **offline backup at generation time** if the key will sign
  consequential cases (for example an encrypted USB copy kept apart
  from the sealing machine). A lost seed cannot be recovered: it is
  32 random bytes and there is no recovery channel.
- A lost key does not invalidate cases already sealed with it. Their
  T1 hash seal still verifies (integrity since sealing), and their T2
  signature still verifies against the published public half. What is
  lost is the ability to make *new* T2 signatures with that key:
  generate a new key and re-seal any case that needs a fresh
  signature.

## Publishing the public half

Verifiers need the public key to check a T2 signature:

```bash
textforensics case verify case.sealed.zip --public-key sealing-key.pub.json
```

Without `--public-key`, verification reports the signature as
`unavailable` and exits 2 (incomplete) — never as a pass. Publish
the public half through the same channel the case files travel
through, so a verifier can match the `keyid` in the seal against the
key they trust. The public half carries no secret and may be posted
publicly.

## Rotating a key

1. Generate a new key (`case keygen`) and publish its public half.
2. Re-export and re-seal any case that must carry a signature under
   the new key. Cases sealed under the old key keep verifying under
   the old public half — the keyid recorded in each seal says which
   key applies, so old and new keys coexist without ambiguity.
3. Stop using the old key for new seals. There is no expiry field on
   a sealing key in v1.0; rotation is a matter of policy, not of the
   format. Rotate on personnel change, on any suspicion of exposure,
   and at least when the key's operational lifetime (set by your own
   policy) ends.

## Compromise and revocation

There is **no central revocation list** in v1.0. Key management
beyond local Ed25519 files (hardware keys, managed PKI, revocation
infrastructure) was deferred by design decision — see the Phase 3
research report (§13, decision 5).

If a key is compromised, or suspected to be:

1. Stop using it for new seals immediately.
2. Publish a notice through the same channel the public key was
   published through, naming the `keyid` and the date from which
   signatures under it must not be trusted.
3. Rotate to a new key (above) and re-seal any case that must carry a
   trustworthy T2 signature.
4. Treat T2 signatures under the compromised keyid made after the
   compromise date as untrusted. Cases sealed before that date keep
   their T1 integrity (the hash seal still proves the bytes have not
   changed since sealing), but their origin claim must not be relied
   on once the compromise is known.

Verifiers should check the keyid in a seal against the publisher's
current public-key notice before trusting an origin claim. The
verifier itself cannot know a key was compromised — that information
travels out of band, like the digest in `--expect-digest`.

## Determinism declarations (v4)

Case files sealed by default are `textforensics.case-file/v4`: v3
plus a per-observation determinism declaration. Every
`detector_observations` item carries `determinism`
(`deterministic` / `non_deterministic` / `unknown`) and
`determinism_reason`; v4 requires `determinism` on `kind:
"observed"` items, v3 keeps it optional (absent means unknown).

The declaration comes from, in order:

1. an explicit seal-time override — `case export --determinism
   <detector_id>:<value>` (repeatable; invalid values error out),
   or `seal_case_file(..., determinism={...},
   determinism_reasons={...})`;
2. the value the analysis recorded in the bundle's
   `detector_results` — the detector's own declaration (the builtin
   heuristic detector declares `deterministic`; the Ollama adapter
   declares `non_deterministic`, because sampling means repeated runs
   may return different scores);
3. `unknown`, when neither exists. A detector that declares nothing
   is `unknown`, and `unknown` fails closed on a replay mismatch.

An explicit override wins over the bundle-recorded value and is
written into the sealed bundle copy as well as the observations, so
verification rebuilds exactly what was sealed; the declaration itself
is protected by the case hash (and T2 signature, when attached). An
override for a detector ID that is not in the bundle, or an invalid
value, is rejected at seal time — a declaration is never silently
dropped.

Replay: when a detector's score, verdict, version or calibration
differs at replay AND its sealed observation declares it
`non_deterministic`, that detector's check status is
`not_reproducible`, no mismatch error is recorded, and a warning
`not_reproducible:<detector_id>[:<reason>]` carries the sealed
reason. The replay outcome is then `inconclusive` — valid but
inconclusive, made explicit by `replay_outcome` and the warning,
never silently passed. A `deterministic` or `unknown` declaration
fails closed on a mismatch. A sealed-bundle verification of an
inconclusive replay exits 2 (valid but incomplete); `case verify` on
a bare case file does the same when its replay is inconclusive. The
CLI does not re-run detectors, so a CLI replay can only reproduce or
fail; `replay_outcome` is still reported in its JSON output and scope
statement.

## Timestamps (T3)

A timestamp token is requested with `case export --seal
--timestamp-url <TSA URL>` and verified with `case verify
--timestamp-token <token.der>` (bare case files) or automatically from
inside a sealed bundle. Tokens from free public TSAs are labelled
**"RFC 3161 timestamp (non-qualified)"** — never "legally
timestamped". A qualified timestamp (eIDAS qualified TSA) is out of
scope for v1.0. If the TSA cannot be reached, the seal fails with an
error instead of silently producing a bundle the user thinks is
timestamped.

## What the seal does not prove

- A hash seal (T1) proves the case bytes have not changed since
  sealing. It does not prove the analysis was run, and it does not
  authenticate who sealed it.
- A signature (T2) proves the sealer held the private key. It does
  not prove the analysis is correct, and it does not prove authorship
  of the submitted text.
- A timestamp (T3) proves the case bytes existed at the token's
  `genTime` according to the TSA's clock. It does not prove when the
  text was written or by whom.
- No seal, signature or timestamp turns a detector score into a
  probability, or a detector verdict into proof of authorship. The
  case file's limitations section says so in plain language, and the
  verification output repeats it in the scope statement.
