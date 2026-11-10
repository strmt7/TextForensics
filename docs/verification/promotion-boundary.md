# Candidate-promotion boundary

> W0 — publication behind an explicit candidate-promotion boundary
> (ENG-04, ENG-05, ENG-06, ENG-14). Status: implemented on branch
> `audit-w0-d`; no release, tag, or image has been published from this work.

## Rule

Nothing is published — no GitHub Release, no package upload, no container
tag — unless the **candidate source SHA** has every **required acceptance
result** recorded as `pass` for that exact SHA. A manual confirmation
(`RELEASE` / `PROMOTE`) is authorization to *attempt* promotion, never
evidence that the criteria passed. Absence of evidence is not evidence of
passing.

Gate-status vocabulary (shared W0 contract): `pass`, `fail`, `skipped`,
`unavailable`, `not_applicable`, `zero_work`. Required gates accept ONLY
`pass` with positive executed work at the exact candidate SHA.

## The two promotion paths

### 1. GitHub Release — `.github/workflows/release.yml`

1. `workflow_dispatch` with confirmation exactly `RELEASE`.
2. **`acceptance-gate` job (runs first, blocks everything else):**
   `scripts/promotion_gate.py --sha <candidate SHA> --repo <owner/name>`
   queries the GitHub check-runs for the exact SHA (read-only `gh api`
   GET) and fails unless every required check below is `success` at that
   SHA. Missing, skipped, failed, stale-SHA, or incomplete results all
   block. Exit codes: 0 pass / 1 blocked / 2 gate unevaluated.
3. The `release` job (`needs: [acceptance-gate]`) additionally runs the
   full canonical pytest collection (`python -m pytest tests`), the claims
   gate, the pip-audit gate, the locked-SBOM check, and the canonical
   verification command `scripts/verify_release.py` (exit 0 pass / 1 gate
   failed / 2 incomplete — 1 and 2 BOTH block promotion; a missing script
   blocks too, fail closed). It also runs an installed-wheel web smoke
   test (`create_web_app()` from the installed wheel).
4. `scripts/publish_release.py upload` enforces the upload boundary (below)
   and only then invokes `gh release create`.

### 2. Container image — `.github/workflows/container.yml`

- **Candidate build (every main push / schedule / plain dispatch): build
  ONLY.** No push, no mutable tags (`latest`, version, short-SHA), and the
  build is never called a governed release. The immutable candidate
  identity is the image **digest**; the SBOM scans the built image **by
  digest**, never `path: .` (the source tree). Post-build running-image
  acceptance runs on the candidate: health endpoint (`/healthz`),
  non-root user, read-only root filesystem, installed web resources.
- **Promotion (pushing `latest` / version / short-SHA tags): ONLY via
  explicit `workflow_dispatch` with confirmation exactly `PROMOTE` and a
  candidate SHA, AFTER the `promotion-gate` job passes for that SHA (same
  required set as releases, plus the candidate-build check for that SHA),
  AND after the rebuilt image passes running-image acceptance again.**
  Promotion rebuilds from the exact candidate SHA; byte-identical rebuild
  is ENG-03/W6-owned and is NOT claimed here.
- **Automated main snapshots are NOT public.** Safe default implemented:
  no push on main push. Whether automated main snapshots are intentionally
  public is a HUMAN-ONLY policy decision (open — see below). Do not call
  main-push builds governed releases.

## Required acceptance set (exact-SHA check-runs)

Check-run display names are `<workflow> / <job>`; matrix jobs require
EVERY leg to pass. The authoritative list lives in
`scripts/promotion_gate.py` (`--list-required` prints it).

| Key | Check-run (prefix) | What it proves |
| --- | --- | --- |
| `claims` | CI / Claims-to-evidence gate (U7) | claims bound to evidence |
| `full-pytest` | CI / Core Python (matrix 3.11–3.15) | full canonical pytest collection |
| `pinned` | CI / Pinned requirements install | pinned install works |
| `locked-sbom` | CI / Checked-in SBOM is not stale | locked SBOM is current |
| `installed-web` | CI / Build and wheel-install | installed wheel / packaged schemas |
| `pip-audit` | Supply-chain security / pip-audit gate | no new vulnerabilities |
| `supply-chain-sbom` | Supply-chain security / Software Bill of Materials | SBOM generation |
| `reproducibility` | Reproducibility / Build Reproducibility | reproducible builds |
| `integrity-sigstore` | Repository Integrity / Sigstore Verification | integrity verification |
| `integrity-provenance` | Repository Integrity / Build Provenance | build provenance |
| `deep-verification` | Enterprise Deep Verification / Full Test Suite (matrix) | full test suite, deep verification |

The integrity and deep-verification workflows run on schedule /
`workflow_dispatch`, not on push: dispatch them for the candidate SHA
before promoting. Until their check-runs exist for that SHA the gate
reports `unavailable` and blocks promotion. That is intentional.

Known limits of this gate (not hidden): the gate verifies that the
*checks ran and passed* for the exact SHA; it cannot repair defects in
the checks themselves. Known check-content defects owned by later waves:
ENG-01 (installed web resources — the `Build and wheel-install` job does
not construct the web app; W6), ENG-03 (reproducibility comparison is
non-gating in its own workflow; W6), ENG-07 (integrity placeholder
verifications; W0/W7). The release job's own installed-web smoke test
covers ENG-01 at the release path directly.

## Upload boundary — `scripts/publish_release.py` (ENG-05/ENG-06)

`upload` fails closed, in this order, before any remote-writing command
(`gh release create`) is launched:

1. **Confirmation:** `RELEASE_CONFIRMATION` must be exactly `RELEASE`.
   Unset, empty, and wrong values ALL fail (the old code accepted
   unset/empty).
2. **Typed mandatory asset manifest** (`build_asset_manifest`): exactly one
   wheel named `textforensics-<version>-py3-none-any.whl`; sdist
   `textforensics-<version>.tar.gz`; source tarball
   `textforensics-<version>-source.tar.gz`; release notes; `SHA256SUMS`;
   **both SBOM payloads** `textforensics-sbom.cdx.json` and
   `textforensics-sbom.spdx.json` **plus** each payload's `.sig`/`.bundle`;
   notes `.sig`/`.bundle`/`.sha256`; at least one provenance bundle
   (`*.intoto.jsonl`). Absence of any mandatory item fails. The final
   attached asset list includes the SBOM JSON payloads (the old glob
   selection never selected `dist/*.json`).
3. **Checksums:** `SHA256SUMS` must contain an entry for every attached
   artifact (except itself) and every digest must match the file content;
   the notes digest is additionally verified against
   `release-notes.md.sha256`. A tampered payload fails.
4. **Tag binding:** the tag must resolve to exactly the artifact's source
   commit (`--source-sha`, default `git rev-parse HEAD`). Tag existence
   alone is not enough.

**Ordering (ENG-06):** define the complete payload set → generate
SBOMs/provenance → sign everything → generate `SHA256SUMS` LAST, covering
every attached artifact. The old order created checksums before SBOMs/
provenance, so "checksums for every attached artifact" was untrue.

**Signing (ENG-06):** `sign-notes` in publication mode (the default)
REQUIRES cosign and FAILS when cosign is absent. A SHA-256 checksum is not
an authenticity signature and is never called a "checksum signature".
`--mode unsigned-preview` writes a checksum only, marks the notes
`UNSIGNED PREVIEW`, and the result is INELIGIBLE for upload (the uploader
refuses preview-marked notes). Signing/TSA trust identity is a HUMAN-ONLY
decision (open — see below); no signer identity or credential is invented
here. This workflow uses the repository's existing keyless Sigstore
identity.

## What is NOT decided here (human-only decisions)

1. **Signing/TSA trust identity and credential policy** (ENG-06 boundary):
   who the trusted signer is, which identity the signatures must assert,
   and how signing credentials are held. Implemented as a fail-closed
   boundary (no signer identity configured → publication mode fails);
   the decision itself is the owner's.
2. **Public-snapshot / container policy** (ENG-14): whether automated main
   snapshots are intentionally public. Safe default implemented (no push
   on main push); the owner decides.
3. **Branch-protection governance** (repo settings, required checks
   enforcement at the GitHub level). The workflows enforce the boundary
   in-pipeline; branch protection is a separate owner decision.
4. **History-rewrite privacy cleanup** (removing historical path
   candidates from public Git history). No rewrite is authorized by this
   work.
5. **Final release authorization**: the owner, not any agent, decides
   whether and when to authorize a release.

## Known-red / open items from this wave

- **Installed-web smoke in `release.yml` is KNOWN-RED until W6 fixes
  ENG-01** (web templates/static are not packaged in the wheel, so
  `create_web_app()` from an installed wheel raises). The step is kept
  required because a release whose advertised web console cannot start
  must not publish; the failure correctly blocks publication.
- **Container candidate acceptance web-resources probe is KNOWN-RED for
  the same ENG-01 reason** (same `create_web_app()` assertion inside the
  image). Health / non-root / read-only acceptance is expected green (the
  container serves the API today).
- **`scripts/verify_release.py` does not exist yet on this branch**
  (Worker B, W0, owns it). The release job fails closed if it is absent;
  once it lands, the release path and the local command agree by
  construction.
- **No release, tag, or image was published by this work.** All
  publication-path tests use mocked subprocess/network and disposable
  directories and assert zero remote-writing invocations.

## Tests

- `tests/test_promotion_gate.py` — missing / skipped / failed / stale-SHA /
  incomplete / matrix-failure / unrelated-name cases; read-only `gh api`
  fetch shape; CLI exit codes 0/1/2.
- `tests/test_publish_release.py` — confirmation unset/empty/wrong; the
  ENG-05 audit probe (wrong-name wheel, no confirmation); every mandatory
  asset removed in turn; version/SHA tampering; mismatching tag; SBOM
  payload inclusion in the final asset list; `sign-notes` with cosign
  absent; unsigned-preview ineligibility; and the W0 no-publication test
  (`test_no_publication_mode_invokes_zero_remote_writes`), which invokes
  every publishing entry point in no-publication mode with mocked
  subprocess/network and asserts ZERO remote-writing invocations
  (`gh release create`, `twine upload`, `docker push`, tag creation,
  registry writes).
