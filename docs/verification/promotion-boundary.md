# Candidate-promotion boundary

> W0 — publication behind an explicit candidate-promotion boundary
> (ENG-04, ENG-05, ENG-06, ENG-14). Status: implemented on branch
> `audit-w0-d`; no release, tag, or image has been published from this work.
>
> W7 (branch `audit-w7-a`) hardens the boundary further: signatures are
> verified with cosign (not just present), SBOM payloads are validated
> as SBOMs, the upload is verified by reading the published release
> back, the release tag is created inside the boundary, and the
> canonical verification command's required set is executable. No
> release, tag, or image has been published from this work either.

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
  AFTER a signed GitHub Release is verified to exist for that SHA
  (`scripts/verify_signed_release.py`, ENG-14/W7: the release tag
  `v<version>` must resolve to exactly the candidate SHA, the release
  must not be a draft, and it must carry at least one `.sig`/`.bundle`
  signature asset — a candidate that was never published as a signed
  release is refused however green its checks are; the promote job
  re-verifies the signed release itself before any push step), AND after
  the rebuilt image passes running-image acceptance again.**
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

Container promotion additionally requires a **signed release** for the
candidate SHA (not a check-run, so not in the table above):
`scripts/verify_signed_release.py` proves the release tag `v<version>`
resolves to exactly the candidate SHA, the release exists and is not a
draft, and it carries a `.sig`/`.bundle` signature asset. The check
runs in the `promotion-gate` job (a failure blocks promotion via
`needs`) and again in the `promote` job before any push step. Exit
codes mirror the gate: 0 allowed, 1 refused, 2 unevaluated.

The integrity and deep-verification workflows run on schedule /
`workflow_dispatch`, not on push: dispatch them for the candidate SHA
before promoting. Until their check-runs exist for that SHA the gate
reports `unavailable` and blocks promotion. That is intentional.

Known limits of this gate (not hidden): the gate verifies that the
*checks ran and passed* for the exact SHA; it cannot repair defects in
the checks themselves. Known check-content defects owned by later waves:
ENG-07 (integrity placeholder verifications; W0/W7). ENG-01 (installed
web resources) and ENG-03 (reproducibility comparison) were closed in
W6: the `Build and wheel-install` job now covers the installed web app,
and the reproducibility comparison gates. The release job's own
installed-web smoke test covers ENG-01 at the release path directly.

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
   notes `.sig`/`.bundle`/`.sha256`; the wheel, sdist and source tarball
   each carry their own `.sig`/`.bundle` (the release workflow signs
   every file in `dist/`); at least one provenance bundle
   (`*.intoto.jsonl`). Absence of any mandatory item fails. The final
   attached asset list includes the SBOM JSON payloads (the old glob
   selection never selected `dist/*.json`).
3. **Checksums:** `SHA256SUMS` must contain an entry for every attached
   artifact (except itself) and every digest must match the file content;
   the notes digest is additionally verified against
   `release-notes.md.sha256`. A tampered payload fails.
4. **SBOM structure (W7):** each SBOM payload must parse as JSON and
   carry its format marker (`bomFormat: CycloneDX` / `spdxVersion:
   SPDX-*`). Checksums prove integrity, not that a payload is an SBOM.
5. **Signatures (W7):** every detached signature is verified with
   `cosign verify-blob --bundle … --signature … --certificate-identity
   <expected> --certificate-oidc-issuer <expected>` against the expected
   signer identity/issuer (`--expected-identity` /
   `--expected-issuer`, required). Existence of `.sig`/`.bundle` files
   is NOT verification: a forged or garbage signature, a malformed
   bundle, a missing cosign binary, or a missing identity all refuse
   the upload. Cosign itself checks the bundle's payload digest, the
   certificate chain, and Rekor inclusion. The workflow passes its own
   keyless identity
   (`https://github.com/<owner>/<repo>/.github/workflows/release.yml@<ref>`)
   and the GitHub Actions OIDC issuer.
6. **Tag binding:** the tag must resolve to exactly the artifact's source
   commit (`--source-sha`, default `git rev-parse HEAD`). Tag existence
   alone is not enough.
7. **Tag creation (W7):** a new version has no tag yet, and step 6
   requires one — so the tag is created inside the boundary by the
   `create-tag` subcommand (release-workflow step, after every gate in
   the job has passed), at exactly the candidate SHA, pushed, and then
   verified on the remote with `git ls-remote`. A tag that already
   resolves to a different commit is never moved. `--dry-run` plans the
   tag creation without any remote write (W10 rehearsal). There is no
   other place a release tag is created.
8. **Read-back (W7):** after `gh release create` succeeds, the upload
   is verified by reading the published release back: `gh release view`
   must list every attached asset (with matching sizes), and `gh release
   download` must return bytes whose SHA-256 matches the local file for
   every asset. A `gh release create` exit code of 0 alone is never
   proof the artifacts arrived intact; a read-back failure is reported
   as a failed upload. A failing `gh release create` is a clean
   refusal (return code 1, no traceback). The standalone `verify-upload`
   subcommand re-runs checks 2–6 plus read-back as a separate,
   read-only process; the release workflow runs it as its own step
   after upload.

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
identity, and the upload/verify-upload steps verify against exactly
that identity (see step 5).

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

## ENG-04 hardening (W7)

- **Canonical verification can now pass.** `scripts/verify_release.py`
  used to mark six CI-only gates (secrets-scan, workflow-lint, codeql,
  container, sigstore-verification, repo-provenance-sbom) as required
  AND statically `unavailable`, so it could never exit 0 and the
  release job's verification step could never pass. Those gates are now
  required=False locally (they have no local equivalent) and remain
  required at the publishing boundary: the exact-SHA promotion gate
  (`scripts/promotion_gate.py`, acceptance-gate job) requires their CI
  check-runs for the candidate SHA. Every required gate in
  `verify_release.py` is now an executable (subprocess/special) gate.
- **Check-run pagination.** `scripts/promotion_gate.py` used to read
  only the first page (per_page=100) of check-runs; required results on
  later pages were missed. It now reads every page.
- **Zero-work provenance step.** The release workflow's "Collect
  provenance bundles" step used to pass with an empty `provenance/`
  directory when the attestation action produced no bundle-path. It
  now fails unless at least one bundle was collected.
- **No soft-fails in `release.yml`.** No step uses `continue-on-error`
  or `|| true`; all six action pins were re-validated against their
  upstream repositories (W7).

## Known-red / open items from this wave

> W7 update: the two ENG-01 items below were CLOSED in W6 (web
> templates/static are packaged; the container candidate build is green
> on main 7d2112c, CI run 43811471270). They are kept here as the W0
> record of what was red at the time.

- **Installed-web smoke in `release.yml` is KNOWN-RED until W6 fixes
  ENG-01** (web templates/static are not packaged in the wheel, so
  `create_web_app()` from an installed wheel raises). The step is kept
  required because a release whose advertised web console cannot start
  must not publish; the failure correctly blocks publication.
- **Container candidate acceptance web-resources probe is KNOWN-RED for
  the ENG-01 reason** (same `create_web_app()` assertion inside the
  image). Health / non-root / read-only acceptance is expected green (the
  container serves the API today). (The release workflow's own
  installed-web smoke is NOT known-red: ENG-01 was fixed in W6, main
  7d2112c.)
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
  registry writes). W7 adds: signature verification (cosign absent /
  identity missing / cosign rejection / wheel signature missing all
  refuse before any remote write); SBOM payload structure (invalid JSON
  / wrong format marker); planted `gh release create` failure (clean
  return code 1, no traceback); read-back digest mismatch and missing
  published asset (both fail the upload after create); the standalone
  `verify-upload` subcommand (accepts a complete published release,
  rejects a tampered one, zero remote writes); and `create-tag`
  (creates + pushes a missing tag at exactly the candidate SHA, refuses
  a tag pointing elsewhere, `--dry-run` writes nothing).
- `tests/test_promotion_gate.py` — W7 adds pagination: check-runs on a
  second page are read and evaluated.
- `tests/test_verify_release.py` — W7 adds: no required gate is
  statically unavailable, and the six CI-only gates remain visible,
  non-required, with `promotion_gate` named as their enforcement point.
