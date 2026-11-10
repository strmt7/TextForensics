# Security policy

TextForensics processes text that may be private, unpublished, legally sensitive, or commercially confidential. Security issues include conventional software vulnerabilities **and** failures that unintentionally expose submitted content, credentials, provenance records, or detector-provider data.

## Supported versions

Until a stable 1.x release exists, security fixes are provided on a best-effort basis for the current `main` branch. No release has been tagged yet (the only tag in the repository is `backup/pre-rewrite-85031b1`, a history-rewrite backup, not a release), so there is no tagged minor release to receive fixes.

| Version | Security fixes |
| --- | --- |
| current `main` | ✅ |
| older 0.x minors | n/a — no release has been tagged |
| unreleased branches | development only |

## Reporting a vulnerability

**Do not open a public GitHub issue for a suspected vulnerability.**

Use GitHub's private security-advisory reporting for this repository when available:

**Repository → Security → Advisories → Report a vulnerability**

Include:
- affected version/commit;
- deployment mode (CLI, browser UI, API, MCP, container, plugin);
- reproduction steps;
- security impact;
- whether raw text, credentials, or external-provider data may have been exposed;
- suggested mitigation if known.

Do not include third-party secrets or unrelated private documents in a report. Use minimal synthetic reproductions wherever possible.

## Dependency audit gate

`pip-audit` runs as a failing CI gate, not a report-only scan. The
gate script is `scripts/check_pip_audit.py` and the accepted
findings are listed per finding in `pip-audit-baseline.toml`
(package, vulnerability id, affected version, reason, review date);
it is owned by `.github/workflows/supply-chain.yml` and runs on
push to `main`, on pull requests touching dependency files, and
weekly. Any finding not matched by a baseline entry fails the run,
and a baseline entry past its review date fails while the finding
is still present. There are no blanket ignores.

The only accepted findings are in pip 24.0, the dev virtualenv's
own installer — not a shipped dependency and not pinned by the
project. A rebuilt venv with pip >= 26.2 clears all of them. The
pinned-requirements audit reports 0 findings.

## Security boundaries

### Core
The dependency-free core is local-first and does not intentionally send submitted text over the network.

### Optional remote detector adapters
A future/current remote adapter is a separate trust boundary. It must:
- require explicit user configuration;
- disclose that document text leaves the machine;
- use authorized provider interfaces;
- avoid writing API credentials to reports;
- sanitize provider error messages that may echo submitted content;
- preserve provider/version metadata when exposed.

### Third-party detector plugins
Python detector plugins execute with the privileges of the TextForensics process. Installing a plugin is equivalent to installing trusted code. TextForensics validates plugin result contracts, but it cannot sandbox arbitrary Python packages in the current release.

### Network service
TextForensics binds to loopback by default. A non-loopback bind requires explicit opt-in. **That opt-in is not authentication.** Shared/public deployments require an external authentication/TLS/rate-limiting layer appropriate to the environment.

### Case files and provenance
Hashes detect modification relative to the hashed artifact. A local hash chain does not establish an independent trusted timestamp or prove authorship. Sealed case files have three seal tiers:

- **T1 — hash.** Always present: a SHA-256 hash of the canonical case bytes detects any modification since sealing. It proves integrity since sealing only — never that the analysis was run, and it does not authenticate who sealed the case.
- **T2 — Ed25519/DSSE signature.** Opt-in (`case export --seal --signing-key <key>`): a detached DSSE signature over the canonical case bytes proves the sealer held the private key. Sealing keys are Ed25519 keypairs in `textforensics.sealing-key/v1` JSON files, made by `case keygen`; the private seed lives only in that key file (written mode `0600`, never overwritten, never committed, never emailed, never placed in a case file or bundle), and only the public half is handed to verifiers. See [Sealing keys](docs/SEALING_KEYS.md).
- **T3 — RFC 3161 timestamp.** Opt-in (`--timestamp-url <TSA URL>`): a timestamp token proves the case bytes existed at the token's `genTime` according to the TSA's clock. Tokens from free public TSAs are honestly labelled "RFC 3161 timestamp (non-qualified)" — they are **not** trusted timestamps. Only a qualified timestamp from a qualified trust service provider (QTSP, on the EU Trusted List) carries an eIDAS presumption of time and integrity; a qualified timestamp is out of scope for v1.0.

No seal tier turns a detector score into a probability or a detector verdict into proof of authorship.

## Privacy defaults

- no application telemetry;
- no raw submitted text in portable case files by default;
- no raw submitted text in application logs by default;
- Uvicorn access logs disabled by default;
- detector/plugin exception messages are redacted before inclusion in forensic reports;
- portable artifacts contain hashes and derived evidence unless the user explicitly chooses otherwise.

Infrastructure outside the application—reverse proxies, container platforms, shell history, process supervisors, or provider APIs—may have separate logging/retention behavior.

## Deployment hardening

For a shared environment:
- run as an unprivileged user;
- use a read-only root filesystem where possible;
- drop unnecessary Linux capabilities;
- terminate TLS at a trusted ingress/proxy;
- authenticate clients outside or in front of the current API;
- set request-size and rate limits upstream as well as in TextForensics;
- mount only required writable artifact directories;
- keep detector/model dependencies patched;
- review remote-provider data-retention terms.

The supplied OCI image already uses a non-root numeric UID, supports a read-only filesystem, and exposes health checks.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/OPERATIONS.md](docs/OPERATIONS.md).

## GitHub Actions pinning policy

GitHub Actions run with the repository's CI permissions, so a compromised
or silently changed action can alter release artifacts. The policy is:
**pin every action to a full commit SHA with a `# vX.Y.Z` comment naming
the release it came from; never use a branch ref (`@main`) or a bare
major tag (`@v0`, `@v4`) in release, container, or supply-chain
workflows.** A SHA is immutable; a tag or branch ref can be moved by the
upstream maintainer (or an attacker who compromises the upstream repo)
without any change on our side. Pinning freezes the exact code that runs
until a deliberate, reviewed bump.

### Cosign installer — decision (2026-11-08)

**Decision: pin, and upgrade the pin.** The release workflow
(`.github/workflows/release.yml`) installs cosign with
`sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532 # v4.1.3`.
Tracking `@main` was rejected: the installer runs in the release job
with `contents: write` / `id-token: write` and produces the signatures
on every release artifact, so a moving target there is the worst place
for one.

Verification (2026-11-08, via the GitHub API tags endpoint —
`gh api repos/sigstore/cosign-installer/git/ref/tags/<tag>` — cross-checked
with `gh api repos/sigstore/cosign-installer/commits/<tag>`):

- The previous pin was **correct, not mislabelled**: tag `v3.10.1`
  resolves to commit `7e8b541eb2e61bf99390e1afd4be13a184e9ebc5`, exactly
  the SHA that was pinned. The problem with it was staleness, not
  integrity.
- The new pin was verified the same way: tag `v4.1.3` resolves to
  commit `756fe2d284c7292c4e9b62c8a28f1e5629c59532` on both API paths.

Reasons for upgrading v3.10.1 → v4.1.3 rather than ratifying v3.10.1:

- The v3 installer branch is superseded: v4.0.0 shipped the same day
  as v3.10.1 (2025-10-16) and there has been no v3 installer release
  since, so staying would pin the release pipeline to cosign v2.6.1
  indefinitely.
- Upstream recommends updating as soon as possible (v4.1.0 release
  notes: bug fixes for Cosign; v4.0.0 notes: v4 is required to install
  Cosign v3+).
- The release workflow already uses the Cosign v3 invocation form
  everywhere (`cosign sign-blob --yes <file> --bundle <file>.bundle
  --output-signature <file>.sig`; `--bundle` is required in Cosign
  v3+). Installer v4.1.3 installs Cosign v3.1.4 by default (v3.10.1
  installed v2.6.1), so the upgrade aligns the installed tool with
  the commands the workflow already issues. No other workflow change
  was needed.
- Installer v4 adds curl retries for transient download failures and
  verifies the downloaded Cosign binary against a keyless Sigstore
  bundle instead of only a detached signature.
- Risk is bounded: no release has ever been published from this
  workflow (no release tag exists), so there are no existing
  signatures to stay compatible with, and the in-repo signature
  verification steps are placeholders.

### Review cadence

- **Trigger:** Dependabot's `github-actions` ecosystem in
  `.github/dependabot.yml` (weekly, verified 2026-11-08) proposes
  action updates. That is the normal trigger; no separate calendar
  reminder is needed while Dependabot is enabled.
- **What "review" means:** read the upstream release notes for
  breaking changes (a major bump is reviewed separately and never
  taken as part of a routine pin update); verify the new SHA against
  the tag with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` and
  cross-check it with `gh api repos/<owner>/<repo>/commits/<tag>`;
  update the SHA **and** the `# vX.Y.Z` comment in the same commit;
  run `pre-commit run --all-files` and the claims gate before merging.
- **Backstop:** the release checklist (`docs/RELEASE.md`) requires
  confirming the pins match this section before every release, and
  the pins are re-audited manually at least quarterly if no
  Dependabot update has arrived in the meantime.

### Survey (2026-11-08) — pinning complete

Most actions in the repo are already SHA-pinned (checkout v7.0.1,
setup-python v7.0.0, upload-artifact v7.0.2, download-artifact
v8.0.2, codeql v4.39.3, dependency-review v5.0.0, cache v6.1.0,
codecov v7.1.1, attest-build-provenance v4.2.2 in `release.yml`).
The survey found 11 unpinned refs. **All 11 are now pinned** to
full commit SHAs in commit `3145521` ("Pin remaining 11 unpinned
GitHub Actions refs to SHAs (SECURITY.md survey)"), and **0 unpinned
refs remain** in `.github/workflows/` (verified 2026-11-09: all 135
`uses:` refs use a full 40-character SHA). Each SHA below was
resolved via the tags API and, for annotated tags, peeled to the
commit with the git-tags API. The table is kept as the record of
what was pinned and why.

| Former ref | File(s) | Pinned to (SHA) | Decision / reason |
| --- | --- | --- | --- |
| `sigstore/cosign-installer@main` | `.github/workflows/repository-integrity.yml:28` | `756fe2d284c7292c4e9b62c8a28f1e5629c59532` (v4.1.3) | Pinned — the only `@main` ref in the repo; invisible to Dependabot; same installer version as the release workflow. |
| `anchore/sbom-action@v0` | `release.yml:121,130`, `supply-chain.yml:94`, `container.yml:93`, `enterprise-deep-verification.yml:287` | `e22c389904149dbc22b58101806040fa8d37a610` | Pinned — SBOMs feed signed release artifacts, so a moving `@v0` can change SBOM output between runs. Note: this is the current `@v0` tip (2026-03-19, Syft v1.42.3), which floats past the latest release v0.24.3 (`66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c`). |
| `anchore/sbom-action@v0.24.3` | `repository-integrity.yml:49` | `66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c` | Pinned — same action as above; a release tag is still a movable ref. |
| `gitleaks/gitleaks-action@v2` | `supply-chain.yml:80` | `e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e` | Upgraded to v3.0.0 (2026-05-30) — Node 20→24 runtime migration only; src/ byte-identical to v2.3.9; default gitleaks binary unchanged at 8.24.3. |
| `ossf/scorecard-action@v2.4.1` | `scorecard.yml:32` | `fa7117db83c52d787ae5a89f350999701505d78e` | Upgraded to v2.5.0 (2026-10-12). Correction: SECURITY.md previously recorded `46dc3187a971a9febf3aeb7f94ccde489f7bb46a` for v2.5.0, but that is the annotated tag object, not the commit; the pin uses the commit SHA `fa7117db83c52d787ae5a89f350999701505d78e`. |
| `docker/setup-buildx-action@v4` | `container.yml:53` | `f87e5991a6d7451dcb8d9637bfbc97413f497069` | Pinned — container publishing path. Currently equals latest patch v4.4.1, so pinning is behavior-preserving. |
| `docker/login-action@v4` | `container.yml:60` | `8aa5831fb8d48d8f76594c7ddde61ae58019f550` | Pinned — same; currently equals latest patch v4.8.0. |
| `docker/metadata-action@v6` | `container.yml:68` | `dc802804100637a589fabce1cb79ff13a1411302` | Pinned — same; currently equals latest patch v6.2.0. |
| `docker/build-push-action@v7` | `container.yml:80` | `c3c9e263c25d99ce0380d002d59b67737d91b0dc` | Pinned — same; currently equals latest patch v7.4.0. |
| `actions/attest-build-provenance@v4` | `container.yml:102` | `4d101475d8b20a2381f78447822ac1eab6504dd8` | Pinned — same SHA already pinned in `release.yml` as v4.2.2; use it here too for consistency. |
| `actions/checkout@v5` | `container.yml:42` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | Upgraded to v7.0.1 — now matches the other checkout pins in the repo. |

### Still open

All three items previously listed here (checkout v5.1.0 → v7.0.1 in
`container.yml:42`, gitleaks v3.0.0 major bump in `supply-chain.yml:80`,
scorecard v2.5.0 bump in `scorecard.yml:32`) were taken by the
2026-11-09 action upgrades; nothing remains open in this section.

## Python dependency pinning policy

The same rule as for GitHub Actions — **pin, and upgrade the pin** —
applies to Python dependencies, with the same shape: an exact pin plus a
named update trigger plus a review step. The mechanism is
`requirements-pinned.txt`, which since 2026-11-10 is an exact-pin
lockfile: every package in the resolved dependency closure, direct and
transitive alike, is pinned `==` to the exact version installed and
tested in a fresh venv. `pyproject.toml` keeps version ranges: it is the
abstract spec (what the project tolerates, the library contract for
downstream consumers); the lockfile is the concrete record (what was
installed and tested). Every direct `==` pin must lie inside its
pyproject range; `tests/test_generate_sbom.py` enforces both the `==`
form and the in-range property.

### Decision (2026-11-10) — full exact-pin lockfile, typer removed

**Decision: pin the whole closure `==`, and upgrade the pin.** The
previous file used version ranges, so a fresh install could resolve to
a newer upstream release with no repo change — and did: filelock
4.2.9 → 4.2.10 and typer 0.28.0 → 0.29.0 staled the checked-in SBOM
and failed the CI staleness job on 2026-11-09 (18/19 jobs success).
Pinning only those two packages was rejected as patchwork: any other
transitive package (click, anyio, pydantic, …) could release next and
fail CI the same way. A `pip-compile` / `pip-tools` two-file lock and a
separate constraints file were considered and deferred (new tooling,
CI-command changes, weaker Dependabot support for standalone
constraints files); the freeze-based lock achieves the same
determinism with the tools the repo already uses, and the
direct/transitive distinction is preserved one level up, in
`pyproject.toml` vs the lockfile. Hash pinning is likewise deferred.

`typer` was removed from the lockfile in the same change: it is unused
(no `import typer` in `src/`, `tests/` or `scripts/`; the Typer CLI
was deleted in Phase 2 and its commands ported to the `argparse`
`cli.py`; the only other requirer, `mcp`, needs it solely under its
uninstalled `cli` extra). Removing it drops `typer` and `shellingham`
(typer's dependency, required by nothing else in the closure) from the
SBOM (122 → 120 components).
`filelock` is pinned as an ordinary transitive lock line
(`filelock==4.2.10`); it needed no special mechanism once the whole
closure is locked, but it is the package that proved a transitive pin
was required — it appeared nowhere in `pyproject.toml` or the old
pinned file, yet its release staled the SBOM.

### Review cadence

- **Trigger:** Dependabot's `pip` ecosystem in
  `.github/dependabot.yml` (weekly, `open-pull-requests-limit: 5`;
  0 open PRs at decision time) proposes bumps. That is the normal
  trigger; no separate calendar reminder is needed while Dependabot is
  enabled. The `pip-audit` gate is the security backstop: a CVE in a
  pinned version fails CI until the pin is bumped, independent of the
  weekly schedule.
- **What "review" means:** read the upstream release notes for
  breaking changes (a major bump is reviewed separately and never
  taken as part of a routine pin update); edit the `==` line(s); if the
  new version falls outside the pyproject range, widen the range in
  `pyproject.toml` in the same commit; reinstall in a fresh venv,
  re-freeze the transitive section, regenerate the SBOM in the same
  commit, and run the claims gate, schemas gate, pre-commit, and
  `tests/test_generate_sbom.py` before merging. The full procedure is
  documented in the lockfile header. This repo works main-only, so
  Dependabot PRs are applied as direct main commits, never merged.
- **Known limits:** the lock carries versions, not hashes (see above);
  it has no environment markers and was resolved on Python 3.12 —
  safe because the file is installed only on 3.12/ubuntu (the
  `pinned`, `sbom`, and `pip-audit-gate` jobs); if a job ever installs
  it on another Python or OS, the lock must be re-resolved per
  environment first. If a direct pin is removed, prune its orphaned
  transitive lines by re-freezing (nothing auto-prunes).
