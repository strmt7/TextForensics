# Recommended repository settings

These settings complement the committed CI/security workflows. Some require GitHub repository-administration permissions and cannot be enforced by source files alone.

## Protect `main`

Recommended ruleset/branch-protection policy:

- require a pull request before merging;
- require the branch to be up to date before merge;
- require at least one approving review when the project has more than one maintainer;
- dismiss stale approvals after new commits;
- require CODEOWNERS review for security-, schema-, detector-, and workflow-sensitive paths when multiple maintainers exist;
- require conversation resolution;
- block force pushes;
- block branch deletion;
- require signed commits/tags if that matches the maintainer's signing workflow.

## Required status checks

After the workflows have run successfully and stable check names are visible, require the applicable checks from:

- CI — Python 3.10–3.13;
- CI — Linux/macOS/Windows smoke;
- CI — wheel build/install;
- CI — API surface;
- CI — MCP surface;
- Container;
- CodeQL;
- Dependency Review.

Do not hard-code obsolete check names after workflow renames; review rulesets whenever CI topology changes.

## Security features

Recommended GitHub features where available:

- private vulnerability reporting / security advisories;
- Dependabot alerts;
- Dependabot security updates;
- dependency graph;
- secret scanning;
- push protection for secrets;
- code scanning / CodeQL.

## Merge strategy

Prefer squash merge for normal feature PRs so each merged PR has one auditable main-branch commit. Keep merge commits only when preserving a meaningful multi-commit history is intentional.

Delete merged feature branches after merge.

## Releases

For public releases:

- create tags from protected `main`;
- use the committed Release Build workflow;
- attach/check SHA-256 checksums;
- do not upload ad-hoc locally built artifacts without matching source provenance;
- verify the published wheel and OCI image from a clean environment.

## Environments and secrets

If future workflows publish to PyPI, an OCI registry, or a hosted service:

- prefer OpenID Connect / trusted publishing over long-lived tokens;
- scope environments separately (for example `test` and `production`);
- require human approval for production publication where appropriate;
- never expose provider API keys to forked pull-request workflows.
