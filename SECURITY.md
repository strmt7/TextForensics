# Security policy

TextForensics processes text that may be private, unpublished, legally sensitive, or commercially confidential. Security issues include conventional software vulnerabilities **and** failures that unintentionally expose submitted content, credentials, provenance records, or detector-provider data.

## Supported versions

Until a stable 1.x release exists, security fixes are provided on a best-effort basis for the latest tagged minor release and the current `main` branch.

| Version | Security fixes |
| --- | --- |
| latest 0.x minor | ✅ |
| older 0.x minors | ❌ unless explicitly announced |
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
Hashes detect modification relative to the hashed artifact. A local hash chain does not establish an independent trusted timestamp or prove authorship.

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
