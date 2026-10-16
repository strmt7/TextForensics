# Changelog

All notable user-visible changes are documented here.

The project is pre-1.0. Public schemas and detector/calibration semantics are treated as contracts and should still be versioned deliberately.

## [Unreleased]

### Added
- strict TFDP/1 runtime result validation;
- detector plugin-health reporting with redacted failure messages;
- qualitative `textforensics.trust-map/v1`;
- sealed, raw-text-free `textforensics.case-file/v1` artifacts;
- case export/verification CLI;
- split-aware calibration artifacts and held-out evaluation guard;
- unified environment configuration and UTF-8 input-size limits;
- API health/readiness/version/detector-health endpoints;
- current MCP v2 server support;
- host-safe ASGI/API runner;
- packaged JSON schemas;
- multi-stage non-root OCI image and Compose example;
- Linux/macOS/Windows smoke CI;
- Python 3.11–3.15 test matrix;
- wheel build/install validation;
- CodeQL, dependency-review, dependency-audit, Dependabot and release-build workflows;
- installation, operations, support and commercial-readiness documentation.

### Changed
- Python 3.10 is no longer supported after its upstream end-of-life; CI now covers Python 3.11–3.15.\n- the legacy `confidence` value is explicitly labeled an **uncalibrated diagnostic reliability heuristic**;
- the legacy Verdict Integrity grade is explicitly marked an unvalidated alpha compatibility diagnostic;
- the browser UI now leads with Trust Map evidence coverage rather than the legacy grade;
- consensus no longer averages detector-local probabilities into an ensemble probability;
- non-loopback network binding requires explicit opt-in;
- corrupted provenance ledgers cannot be appended to silently.

### Security
- detector/plugin exceptions are redacted before inclusion in reports;
- raw submitted text remains absent from portable case artifacts by default;
- default API access logging is disabled;
- browser UI sends no-store, CSP, no-sniff, no-referrer, and permissions-policy headers;
- container runtime uses a non-root numeric UID.

## [0.1.0]

Initial alpha foundation:
- dependency-free heuristic baseline;
- local CLI/browser UI;
- TFDP detector protocol;
- forensic bundle;
- MCP/API scaffolding;
- provenance ledger;
- benchmark/calibration scaffolding.
